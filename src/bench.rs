//! `jager bench`: cost of one hunting tick on this machine.

use crate::proc;
use crate::util::{fmt_bytes, now_ms};
use crate::watch::{Action, Engine, Lane, Policy, default_fast_policy, default_policy, default_stale_policy};
use std::time::Instant;

pub fn run(mut args: impl Iterator<Item = String>) {
    let mut ticks: u32 = 200;
    while let Some(a) = args.next() {
        match a.as_str() {
            "-n" => ticks = args.next().and_then(|v| v.parse().ok()).unwrap_or(ticks),
            _ => {
                eprintln!("usage: jager bench [-n TICKS]");
                std::process::exit(2);
            }
        }
    }

    let (rss0, cpu0) = proc::self_usage();
    let pol = Policy { dry_run: true, ..default_policy() };
    let interval_ms = pol.interval_ms;
    let mut engine = Engine::new(
        pol,
        Policy { dry_run: true, ..default_fast_policy() },
        Policy { dry_run: true, ..default_stale_policy() },
    );
    let mut actions: Vec<Action> = Vec::new();
    let me = proc::my_uid();

    let mut samples = Vec::with_capacity(ticks as usize);
    let mut seen = 0usize;
    let t0 = Instant::now();
    for i in 0..ticks {
        let start = Instant::now();
        // Fake clock: each tick looks like one real interval later.
        let now = now_ms() + i as u64 * interval_ms;
        engine.begin_tick(now);
        seen = 0;
        proc::scan(|p| {
            seen += 1;
            if p.uid != me {
                return;
            }
            let age = (now / 1000).saturating_sub(p.start);
            engine.observe(&p, age, Lane::Normal, |_, _| true, &mut actions);
        });
        engine.end_tick();
        actions.clear();
        samples.push(start.elapsed().as_micros() as u64);
    }
    let wall = t0.elapsed();
    let (rss1, cpu1) = proc::self_usage();

    samples.sort_unstable();
    let pct = |q: f64| samples[((samples.len() - 1) as f64 * q) as usize];
    let mean = samples.iter().sum::<u64>() / samples.len().max(1) as u64;
    let cpu_per_tick_us = (cpu1 - cpu0) / 1000 / ticks.max(1) as u64;
    let per_hour_ms = cpu_per_tick_us * (3_600_000 / interval_ms) / 1000;

    let (mut a, mut b) = (String::new(), String::new());
    fmt_bytes(&mut a, rss0);
    fmt_bytes(&mut b, rss1);
    println!("ticks:             {ticks} ({} processes visible, {} tracked)", seen, engine.tracked());
    println!("wall:              {:.2?}", wall);
    println!("tick latency:      mean {mean} µs · p50 {} µs · p99 {} µs · max {} µs", pct(0.5), pct(0.99), pct(1.0));
    println!("cpu per tick:      {cpu_per_tick_us} µs");
    println!("at {}s interval:    ~{per_hour_ms} ms CPU per hour", interval_ms / 1000);
    println!("rss:               {a} before → {b} after");
}
