//! `jager scan`: one-shot report of long-running processes.

use crate::proc::{self, Proc, State};
use crate::util::{fmt_bytes, fmt_dur, parse_dur, use_color};
use std::fmt::Write as _;
use std::io::{self, Write};
use std::time::Duration;

const HELP: &str = "\
jager scan — one-shot report of long-running processes

USAGE: jager scan [OPTIONS]

OPTIONS:
  -t, --min-age DUR   minimum age (default: 1h). e.g. 90s, 30m, 2h, 1d
  -s, --sample DUR    instant CPU sampling window (default: 1s, 0 = off)
  -a, --all           include idle background processes
  -u, --users         all users (needs sudo to read everything)
  -c, --cpu           sort by CPU instead of age
  -n, --limit N       max rows (default: 50)
  -w, --wide          full command line
  -h, --help          this help

By default, shows your processes older than 1h that are burning CPU,
zombie/stopped, or attached to a terminal.

VERDICTS:
  LOOP     >= 90% of a core: likely a loop
  HOT      >= 20% of a core
  ZOMBIE   dead but not reaped by its parent
  STOPPED  suspended (Ctrl-Z, SIGSTOP)
  IDLE     alive, resting
";

struct Opts {
    min_age_ms: u64,
    sample_ms: u64,
    all: bool,
    users: bool,
    by_cpu: bool,
    limit: usize,
    wide: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Verdict {
    Loop,
    Hot,
    Zombie,
    Stopped,
    Idle,
}

impl Verdict {
    fn label(self) -> &'static str {
        match self {
            Verdict::Loop => "LOOP",
            Verdict::Hot => "HOT",
            Verdict::Zombie => "ZOMBIE",
            Verdict::Stopped => "STOPPED",
            Verdict::Idle => "IDLE",
        }
    }

    fn color(self) -> &'static str {
        match self {
            Verdict::Loop => "\x1b[1;31m",
            Verdict::Hot => "\x1b[33m",
            Verdict::Zombie | Verdict::Stopped => "\x1b[35m",
            Verdict::Idle => "\x1b[2m",
        }
    }
}

struct Hit {
    p: Proc,
    age_s: u64,
    /// Lifetime average, % of one core.
    avg: f32,
    /// Measured over the sample window, % of one core. None if not sampled.
    now: Option<f32>,
    verdict: Verdict,
}

pub fn run(args: impl Iterator<Item = String>) {
    let opts = match parse_args(args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("jager scan: {e}\n\n{HELP}");
            std::process::exit(2);
        }
    };

    let me = proc::my_uid();
    let self_pid = std::process::id();
    let now = crate::util::now_ms() / 1000;
    let min_age_s = opts.min_age_ms / 1000;

    let mut hits: Vec<Hit> = Vec::new();
    let unreadable = proc::scan(|p| {
        if p.pid == self_pid || (!opts.users && p.uid != me) {
            return;
        }
        let age_s = now.saturating_sub(p.start);
        if age_s < min_age_s {
            return;
        }
        let avg = p.cpu_ns as f64 / (age_s.max(1) as f64 * 1e9) * 100.0;
        hits.push(Hit { p, age_s, avg: avg as f32, now: None, verdict: Verdict::Idle });
    });

    if opts.sample_ms > 0 && !hits.is_empty() {
        std::thread::sleep(Duration::from_millis(opts.sample_ms));
        let window_ns = opts.sample_ms as f64 * 1e6;
        hits.retain_mut(|h| match proc::cpu_ns(h.p.pid) {
            Some(cpu) => {
                let delta = cpu.saturating_sub(h.p.cpu_ns);
                h.now = Some((delta as f64 / window_ns * 100.0) as f32);
                true
            }
            None => false, // exited during the sample
        });
    }

    for h in &mut hits {
        let load = h.now.unwrap_or(h.avg);
        h.verdict = match h.p.state {
            State::Zombie => Verdict::Zombie,
            State::Stop => Verdict::Stopped,
            _ if load >= 90.0 => Verdict::Loop,
            _ if load >= 20.0 => Verdict::Hot,
            _ => Verdict::Idle,
        };
    }

    let total = hits.len();
    if !opts.all {
        hits.retain(|h| h.verdict != Verdict::Idle || h.p.tty);
    }
    if opts.by_cpu {
        hits.sort_unstable_by(|a, b| {
            let (la, lb) = (a.now.unwrap_or(a.avg), b.now.unwrap_or(b.avg));
            lb.total_cmp(&la).then(b.age_s.cmp(&a.age_s))
        });
    } else {
        hits.sort_unstable_by(|a, b| a.verdict.cmp(&b.verdict).then(b.age_s.cmp(&a.age_s)));
    }

    if let Err(e) = render(&opts, &hits, total, unreadable) {
        if e.kind() != io::ErrorKind::BrokenPipe {
            eprintln!("jager: {e}");
            std::process::exit(1);
        }
    }
}

fn render(opts: &Opts, hits: &[Hit], total: usize, unreadable: usize) -> io::Result<()> {
    let color = use_color();
    let (bold, reset) = if color { ("\x1b[1m", "\x1b[0m") } else { ("", "") };
    let out = io::stdout();
    let mut out = io::BufWriter::with_capacity(8 * 1024, out.lock());

    let mut user = String::new();
    let mut cmd = String::new();
    let mut scratch = Vec::new();
    let max_cmd = if opts.wide { 4096 } else { 80 };

    write!(out, "{bold}{:>6}  {:>7}  {:>8}  {:>5}  {:>5}  {:>6}  S T  {:<7}  ", "PID", "AGE", "CPU", "AVG%", "NOW%", "RSS", "VERDICT")?;
    if opts.users {
        write!(out, "{:<10}  ", "USER")?;
    }
    writeln!(out, "COMMAND{reset}")?;

    let mut age = String::new();
    let mut cpu = String::new();
    let mut rss = String::new();
    let mut now = String::new();
    for h in hits.iter().take(opts.limit) {
        let p = &h.p;
        fmt_dur(&mut age, h.age_s);
        fmt_dur(&mut cpu, p.cpu_ns / 1_000_000_000);
        fmt_bytes(&mut rss, p.rss);
        now.clear();
        match h.now {
            Some(v) => { let _ = write!(now, "{v:.0}"); }
            None => now.push('-'),
        }
        let (vc, vr) = if color { (h.verdict.color(), reset) } else { ("", "") };
        write!(
            out,
            "{:>6}  {:>7}  {:>8}  {:>5.1}  {:>5}  {:>6}  {} {}  {vc}{:<7}{vr}  ",
            p.pid,
            age,
            cpu,
            h.avg,
            now,
            rss,
            p.state.letter(),
            if p.tty { '+' } else { ' ' },
            h.verdict.label(),
        )?;
        if opts.users {
            proc::user_name(p.uid, &mut user);
            write!(out, "{user:<10}  ")?;
        }
        if !proc::cmdline(p.pid, &mut scratch, &mut cmd, max_cmd) {
            cmd.clear();
            cmd.push_str(p.name());
        }
        writeln!(out, "{cmd}")?;
        if opts.wide && scratch.capacity() > 64 * 1024 {
            // Don't keep a 1 MiB argv buffer around between rows.
            scratch = Vec::new();
        }
    }

    let count = |v: Verdict| hits.iter().filter(|h| h.verdict == v).count();
    write!(
        out,
        "\n{} shown / {} processes ≥ {} · {} LOOP · {} HOT · {} ZOMBIE · {} STOPPED",
        hits.len().min(opts.limit),
        total,
        { fmt_dur(&mut age, opts.min_age_ms / 1000); &age },
        count(Verdict::Loop),
        count(Verdict::Hot),
        count(Verdict::Zombie),
        count(Verdict::Stopped),
    )?;
    if opts.users && unreadable > 0 {
        write!(out, " · {unreadable} unreadable (sudo)")?;
    }
    writeln!(out)?;
    out.flush()
}




fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Opts, String> {
    let mut o = Opts {
        min_age_ms: 3_600_000,
        sample_ms: 1000,
        all: false,
        users: false,
        by_cpu: false,
        limit: 50,
        wide: false,
    };
    while let Some(a) = args.next() {
        let mut val = |name: &str| args.next().ok_or_else(|| format!("{name} expects a value"));
        match a.as_str() {
            "-t" | "--min-age" => o.min_age_ms = parse_dur(&val(&a)?)?,
            "-s" | "--sample" => o.sample_ms = parse_dur(&val(&a)?)?,
            "-n" | "--limit" => {
                o.limit = val(&a)?.parse().map_err(|_| "--limit expects an integer".to_string())?
            }
            "-a" | "--all" => o.all = true,
            "-u" | "--users" => o.users = true,
            "-c" | "--cpu" => o.by_cpu = true,
            "-w" | "--wide" => o.wide = true,
            "-h" | "--help" => {
                print!("{HELP}");
                std::process::exit(0);
            }
            _ => return Err(format!("unknown option: {a}")),
        }
    }
    Ok(o)
}

