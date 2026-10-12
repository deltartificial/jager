//! End-to-end: real processes, real signals. Each test targets only the
//! child it spawned (`--only-pid`) and uses `--time-warp` so a few-second-old
//! child looks hours old.

use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const JAGER: &str = env!("CARGO_BIN_EXE_jager");

struct Victim(Child);

impl Victim {
    fn spawn(cmd: &str, args: &[&str]) -> Self {
        let child = Command::new(cmd)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn victim");
        Victim(child)
    }

    fn pid(&self) -> String {
        self.0.id().to_string()
    }

    fn exit(&mut self, within: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + within;
        loop {
            if let Some(st) = self.0.try_wait().unwrap() {
                return Some(st);
            }
            if Instant::now() > deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Victim {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn log_path(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("jager-test-{name}-{}.log", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

/// Runs a fast watcher (300ms ticks, 1s sustain, 1s grace) against `pid`.
fn hunt(pid: &str, log: &PathBuf, extra: &[&str]) -> String {
    let mut args = vec![
        "watch", "--only-pid", pid, "--min-age", "3h", "--time-warp", "5h", "--interval", "300ms",
        "--sustain", "1s", "--grace", "1s", "--ticks", "14", "--no-notify", "--log",
    ];
    args.push(log.to_str().unwrap());
    args.extend_from_slice(extra);
    let st = Command::new(JAGER).args(&args).status().expect("run jager");
    assert!(st.success(), "jager exited with {st}");
    std::fs::read_to_string(log).unwrap_or_default()
}

#[test]
fn kills_an_old_infinite_loop_with_sigterm() {
    let mut v = Victim::spawn("/usr/bin/yes", &[]);
    let log = log_path("term");
    let out = hunt(&v.pid(), &log, &[]);
    let st = v.exit(Duration::from_secs(2)).expect("victim should be dead");
    assert_eq!(st.signal(), Some(15), "log:\n{out}");
    assert!(out.contains(&format!("TERM pid={}", v.pid())), "log:\n{out}");
    assert!(out.contains("cmd=/usr/bin/yes"), "log:\n{out}");
}

#[test]
fn escalates_to_sigkill_when_sigterm_is_ignored() {
    let mut v = Victim::spawn("/bin/sh", &["-c", "trap '' TERM; while :; do :; done"]);
    let log = log_path("kill");
    let out = hunt(&v.pid(), &log, &[]);
    let st = v.exit(Duration::from_secs(2)).expect("victim should be dead");
    assert_eq!(st.signal(), Some(9), "log:\n{out}");
    let term = out.find("TERM pid=").expect("TERM logged");
    let kill = out.find("KILL pid=").expect("KILL logged");
    assert!(term < kill, "log:\n{out}");
}

#[test]
fn kills_an_old_memory_hog_even_when_idle() {
    // ~300 MiB written (so actually resident), then sleeps at 0% CPU.
    let mut v = Victim::spawn("/usr/bin/perl", &["-e", "$x = 'x' x (300 << 20); sleep 60"]);
    std::thread::sleep(Duration::from_millis(800));
    let log = log_path("mem");
    let out = hunt(&v.pid(), &log, &["--cpu", "1000", "--mem", "200M"]);
    let st = v.exit(Duration::from_secs(2)).expect("victim should be dead");
    assert_eq!(st.signal(), Some(15), "log:\n{out}");
}

#[test]
fn leaves_young_processes_alone() {
    let mut v = Victim::spawn("/usr/bin/yes", &[]);
    let log = log_path("young");
    let out = hunt(&v.pid(), &log, &["--time-warp", "0s"]);
    assert!(v.exit(Duration::ZERO).is_none(), "young victim was killed\n{out}");
    assert!(!out.contains("TERM"), "log:\n{out}");
}

#[test]
fn leaves_old_idle_processes_alone() {
    let mut v = Victim::spawn("/bin/sleep", &["60"]);
    let log = log_path("idle");
    let out = hunt(&v.pid(), &log, &[]);
    assert!(v.exit(Duration::ZERO).is_none(), "idle victim was killed\n{out}");
}

#[test]
fn dry_run_reports_but_never_signals() {
    let mut v = Victim::spawn("/usr/bin/yes", &[]);
    let log = log_path("dry");
    let out = hunt(&v.pid(), &log, &["--dry-run"]);
    assert!(v.exit(Duration::ZERO).is_none(), "dry-run killed\n{out}");
    assert_eq!(out.matches("WOULD-KILL").count(), 1, "log:\n{out}");
}

#[test]
fn protected_names_are_spared() {
    let mut v = Victim::spawn("/usr/bin/yes", &[]);
    let log = log_path("protect");
    let out = hunt(&v.pid(), &log, &["--protect", "yes"]);
    assert!(v.exit(Duration::ZERO).is_none(), "protected victim killed\n{out}");
    assert!(out.contains("SPARED"), "log:\n{out}");
}
