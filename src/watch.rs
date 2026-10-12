//! `jager watch`: the resident hunter.
//!
//! Every `interval` it scans the current user's processes, measures CPU over
//! the last interval, and kills (SIGTERM, then SIGKILL after `grace`) any
//! process that is older than `min_age` and has stayed above the CPU or
//! memory threshold for `sustain` in a row.

use crate::proc::{self, PATH_MAX, Proc, SIGKILL, SIGTERM, State};
use crate::util::{Bytes, Dur, StackBuf, now_ms, parse_dur};
use std::ffi::{c_char, c_void};
use std::fmt::Write as _;
use std::io::Write as _;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const HELP: &str = "\
jager watch — resident hunter: kills processes that run too long and too hot

USAGE: jager watch [OPTIONS]

A process is killed when ALL of these hold:
  - it belongs to you (never root, never other users)
  - it is older than --min-age
  - it has used >= --cpu of a core, or >= --mem of RAM, for --sustain in a row
  - it is not protected (system paths, apps in /Applications, --protect)
It first gets SIGTERM, then SIGKILL if still alive after --grace.

OPTIONS:
  --min-age DUR     minimum age before it can be hunted (default: 3h)
  --cpu PCT         CPU threshold, % of one core (default: 80)
  --mem SIZE|PCT    RSS threshold, e.g. 8G or 25% of RAM, 0 = off (default: 25%)
  --sustain DUR     how long it must stay over threshold (default: 10m)
  --interval DUR    time between scans (default: 30s)
  --grace DUR       delay between SIGTERM and SIGKILL (default: 15s)
  --protect NAME    never kill processes whose name or path contains NAME
                    (repeatable)
  --include-apps    also hunt apps from /Applications
  --dry-run         log and notify, but never send a signal
  --no-notify       no macOS notifications
  --log PATH        log file (default: ~/Library/Logs/jager.log, - = stderr)
  -h, --help        this help

DUR: 500ms, 90s, 30m, 3h, 1d
";

/// Names that are never hunted, on top of the path rules.
const PROTECTED: &[&str] = &[
    "launchd", "loginwindow", "Finder", "Dock", "SystemUIServer", "WindowServer",
    "ControlCenter", "NotificationCenter", "coreaudiod", "Spotlight", "mds", "mds_stores",
    "claude", "jager",
];

/// Path prefixes owned by the OS.
const SYSTEM_PATHS: &[&str] =
    &["/System/", "/usr/libexec/", "/usr/sbin/", "/sbin/", "/Library/Apple/"];

#[derive(Clone, Copy)]
pub struct Policy {
    pub min_age_s: u64,
    pub cpu_pct: f32,
    /// 0 = memory rule off.
    pub mem_bytes: u64,
    pub sustain_ms: u64,
    pub grace_ms: u64,
    pub interval_ms: u64,
    pub dry_run: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Act {
    Term,
    Kill,
    WouldKill,
    Spare,
}

#[derive(Clone, Copy, Debug)]
pub struct Action {
    pub pid: u32,
    pub start: u64,
    pub act: Act,
    pub cpu_pct: f32,
    pub rss: u64,
    pub age_s: u64,
    pub hot_ms: u64,
}

const SEEN: u8 = 1;
const TERM_SENT: u8 = 2;
/// Already acted upon in this hot episode.
const DONE: u8 = 4;
const HOT: u8 = 8;

/// One tracked process: 32 bytes. Times are the low 32 bits of the
/// millisecond clock; only short spans (< 49 days) are ever subtracted,
/// so wrapping arithmetic is exact.
#[derive(Clone, Copy)]
struct Track {
    pid: u32,
    start: u32,
    last_cpu: u64,
    hot_since: u32,
    term_at: u32,
    flags: u8,
}

const _: () = assert!(size_of::<Track>() == 32);

impl Track {
    fn new(p: &Proc) -> Self {
        Track { pid: p.pid, start: p.start as u32, last_cpu: p.cpu_ns, hot_since: 0, term_at: 0, flags: SEEN }
    }
}

/// Pure decision engine: feed it process snapshots with a clock, it returns
/// actions. No syscalls, so it is fully testable with fake time.
///
/// Tracks live in one Vec sorted by pid, allocated once: no hashing, no
/// per-tick allocation. Every live track is refreshed on every tick, so a
/// single engine-wide `dt` replaces per-track timestamps.
pub struct Engine {
    pub policy: Policy,
    tracks: Vec<Track>,
    now: u64,
    dt: u64,
    last_tick: Option<u64>,
    /// Set after a long gap (machine asleep): CPU deltas are meaningless.
    rebase: bool,
}

impl Engine {
    pub fn new(policy: Policy) -> Self {
        Engine { policy, tracks: Vec::with_capacity(1024), now: 0, dt: 0, last_tick: None, rebase: false }
    }

    pub fn tracked(&self) -> usize {
        self.tracks.len()
    }

    pub fn begin_tick(&mut self, now_ms: u64) {
        self.now = now_ms;
        self.dt = self.last_tick.map_or(0, |t| now_ms.saturating_sub(t));
        self.rebase = self.last_tick.is_some() && self.dt > 3 * self.policy.interval_ms.max(1);
    }

    /// `age_s` is supplied by the caller so time can be warped in tests.
    pub fn observe(
        &mut self,
        p: &Proc,
        age_s: u64,
        mut protected: impl FnMut(&Proc) -> bool,
        out: &mut Vec<Action>,
    ) {
        let idx = match self.tracks.binary_search_by_key(&p.pid, |t| t.pid) {
            Ok(i) if self.tracks[i].start == p.start as u32 => i,
            // Same pid, different process: start over.
            Ok(i) => return self.tracks[i] = Track::new(p),
            Err(i) => return self.tracks.insert(i, Track::new(p)),
        };
        let pol = &self.policy;
        let (now, dt) = (self.now, self.dt);
        let now32 = now as u32;
        let t = &mut self.tracks[idx];
        t.flags |= SEEN;
        if dt == 0 {
            return;
        }
        let cpu_pct = (p.cpu_ns.saturating_sub(t.last_cpu) as f64 / (dt as f64 * 1e6) * 100.0) as f32;
        t.last_cpu = p.cpu_ns;

        let act = |act, hot_ms| Action { pid: p.pid, start: p.start, act, cpu_pct, rss: p.rss, age_s, hot_ms };

        // Escalation runs regardless of current load.
        if t.flags & TERM_SENT != 0 {
            if t.flags & DONE == 0 && now32.wrapping_sub(t.term_at) as u64 >= pol.grace_ms {
                out.push(act(Act::Kill, 0));
                t.flags |= DONE;
            }
            return;
        }
        if self.rebase {
            t.flags &= !HOT;
            return;
        }

        let over = cpu_pct >= pol.cpu_pct || (pol.mem_bytes > 0 && p.rss >= pol.mem_bytes);
        let hot = over && age_s >= pol.min_age_s && !matches!(p.state, State::Zombie | State::Stop);
        if !hot {
            t.flags &= !(HOT | DONE);
            return;
        }
        if t.flags & DONE != 0 {
            return;
        }
        if t.flags & HOT == 0 {
            // It was already over threshold during the window that just ended.
            t.flags |= HOT;
            t.hot_since = (now - dt) as u32;
        }
        let hot_ms = now32.wrapping_sub(t.hot_since) as u64;
        if hot_ms < pol.sustain_ms {
            return;
        }
        if protected(p) {
            out.push(act(Act::Spare, hot_ms));
            t.flags |= DONE;
        } else if pol.dry_run {
            out.push(act(Act::WouldKill, hot_ms));
            t.flags |= DONE;
        } else {
            out.push(act(Act::Term, hot_ms));
            t.flags |= TERM_SENT;
            t.term_at = now32;
        }
    }

    pub fn end_tick(&mut self) {
        self.tracks.retain_mut(|t| {
            let seen = t.flags & SEEN != 0;
            t.flags &= !SEEN;
            seen
        });
        self.last_tick = Some(self.now);
        self.rebase = false;
    }
}

pub struct Opts {
    pub policy: Policy,
    protect: Vec<String>,
    include_apps: bool,
    notify: bool,
    log: Option<PathBuf>,
    // Test hooks (undocumented): make processes look older, restrict to one
    // pid, stop after N ticks.
    warp_s: u64,
    only_pid: Option<u32>,
    ticks: Option<u64>,
}

pub fn default_policy() -> Policy {
    Policy {
        min_age_s: 3 * 3600,
        cpu_pct: 80.0,
        mem_bytes: proc::phys_mem() / 4,
        sustain_ms: 10 * 60_000,
        grace_ms: 15_000,
        interval_ms: 30_000,
        dry_run: false,
    }
}

pub fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Opts, String> {
    let mut o = Opts {
        policy: default_policy(),
        protect: Vec::new(),
        include_apps: false,
        notify: true,
        log: std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Logs/jager.log")),
        warp_s: 0,
        only_pid: None,
        ticks: None,
    };
    while let Some(a) = args.next() {
        let mut val = |name: &str| args.next().ok_or_else(|| format!("{name} expects a value"));
        let p = &mut o.policy;
        match a.as_str() {
            "--min-age" => p.min_age_s = parse_dur(&val(&a)?)? / 1000,
            "--cpu" => {
                let v = val(&a)?;
                p.cpu_pct = v.trim_end_matches('%').parse().map_err(|_| format!("invalid --cpu: {v}"))?
            }
            "--mem" => p.mem_bytes = parse_mem(&val(&a)?)?,
            "--sustain" => p.sustain_ms = parse_dur(&val(&a)?)?,
            "--interval" => p.interval_ms = parse_dur(&val(&a)?)?.max(100),
            "--grace" => p.grace_ms = parse_dur(&val(&a)?)?,
            "--protect" => o.protect.push(val(&a)?),
            "--include-apps" => o.include_apps = true,
            "--dry-run" => p.dry_run = true,
            "--no-notify" => o.notify = false,
            "--log" => {
                let v = val(&a)?;
                o.log = (v != "-").then(|| PathBuf::from(v));
            }
            "--time-warp" => o.warp_s = parse_dur(&val(&a)?)? / 1000,
            "--only-pid" => {
                o.only_pid = Some(val(&a)?.parse().map_err(|_| "--only-pid expects a pid".to_string())?)
            }
            "--ticks" => o.ticks = Some(val(&a)?.parse().map_err(|_| "--ticks expects an integer".to_string())?),
            "-h" | "--help" => {
                print!("{HELP}");
                std::process::exit(0);
            }
            _ => return Err(format!("unknown option: {a}")),
        }
    }
    Ok(o)
}

/// "8G", "512M", "25%", "0" → bytes.
fn parse_mem(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if let Some(pct) = s.strip_suffix('%') {
        let pct: f64 = pct.parse().map_err(|_| format!("invalid --mem: {s}"))?;
        return Ok((proc::phys_mem() as f64 * pct / 100.0) as u64);
    }
    if s == "0" || s == "off" {
        return Ok(0);
    }
    let (num, mult) = match s.as_bytes().last() {
        Some(b'G' | b'g') => (&s[..s.len() - 1], 1u64 << 30),
        Some(b'M' | b'm') => (&s[..s.len() - 1], 1 << 20),
        Some(b'K' | b'k') => (&s[..s.len() - 1], 1 << 10),
        _ => (s, 1),
    };
    let n: f64 = num.parse().map_err(|_| format!("invalid --mem: {s}"))?;
    Ok((n * mult as f64) as u64)
}

fn is_protected(p: &Proc, o: &Opts, buf: &mut [u8; PATH_MAX]) -> bool {
    let name = p.name();
    if PROTECTED.iter().any(|n| n.eq_ignore_ascii_case(name)) {
        return true;
    }
    // Unknown path: when in doubt, don't shoot.
    let Some(path) = proc::path(p.pid, buf) else { return true };
    if o.protect.iter().any(|n| name.contains(n.as_str()) || path.contains(n.as_str())) {
        return true;
    }
    if SYSTEM_PATHS.iter().any(|pre| path.starts_with(pre)) {
        return true;
    }
    // GUI apps are left alone, but toolchains bundled inside an app
    // (e.g. Xcode's python) are fair game.
    !o.include_apps && path.contains("/Applications/") && path.contains(".app/")
        && !path.contains("/Contents/Developer/")
}

pub fn run(args: impl Iterator<Item = String>) {
    let o = match parse_args(args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("jager watch: {e}\n\n{HELP}");
            std::process::exit(2);
        }
    };
    let me = proc::my_uid();
    let self_pid = std::process::id();
    let mut log = Log::new(o.log.clone());

    let pol = &o.policy;
    let mut line = String::new();
    let mut a = String::new();
    let mut b = String::new();
    let mut c = String::new();
    fmt_dur(&mut a, pol.min_age_s);
    fmt_dur(&mut b, pol.sustain_ms / 1000);
    fmt_bytes(&mut c, pol.mem_bytes);
    let _ = write!(
        line,
        "START pid={self_pid} min-age={a} cpu>={}% mem>={} sustain={b} interval={}ms grace={}ms{}",
        pol.cpu_pct,
        if pol.mem_bytes == 0 { "off" } else { &c },
        pol.interval_ms,
        pol.grace_ms,
        if pol.dry_run { " DRY-RUN" } else { "" },
    );
    log.write(&line);

    let mut engine = Engine::new(o.policy);
    let mut actions: Vec<Action> = Vec::with_capacity(4);
    let mut path_buf = [0u8; PATH_MAX];
    let mut tick = 0u64;
    loop {
        let now = now_ms();
        let wall_s = now / 1000 + o.warp_s;
        engine.begin_tick(now);
        proc::scan(|p| {
            if p.uid != me || p.pid == self_pid || p.pid <= 1 {
                return;
            }
            if o.only_pid.is_some_and(|only| only != p.pid) {
                return;
            }
            let age_s = wall_s.saturating_sub(p.start);
            engine.observe(&p, age_s, |p| is_protected(p, &o, &mut path_buf), &mut actions);
        });
        engine.end_tick();

        for act in actions.drain(..) {
            execute(&act, me, &o, &mut log);
        }

        tick += 1;
        if o.ticks.is_some_and(|n| tick >= n) {
            break;
        }
        std::thread::sleep(Duration::from_millis(engine.policy.interval_ms));
    }
}

fn execute(a: &Action, me: u32, o: &Opts, log: &mut Log) {
    let mut line = String::new();
    let mut cmd = String::new();
    let mut scratch = Vec::new();
    if !proc::cmdline(a.pid, &mut scratch, &mut cmd, 200) {
        cmd.push('?');
    }
    drop(scratch);

    // Never signal a pid that now belongs to someone else.
    if proc::identity(a.pid) != Some((a.start, me)) {
        let _ = write!(line, "GONE pid={} (exited or reused before {:?})", a.pid, a.act);
        log.write(&line);
        return;
    }

    let (tag, ok) = match a.act {
        Act::Term => ("TERM", proc::signal(a.pid, SIGTERM)),
        Act::Kill => ("KILL", proc::signal(a.pid, SIGKILL)),
        Act::WouldKill => ("WOULD-KILL", true),
        Act::Spare => ("SPARED", true),
    };
    let (mut age, mut hot, mut rss) = (String::new(), String::new(), String::new());
    fmt_dur(&mut age, a.age_s);
    fmt_dur(&mut hot, a.hot_ms / 1000);
    fmt_bytes(&mut rss, a.rss);
    let _ = write!(
        line,
        "{tag}{} pid={} age={age} cpu={:.0}% rss={rss} hot-for={hot} cmd={cmd}",
        if ok { "" } else { "(failed)" },
        a.pid,
        a.cpu_pct,
    );
    log.write(&line);

    if o.notify && matches!(a.act, Act::Term | Act::WouldKill) {
        let verb = if a.act == Act::Term { "Killed" } else { "Would kill" };
        let short: String = cmd.chars().take(60).collect();
        let msg = format!("{verb} pid {} ({:.0}% CPU, {rss}, up {age}): {short}", a.pid, a.cpu_pct);
        notify(&msg);
    }
}

fn notify(msg: &str) {
    let esc = msg.replace('\\', "\\\\").replace('"', "\\\"");
    let script = format!("display notification \"{esc}\" with title \"jäger\"");
    let _ = std::process::Command::new("/usr/bin/osascript")
        .args(["-e", &script])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// Append-only log with 1 MiB rotation. The file is opened per write:
/// events are rare and an idle daemon holds no descriptor.
pub struct Log {
    path: Option<PathBuf>,
}

impl Log {
    pub fn new(path: Option<PathBuf>) -> Self {
        Log { path }
    }

    pub fn write(&mut self, msg: &str) {
        let mut ts = String::new();
        timestamp(&mut ts);
        let Some(path) = &self.path else {
            eprintln!("{ts} {msg}");
            return;
        };
        if std::fs::metadata(path).is_ok_and(|m| m.len() > 1 << 20) {
            let _ = std::fs::rename(path, path.with_extension("log.1"));
        }
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(f, "{ts} {msg}");
        }
    }
}

#[repr(C)]
struct Tm {
    sec: i32,
    min: i32,
    hour: i32,
    mday: i32,
    mon: i32,
    year: i32,
    wday: i32,
    yday: i32,
    isdst: i32,
    gmtoff: i64,
    zone: *const std::ffi::c_char,
}

unsafe extern "C" {
    fn localtime_r(t: *const i64, out: *mut Tm) -> *mut Tm;
}

fn timestamp(out: &mut String) {
    let t = (now_ms() / 1000) as i64;
    let mut tm = std::mem::MaybeUninit::<Tm>::zeroed();
    if unsafe { localtime_r(&t, tm.as_mut_ptr()) }.is_null() {
        let _ = write!(out, "@{t}");
        return;
    }
    let tm = unsafe { tm.assume_init() };
    let _ = write!(
        out,
        "{}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.year + 1900,
        tm.mon + 1,
        tm.mday,
        tm.hour,
        tm.min,
        tm.sec
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: u64 = 3600;
    const MIN: u64 = 60_000;

    fn policy() -> Policy {
        Policy {
            min_age_s: 3 * H,
            cpu_pct: 80.0,
            mem_bytes: 16 << 30,
            sustain_ms: 10 * MIN,
            grace_ms: 15_000,
            interval_ms: 30_000,
            dry_run: false,
        }
    }

    fn proc_(pid: u32, start: u64) -> Proc {
        let mut p = proc::blank();
        p.pid = pid;
        p.start = start;
        p.state = State::Run;
        p
    }

    /// Drives one process through ticks every 30s at the given CPU load.
    /// Returns every action emitted with the tick time.
    struct Sim {
        e: Engine,
        p: Proc,
        now: u64,
        out: Vec<(u64, Action)>,
    }

    impl Sim {
        fn new(pol: Policy, age_s: u64) -> Self {
            let now = 1_000_000 * 1000;
            Sim { e: Engine::new(pol), p: proc_(42, now / 1000 - age_s), now, out: Vec::new() }
        }

        fn run(&mut self, secs: u64, load_pct: f64, protected: bool) {
            let steps = secs / 30;
            for _ in 0..steps {
                self.now += 30_000;
                self.p.cpu_ns += (30e9 * load_pct / 100.0) as u64;
                let mut acts = Vec::new();
                self.e.begin_tick(self.now);
                let age = self.now / 1000 - self.p.start;
                self.e.observe(&self.p, age, |_| protected, &mut acts);
                self.e.end_tick();
                self.out.extend(acts.into_iter().map(|a| (self.now, a)));
            }
        }

        fn acts(&self) -> Vec<Act> {
            self.out.iter().map(|(_, a)| a.act).collect()
        }
    }

    #[test]
    fn spinning_for_hours_gets_term_then_kill() {
        let mut s = Sim::new(policy(), 5 * H);
        // First tick is only a baseline, so hot time starts on the second.
        s.run(10 * 60, 100.0, false);
        assert!(s.acts().is_empty(), "nothing before sustain elapsed");
        s.run(30, 100.0, false);
        assert_eq!(s.acts(), [Act::Term]);
        assert_eq!(s.out[0].1.hot_ms, 10 * MIN);
        s.run(30, 100.0, false);
        assert_eq!(s.acts(), [Act::Term, Act::Kill]);
        s.run(10 * 60, 100.0, false);
        assert_eq!(s.acts(), [Act::Term, Act::Kill], "kill is sent once");
    }

    #[test]
    fn young_process_is_left_alone() {
        let mut s = Sim::new(policy(), 2 * H);
        s.run(50 * 60, 100.0, false);
        assert!(s.acts().is_empty());
    }

    #[test]
    fn young_process_is_hunted_once_it_crosses_min_age() {
        let mut s = Sim::new(policy(), 3 * H - 5 * 60);
        s.run(5 * 60, 100.0, false);
        s.run(10 * 60 - 60, 100.0, false);
        assert!(s.acts().is_empty(), "sustain counts only after min-age");
        s.run(30, 100.0, false);
        assert_eq!(s.acts(), [Act::Term]);
    }

    #[test]
    fn idle_old_process_is_left_alone() {
        let mut s = Sim::new(policy(), 48 * H);
        s.run(60 * 60, 2.0, false);
        assert!(s.acts().is_empty());
    }

    #[test]
    fn a_cool_down_resets_the_sustain_timer() {
        let mut s = Sim::new(policy(), 5 * H);
        s.run(9 * 60, 100.0, false);
        s.run(30, 5.0, false);
        s.run(9 * 60, 100.0, false);
        assert!(s.acts().is_empty());
        s.run(60, 100.0, false);
        assert_eq!(s.acts(), [Act::Term]);
    }

    #[test]
    fn memory_hog_is_hunted_even_when_idle() {
        let mut s = Sim::new(policy(), 5 * H);
        s.p.rss = 20 << 30;
        s.run(11 * 60, 0.0, false);
        assert_eq!(s.acts()[0], Act::Term);
    }

    #[test]
    fn protected_is_spared_once() {
        let mut s = Sim::new(policy(), 5 * H);
        s.run(60 * 60, 100.0, true);
        assert_eq!(s.acts(), [Act::Spare]);
    }

    #[test]
    fn dry_run_never_kills_and_reports_once_per_episode() {
        let mut s = Sim::new(Policy { dry_run: true, ..policy() }, 5 * H);
        s.run(60 * 60, 100.0, false);
        assert_eq!(s.acts(), [Act::WouldKill]);
        s.run(30, 0.0, false);
        s.run(11 * 60, 100.0, false);
        assert_eq!(s.acts(), [Act::WouldKill, Act::WouldKill]);
    }

    #[test]
    fn sleep_gap_does_not_count_as_hot_time() {
        let mut s = Sim::new(policy(), 5 * H);
        s.run(9 * 60, 100.0, false);
        s.now += 2 * H * 1000; // lid closed for 2h
        s.run(30, 100.0, false);
        assert!(s.acts().is_empty(), "rebased after wake");
        s.run(9 * 60, 100.0, false);
        assert!(s.acts().is_empty());
        s.run(60, 100.0, false);
        assert_eq!(s.acts(), [Act::Term]);
    }

    #[test]
    fn pid_reuse_starts_a_fresh_track() {
        let mut s = Sim::new(policy(), 5 * H);
        s.run(9 * 60, 100.0, false);
        s.p.start += 1; // same pid, different process
        s.run(9 * 60, 100.0, false);
        assert!(s.acts().is_empty());
    }

    #[test]
    fn stopped_and_zombie_are_not_hunted() {
        for st in [State::Stop, State::Zombie] {
            let mut s = Sim::new(policy(), 5 * H);
            s.p.state = st;
            s.p.rss = 20 << 30;
            s.run(60 * 60, 100.0, false);
            assert!(s.acts().is_empty());
        }
    }

    #[test]
    fn gone_processes_are_forgotten() {
        let mut e = Engine::new(policy());
        e.begin_tick(1000);
        e.observe(&proc_(1, 0), 0, |_| false, &mut Vec::new());
        e.observe(&proc_(2, 0), 0, |_| false, &mut Vec::new());
        e.end_tick();
        assert_eq!(e.tracked(), 2);
        e.begin_tick(2000);
        e.observe(&proc_(2, 0), 0, |_| false, &mut Vec::new());
        e.end_tick();
        assert_eq!(e.tracked(), 1);
    }

    #[test]
    fn parses_mem() {
        assert_eq!(parse_mem("8G").unwrap(), 8 << 30);
        assert_eq!(parse_mem("512M").unwrap(), 512 << 20);
        assert_eq!(parse_mem("0").unwrap(), 0);
        assert!(parse_mem("50%").unwrap() > 0);
        assert!(parse_mem("lots").is_err());
    }
}
