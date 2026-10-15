//! `jager watch`: the resident hunter.
//!
//! Every `interval` it scans the current user's processes, measures CPU over
//! the last interval, and kills (SIGTERM, then SIGKILL after `grace`) any
//! process that is older than `min_age` and has stayed above the CPU or
//! memory threshold for `sustain` in a row.
//!
//! Headless browsers driven by agents (`agent-browser`, Chrome for Testing)
//! go through a faster lane: shorter age and sustain, a lower memory bar,
//! and a detached one (parent = launchd) that sits idle is taken as
//! abandoned by the session that started it.
//!
//! Dev servers and agent sessions (`node`, `next-server`, `claude`) go
//! through a stale lane: past `max_age`, one that stays quiet is taken as
//! forgotten, even while its parent is still alive.

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

Fast lane: processes whose name contains a --fast pattern (default:
agent-browser, Chrome for Testing) use the --fast-* thresholds instead, and
are also killed when detached (parent = launchd) and idle (< 1% CPU) for
--fast-idle: an agent's browser left behind after its session ended.
Killing the agent-browser daemon closes its whole Chrome.

Stale lane: processes whose name contains a --stale pattern (default: node,
next-server, claude) are also killed once older than --max-age and quiet
(< --stale-cpu) for --stale-idle: a dev server or a Claude session forgotten
for a day. Busy ones are left alone until they calm down.

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
  --fast NAME       add a fast-lane name pattern (repeatable)
  --no-fast         no fast lane
  --fast-min-age DUR  (default: 10m)
  --fast-sustain DUR  (default: 2m)
  --fast-mem SIZE|PCT (default: 2G)
  --fast-idle DUR   kill a detached fast-lane process idle this long,
                    0 = off (default: 10m)
  --stale NAME      add a stale-lane name pattern (repeatable)
  --no-stale        no stale lane
  --max-age DUR     age past which a quiet stale-lane process goes,
                    0 = off (default: 24h)
  --stale-idle DUR  how long it must stay quiet (default: 15m)
  --stale-cpu PCT   below this it counts as quiet (default: 5)
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
    /// Idle this long = abandoned. 0 = rule off.
    pub idle_ms: u64,
    /// Below this, a tick counts as idle.
    pub idle_cpu_pct: f32,
    /// The idle rule only applies past this age...
    pub idle_min_age_s: u64,
    /// ...and, when set, only to detached processes (parent = launchd).
    pub idle_detached: bool,
    pub dry_run: bool,
}

/// Which policy a process is judged by.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lane {
    Normal,
    Fast,
    Stale,
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
    /// How long the condition held (hot, or idle when `idle`).
    pub hot_ms: u64,
    pub idle: bool,
}

const SEEN: u8 = 1;
const TERM_SENT: u8 = 2;
/// Already acted upon in this hot episode.
const DONE: u8 = 4;
const HOT: u8 = 8;
const IDLE: u8 = 16;

/// One tracked process: 32 bytes. Times are the low 32 bits of the
/// millisecond clock; only short spans (< 49 days) are ever subtracted,
/// so wrapping arithmetic is exact.
#[derive(Clone, Copy)]
struct Track {
    pid: u32,
    start: u32,
    last_cpu: u64,
    hot_since: u32,
    idle_since: u32,
    term_at: u32,
    flags: u8,
}

const _: () = assert!(size_of::<Track>() == 32);

impl Track {
    fn new(p: &Proc) -> Self {
        Track { pid: p.pid, start: p.start as u32, last_cpu: p.cpu_ns, hot_since: 0, idle_since: 0, term_at: 0, flags: SEEN }
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
    /// Policy of the fast lane.
    pub fast: Policy,
    /// Policy of the stale lane.
    pub stale: Policy,
    tracks: Vec<Track>,
    now: u64,
    dt: u64,
    last_tick: Option<u64>,
    /// Set after a long gap (machine asleep): CPU deltas are meaningless.
    rebase: bool,
}

impl Engine {
    pub fn new(policy: Policy, fast: Policy, stale: Policy) -> Self {
        Engine { policy, fast, stale, tracks: Vec::with_capacity(1024), now: 0, dt: 0, last_tick: None, rebase: false }
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
    /// `protected` is told whether the idle rule fired.
    pub fn observe(
        &mut self,
        p: &Proc,
        age_s: u64,
        lane: Lane,
        mut protected: impl FnMut(&Proc, bool) -> bool,
        out: &mut Vec<Action>,
    ) {
        let idx = match self.tracks.binary_search_by_key(&p.pid, |t| t.pid) {
            Ok(i) if self.tracks[i].start == p.start as u32 => i,
            // Same pid, different process: start over.
            Ok(i) => return self.tracks[i] = Track::new(p),
            Err(i) => return self.tracks.insert(i, Track::new(p)),
        };
        let pol = match lane {
            Lane::Normal => &self.policy,
            Lane::Fast => &self.fast,
            Lane::Stale => &self.stale,
        };
        let (now, dt) = (self.now, self.dt);
        let now32 = now as u32;
        let t = &mut self.tracks[idx];
        t.flags |= SEEN;
        if dt == 0 {
            return;
        }
        let cpu_pct = (p.cpu_ns.saturating_sub(t.last_cpu) as f64 / (dt as f64 * 1e6) * 100.0) as f32;
        t.last_cpu = p.cpu_ns;

        let act = |act, hot_ms, idle| Action { pid: p.pid, start: p.start, act, cpu_pct, rss: p.rss, age_s, hot_ms, idle };

        // Escalation runs regardless of current load.
        if t.flags & TERM_SENT != 0 {
            if t.flags & DONE == 0 && now32.wrapping_sub(t.term_at) as u64 >= pol.grace_ms {
                out.push(act(Act::Kill, 0, false));
                t.flags |= DONE;
            }
            return;
        }
        if self.rebase {
            t.flags &= !(HOT | IDLE);
            return;
        }

        let alive = !matches!(p.state, State::Zombie | State::Stop);
        let over = cpu_pct >= pol.cpu_pct || (pol.mem_bytes > 0 && p.rss >= pol.mem_bytes);
        let hot = over && age_s >= pol.min_age_s && alive;
        // Left behind (detached, or simply too old) and doing nothing.
        let idle = pol.idle_ms > 0
            && cpu_pct < pol.idle_cpu_pct
            && age_s >= pol.idle_min_age_s
            && (p.ppid == 1 || !pol.idle_detached)
            && alive;
        if !hot && !idle {
            t.flags &= !(HOT | IDLE | DONE);
            return;
        }
        if t.flags & DONE != 0 {
            return;
        }
        // Each condition was already true during the window that just ended.
        if !hot {
            t.flags &= !HOT;
        } else if t.flags & HOT == 0 {
            t.flags |= HOT;
            t.hot_since = (now - dt) as u32;
        }
        if !idle {
            t.flags &= !IDLE;
        } else if t.flags & IDLE == 0 {
            t.flags |= IDLE;
            t.idle_since = (now - dt) as u32;
        }
        let hot_ms = if hot { now32.wrapping_sub(t.hot_since) as u64 } else { 0 };
        let idle_ms = if idle { now32.wrapping_sub(t.idle_since) as u64 } else { 0 };
        let (for_ms, by_idle) = if hot && hot_ms >= pol.sustain_ms {
            (hot_ms, false)
        } else if idle && idle_ms >= pol.idle_ms {
            (idle_ms, true)
        } else {
            return;
        };
        if protected(p, by_idle) {
            out.push(act(Act::Spare, for_ms, by_idle));
            t.flags |= DONE;
        } else if pol.dry_run {
            out.push(act(Act::WouldKill, for_ms, by_idle));
            t.flags |= DONE;
        } else {
            out.push(act(Act::Term, for_ms, by_idle));
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
    pub fast_policy: Policy,
    pub stale_policy: Policy,
    fast: Vec<String>,
    stale: Vec<String>,
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
        idle_ms: 0,
        idle_cpu_pct: 1.0,
        idle_min_age_s: 0,
        idle_detached: true,
        dry_run: false,
    }
}

pub fn default_fast_policy() -> Policy {
    Policy {
        min_age_s: 10 * 60,
        mem_bytes: 2 << 30,
        sustain_ms: 2 * 60_000,
        grace_ms: 5_000,
        idle_ms: 10 * 60_000,
        ..default_policy()
    }
}

/// Same hot rules as the normal lane, plus the age-based idle rule.
pub fn default_stale_policy() -> Policy {
    Policy {
        idle_ms: 15 * 60_000,
        // An idle Claude session still ticks at ~1-2% of a core.
        idle_cpu_pct: 5.0,
        idle_min_age_s: 24 * 3600,
        idle_detached: false,
        ..default_policy()
    }
}

const FAST_DEFAULT: &[&str] = &["agent-browser", "Chrome for Testing"];
const STALE_DEFAULT: &[&str] = &["node", "next-server", "claude"];

pub fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Opts, String> {
    let mut o = Opts {
        policy: default_policy(),
        fast_policy: default_fast_policy(),
        stale_policy: default_stale_policy(),
        fast: FAST_DEFAULT.iter().map(|s| s.to_string()).collect(),
        stale: STALE_DEFAULT.iter().map(|s| s.to_string()).collect(),
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
        let f = &mut o.fast_policy;
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
            "--fast" => o.fast.push(val(&a)?),
            "--no-fast" => o.fast.clear(),
            "--fast-min-age" => f.min_age_s = parse_dur(&val(&a)?)? / 1000,
            "--fast-sustain" => f.sustain_ms = parse_dur(&val(&a)?)?,
            "--fast-mem" => f.mem_bytes = parse_mem(&val(&a)?)?,
            "--fast-idle" => f.idle_ms = parse_dur(&val(&a)?)?,
            "--stale" => o.stale.push(val(&a)?),
            "--no-stale" => o.stale.clear(),
            "--max-age" => o.stale_policy.idle_min_age_s = parse_dur(&val(&a)?)? / 1000,
            "--stale-idle" => o.stale_policy.idle_ms = parse_dur(&val(&a)?)?,
            "--stale-cpu" => {
                let v = val(&a)?;
                o.stale_policy.idle_cpu_pct =
                    v.trim_end_matches('%').parse().map_err(|_| format!("invalid --stale-cpu: {v}"))?
            }
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
    // The fast lane shares what is not lane-specific.
    let (p, f) = (&o.policy, &mut o.fast_policy);
    (f.cpu_pct, f.interval_ms, f.dry_run) = (p.cpu_pct, p.interval_ms, p.dry_run);
    f.grace_ms = f.grace_ms.min(p.grace_ms);
    // The stale lane is the normal lane plus its idle rule.
    let st = &mut o.stale_policy;
    *st = Policy {
        idle_ms: if st.idle_min_age_s == 0 { 0 } else { st.idle_ms },
        idle_cpu_pct: st.idle_cpu_pct,
        idle_min_age_s: st.idle_min_age_s,
        idle_detached: false,
        ..o.policy
    };
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

/// `stale_idle`: the stale lane's idle rule fired, which may reach the
/// protected names (a forgotten `claude` session); the path rules still hold.
fn is_protected(p: &Proc, o: &Opts, stale_idle: bool, buf: &mut [u8; PATH_MAX]) -> bool {
    let name = p.name();
    if !stale_idle && PROTECTED.iter().any(|n| n.eq_ignore_ascii_case(name)) {
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
    let log = Log { path: o.log.as_deref() };

    let pol = &o.policy;
    let mem = Bytes(pol.mem_bytes);
    log.write(format_args!(
        "START pid={self_pid} min-age={} cpu>={}% mem>={} sustain={} interval={}ms grace={}ms{}",
        Dur(pol.min_age_s),
        pol.cpu_pct,
        if pol.mem_bytes == 0 { &"off" as &dyn std::fmt::Display } else { &mem },
        Dur(pol.sustain_ms / 1000),
        pol.interval_ms,
        pol.grace_ms,
        if pol.dry_run { " DRY-RUN" } else { "" },
    ));
    if !o.fast.is_empty() {
        let f = &o.fast_policy;
        log.write(format_args!(
            "FAST-LANE {:?} min-age={} mem>={} sustain={} idle={} grace={}ms",
            o.fast,
            Dur(f.min_age_s),
            Bytes(f.mem_bytes),
            Dur(f.sustain_ms / 1000),
            if f.idle_ms == 0 { "off".to_string() } else { Dur(f.idle_ms / 1000).to_string() },
            f.grace_ms,
        ));
    }
    if !o.stale.is_empty() && o.stale_policy.idle_ms > 0 {
        let s = &o.stale_policy;
        log.write(format_args!(
            "STALE-LANE {:?} max-age={} idle={} cpu<{}%",
            o.stale,
            Dur(s.idle_min_age_s),
            Dur(s.idle_ms / 1000),
            s.idle_cpu_pct,
        ));
    }

    let mut engine = Engine::new(o.policy, o.fast_policy, o.stale_policy);
    let mut actions: Vec<Action> = Vec::with_capacity(16);
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
            let has = |pats: &[String]| pats.iter().any(|n| p.name().contains(n.as_str()));
            let lane = if has(&o.fast) {
                Lane::Fast
            } else if has(&o.stale) {
                Lane::Stale
            } else {
                Lane::Normal
            };
            engine.observe(
                &p,
                age_s,
                lane,
                |p, by_idle| is_protected(p, &o, lane == Lane::Stale && by_idle, &mut path_buf),
                &mut actions,
            );
        });
        engine.end_tick();

        for act in actions.drain(..) {
            execute(&act, me, &o, &log);
        }

        tick += 1;
        if o.ticks.is_some_and(|n| tick >= n) {
            break;
        }
        std::thread::sleep(Duration::from_millis(engine.policy.interval_ms));
    }
}

fn execute(a: &Action, me: u32, o: &Opts, log: &Log) {
    let mut cmd = StackBuf::<240>::new();
    if !proc::cmdline(a.pid, &mut cmd, 200) {
        let _ = cmd.write_char('?');
    }

    // Never signal a pid that now belongs to someone else.
    if proc::identity(a.pid) != Some((a.start, me)) {
        log.write(format_args!("GONE pid={} (exited or reused before {:?})", a.pid, a.act));
        return;
    }

    let (tag, ok) = match a.act {
        Act::Term => ("TERM", proc::signal(a.pid, SIGTERM)),
        Act::Kill => ("KILL", proc::signal(a.pid, SIGKILL)),
        Act::WouldKill => ("WOULD-KILL", true),
        Act::Spare => ("SPARED", true),
    };
    log.write(format_args!(
        "{tag}{} pid={} age={} cpu={:.0}% rss={} {}-for={} cmd={}",
        if ok { "" } else { "(failed)" },
        a.pid,
        Dur(a.age_s),
        a.cpu_pct,
        Bytes(a.rss),
        if a.idle { "idle" } else { "hot" },
        Dur(a.hot_ms / 1000),
        cmd.as_str(),
    ));

    if o.notify && matches!(a.act, Act::Term | Act::WouldKill) {
        let mut msg = StackBuf::<160>::new();
        let short: &str = {
            let s = cmd.as_str();
            s.char_indices().nth(60).map_or(s, |(i, _)| &s[..i])
        };
        let _ = write!(
            msg,
            "{}{} pid {} ({:.0}% CPU, {}, up {}): {short}",
            if a.act == Act::Term { "Killed" } else { "Would kill" },
            if a.idle { " idle" } else { "" },
            a.pid,
            a.cpu_pct,
            Bytes(a.rss),
            Dur(a.age_s),
        );
        notify(msg.as_str());
    }
}

unsafe extern "C" {
    fn posix_spawn(
        pid: *mut i32,
        path: *const c_char,
        file_actions: *const *mut c_void,
        attr: *const c_void,
        argv: *const *const c_char,
        envp: *const *const c_char,
    ) -> i32;
    fn posix_spawn_file_actions_init(fa: *mut *mut c_void) -> i32;
    fn posix_spawn_file_actions_addopen(
        fa: *mut *mut c_void,
        fd: i32,
        path: *const c_char,
        oflag: i32,
        mode: u16,
    ) -> i32;
    fn posix_spawn_file_actions_destroy(fa: *mut *mut c_void) -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
}

/// macOS notification through osascript, spawned directly with an empty
/// environment (std's Command would copy the whole environment).
fn notify(msg: &str) {
    let mut script = StackBuf::<400>::new();
    let _ = script.write_str("display notification \"");
    for ch in msg.chars() {
        if matches!(ch, '"' | '\\') {
            let _ = script.write_char('\\');
        }
        let _ = script.write_char(ch);
    }
    if script.write_str("\" with title \"jäger\"\0").is_err() {
        return;
    }
    let argv = [c"osascript".as_ptr(), c"-e".as_ptr(), script.as_bytes().as_ptr().cast(), std::ptr::null()];
    let envp = [std::ptr::null::<c_char>()];
    unsafe {
        let mut fa: *mut c_void = std::ptr::null_mut();
        posix_spawn_file_actions_init(&mut fa);
        posix_spawn_file_actions_addopen(&mut fa, 1, c"/dev/null".as_ptr(), 1, 0);
        posix_spawn_file_actions_addopen(&mut fa, 2, c"/dev/null".as_ptr(), 1, 0);
        let mut pid = 0;
        let rc = posix_spawn(&mut pid, c"/usr/bin/osascript".as_ptr(), &fa, std::ptr::null(), argv.as_ptr(), envp.as_ptr());
        posix_spawn_file_actions_destroy(&mut fa);
        if rc == 0 {
            let mut st = 0;
            waitpid(pid, &mut st, 0);
        }
    }
}

/// Append-only log with 1 MiB rotation. Lines are formatted on the stack
/// and the file is opened per write: events are rare and an idle daemon
/// holds no descriptor and no buffer.
pub struct Log<'a> {
    path: Option<&'a Path>,
}

impl Log<'_> {
    pub fn write(&self, msg: std::fmt::Arguments) {
        let mut line = StackBuf::<512>::new();
        timestamp(&mut line);
        let _ = write!(line, " {msg}");
        let _ = line.write_char('\n');
        let Some(path) = self.path else {
            let _ = std::io::stderr().write_all(line.as_bytes());
            return;
        };
        if std::fs::metadata(path).is_ok_and(|m| m.len() > 1 << 20) {
            let _ = std::fs::rename(path, path.with_extension("log.1"));
        }
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

/// UTC timestamp, e.g. "2026-10-12 21:42:58Z". Local time would make libc
/// load the timezone database (~80 KB, resident forever); `jager status`
/// converts to local time when displaying.
fn timestamp(out: &mut impl std::fmt::Write) {
    let t = now_ms() / 1000;
    let (secs, days) = (t % 86_400, (t / 86_400) as i64);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + (m <= 2) as i64;
    let _ = write!(
        out,
        "{y}-{m:02}-{d:02} {:02}:{:02}:{:02}Z",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
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
            idle_ms: 0,
            idle_cpu_pct: 1.0,
            idle_min_age_s: 0,
            idle_detached: true,
            dry_run: false,
        }
    }

    fn fast_policy() -> Policy {
        Policy { min_age_s: 600, mem_bytes: 2 << 30, sustain_ms: 2 * MIN, idle_ms: 10 * MIN, ..policy() }
    }

    fn stale_policy() -> Policy {
        Policy { idle_ms: 15 * MIN, idle_cpu_pct: 5.0, idle_min_age_s: 24 * H, idle_detached: false, ..policy() }
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
        lane: Lane,
    }

    impl Sim {
        fn new(pol: Policy, age_s: u64) -> Self {
            let now = 1_000_000 * 1000;
            Sim {
                e: Engine::new(pol, fast_policy(), stale_policy()),
                p: proc_(42, now / 1000 - age_s),
                now,
                out: Vec::new(),
                lane: Lane::Normal,
            }
        }

        fn run(&mut self, secs: u64, load_pct: f64, protected: bool) {
            let steps = secs / 30;
            for _ in 0..steps {
                self.now += 30_000;
                self.p.cpu_ns += (30e9 * load_pct / 100.0) as u64;
                let mut acts = Vec::new();
                self.e.begin_tick(self.now);
                let age = self.now / 1000 - self.p.start;
                self.e.observe(&self.p, age, self.lane, |_, _| protected, &mut acts);
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
        let mut e = Engine::new(policy(), fast_policy(), stale_policy());
        e.begin_tick(1000);
        e.observe(&proc_(1, 0), 0, Lane::Normal, |_, _| false, &mut Vec::new());
        e.observe(&proc_(2, 0), 0, Lane::Normal, |_, _| false, &mut Vec::new());
        e.end_tick();
        assert_eq!(e.tracked(), 2);
        e.begin_tick(2000);
        e.observe(&proc_(2, 0), 0, Lane::Normal, |_, _| false, &mut Vec::new());
        e.end_tick();
        assert_eq!(e.tracked(), 1);
    }

    fn fast_sim(age_s: u64, ppid: u32) -> Sim {
        let mut s = Sim::new(policy(), age_s);
        s.lane = Lane::Fast;
        s.p.ppid = ppid;
        s
    }

    #[test]
    fn fast_lane_kills_a_hot_browser_within_minutes() {
        let mut s = fast_sim(15 * 60, 500);
        s.run(2 * 60, 150.0, false);
        assert!(s.acts().is_empty());
        s.run(30, 150.0, false);
        assert_eq!(s.acts(), [Act::Term]);
        s.run(30, 150.0, false);
        assert_eq!(s.acts(), [Act::Term, Act::Kill], "fast grace (5s) < one tick");
    }

    #[test]
    fn fast_lane_lowers_the_memory_bar() {
        let mut s = fast_sim(15 * 60, 500);
        s.p.rss = 3 << 30;
        s.run(2 * 60 + 30, 0.0, false);
        assert_eq!(s.acts(), [Act::Term]);
        let mut slow = Sim::new(policy(), 5 * H);
        slow.p.rss = 3 << 30;
        slow.run(60 * 60, 0.0, false);
        assert!(slow.acts().is_empty(), "same process outside the lane is fine");
    }

    #[test]
    fn detached_idle_browser_is_killed_as_abandoned() {
        let mut s = fast_sim(60, 1);
        s.run(10 * 60, 0.0, false);
        assert!(s.acts().is_empty());
        s.run(30, 0.0, false);
        assert_eq!(s.acts(), [Act::Term]);
        assert!(s.out[0].1.idle);
    }

    #[test]
    fn a_browser_in_use_is_not_idle() {
        let mut s = fast_sim(60, 1);
        for _ in 0..4 {
            s.run(8 * 60, 0.0, false);
            s.run(30, 20.0, false); // a command came in
        }
        assert!(s.acts().is_empty());
    }

    #[test]
    fn idle_rule_needs_a_detached_process() {
        let mut s = fast_sim(60, 500); // Chrome under its daemon
        s.run(60 * 60, 0.0, false);
        assert!(s.acts().is_empty());
    }

    #[test]
    fn idle_rule_is_off_outside_the_fast_lane() {
        let mut s = Sim::new(policy(), 5 * H);
        s.p.ppid = 1;
        s.run(60 * 60, 0.0, false);
        assert!(s.acts().is_empty());
    }

    fn stale_sim(age_s: u64) -> Sim {
        let mut s = Sim::new(policy(), age_s);
        s.lane = Lane::Stale;
        s.p.ppid = 500; // its session is still alive
        s
    }

    #[test]
    fn forgotten_dev_server_is_killed_after_max_age() {
        let mut s = stale_sim(30 * H);
        s.p.rss = 5 << 30;
        s.run(15 * 60, 0.0, false);
        assert!(s.acts().is_empty());
        s.run(30, 0.0, false);
        assert_eq!(s.acts(), [Act::Term]);
        assert!(s.out[0].1.idle);
    }

    #[test]
    fn idle_claude_session_ticking_at_two_percent_counts_as_quiet() {
        let mut s = stale_sim(30 * H);
        s.run(15 * 60 + 30, 2.0, false);
        assert_eq!(s.acts(), [Act::Term]);
    }

    #[test]
    fn stale_lane_waits_for_max_age() {
        let mut s = stale_sim(23 * H);
        s.run(50 * 60, 0.0, false);
        assert!(s.acts().is_empty());
        s.run(24 * 60, 0.0, false);
        assert!(s.acts().is_empty(), "quiet time counts only past max-age");
        s.run(30, 0.0, false);
        assert_eq!(s.acts(), [Act::Term]);
        assert_eq!(s.out[0].1.hot_ms, 15 * MIN);
    }

    #[test]
    fn busy_old_session_is_left_alone() {
        let mut s = stale_sim(30 * H);
        for _ in 0..6 {
            s.run(10 * 60, 0.0, false);
            s.run(30, 30.0, false); // working
        }
        assert!(s.acts().is_empty());
    }

    #[test]
    fn stale_idle_rule_is_off_in_the_normal_lane() {
        let mut s = Sim::new(policy(), 30 * H);
        s.run(60 * 60, 0.0, false);
        assert!(s.acts().is_empty());
    }

    #[test]
    fn stale_lane_options() {
        let o = parse_args(["--max-age", "12h", "--stale-cpu", "3", "--dry-run"].map(String::from).into_iter()).unwrap();
        assert_eq!(o.stale_policy.idle_min_age_s, 12 * H);
        assert_eq!(o.stale_policy.idle_cpu_pct, 3.0);
        assert!(o.stale_policy.dry_run);
        assert!(!o.stale_policy.idle_detached);
        assert_eq!(o.stale, STALE_DEFAULT);
        let o = parse_args(["--max-age", "0"].map(String::from).into_iter()).unwrap();
        assert_eq!(o.stale_policy.idle_ms, 0);
    }

    #[test]
    fn utc_timestamp_matches_libc() {
        let mut b = StackBuf::<32>::new();
        timestamp(&mut b);
        let out = std::process::Command::new("date").args(["-u", "+%Y-%m-%d %H:%M"]).output().unwrap();
        let want = String::from_utf8(out.stdout).unwrap();
        assert!(b.as_str().starts_with(want.trim()), "{} vs {want}", b.as_str());
        assert!(b.as_str().ends_with('Z'));
    }

    #[test]
    fn parses_mem() {
        assert_eq!(parse_mem("8G").unwrap(), 8 << 30);
        assert_eq!(parse_mem("512M").unwrap(), 512 << 20);
        assert_eq!(parse_mem("0").unwrap(), 0);
        assert!(parse_mem("50%").unwrap() > 0);
        assert!(parse_mem("lots").is_err());
    }

    #[test]
    fn fast_lane_shares_cpu_and_dry_run() {
        let o = parse_args(["--cpu", "60", "--dry-run", "--grace", "2s"].map(String::from).into_iter()).unwrap();
        assert_eq!(o.fast_policy.cpu_pct, 60.0);
        assert!(o.fast_policy.dry_run);
        assert_eq!(o.fast_policy.grace_ms, 2_000);
        assert_eq!(o.fast, FAST_DEFAULT);
        let o = parse_args(["--no-fast", "--fast", "puppeteer"].map(String::from).into_iter()).unwrap();
        assert_eq!(o.fast, ["puppeteer"]);
    }
}
