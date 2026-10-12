//! `jager watch`: the resident hunter.
//!
//! Every `interval` it scans the current user's processes, measures CPU over
//! the last interval, and kills (SIGTERM, then SIGKILL after `grace`) any
//! process that is older than `min_age` and has stayed above the CPU or
//! memory threshold for `sustain` in a row.

use crate::proc::{self, PATH_MAX, Proc, SIGKILL, SIGTERM, State};
use crate::util::{fmt_bytes, fmt_dur, now_ms, parse_dur};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::PathBuf;
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

#[derive(Clone, Copy)]
struct Track {
    start: u64,
    last_cpu: u64,
    last_ms: u64,
    hot_since: Option<u64>,
    term_at: Option<u64>,
    /// Already acted upon in this hot episode.
    done: bool,
    seen: bool,
}

/// Pure decision engine: feed it process snapshots with a clock, it returns
/// actions. No syscalls, so it is fully testable with fake time.
pub struct Engine {
    pub policy: Policy,
    tracks: HashMap<u32, Track>,
    now: u64,
    last_tick: Option<u64>,
    /// Set after a long gap (machine asleep): CPU deltas are meaningless.
    rebase: bool,
}

impl Engine {
    pub fn new(policy: Policy) -> Self {
        Engine { policy, tracks: HashMap::new(), now: 0, last_tick: None, rebase: false }
    }

    pub fn tracked(&self) -> usize {
        self.tracks.len()
    }

    pub fn begin_tick(&mut self, now_ms: u64) {
        self.now = now_ms;
        self.rebase = matches!(self.last_tick, Some(t) if now_ms.saturating_sub(t) > 3 * self.policy.interval_ms.max(1));
        for t in self.tracks.values_mut() {
            t.seen = false;
        }
    }

    /// `age_s` is supplied by the caller so time can be warped in tests.
    pub fn observe(
        &mut self,
        p: &Proc,
        age_s: u64,
        mut protected: impl FnMut(&Proc) -> bool,
        out: &mut Vec<Action>,
    ) {
        let now = self.now;
        let pol = &self.policy;
        // New pid, or pid reused by a different process.
        if self.tracks.get(&p.pid).is_none_or(|t| t.start != p.start) {
            self.tracks.insert(
                    p.pid,
                Track {
                    start: p.start,
                    last_cpu: p.cpu_ns,
                    last_ms: now,
                    hot_since: None,
                    term_at: None,
                    done: false,
                    seen: true,
                },
            );
            return;
        }
        let Some(t) = self.tracks.get_mut(&p.pid) else { return };
        t.seen = true;
        let prev_ms = t.last_ms;
        let dt = now.saturating_sub(prev_ms);
        if dt == 0 {
            return;
        }
        let cpu_pct = (p.cpu_ns.saturating_sub(t.last_cpu) as f64 / (dt as f64 * 1e6) * 100.0) as f32;
        t.last_cpu = p.cpu_ns;
        t.last_ms = now;

        let act = |act, hot_ms| Action {
            pid: p.pid,
            start: p.start,
            act,
            cpu_pct,
            rss: p.rss,
            age_s,
            hot_ms,
        };

        // Escalation runs regardless of current load.
        if let Some(at) = t.term_at {
            if !t.done && now.saturating_sub(at) >= pol.grace_ms {
                out.push(act(Act::Kill, 0));
                t.done = true;
            }
            return;
        }
        if self.rebase {
            t.hot_since = None;
            return;
        }

        let over = cpu_pct >= pol.cpu_pct || (pol.mem_bytes > 0 && p.rss >= pol.mem_bytes);
        let hot = over && age_s >= pol.min_age_s && !matches!(p.state, State::Zombie | State::Stop);
        if !hot {
            t.hot_since = None;
            t.done = false;
            return;
        }
        if t.done {
            return;
        }
        // It was already over threshold during the window that just ended.
        let since = *t.hot_since.get_or_insert(prev_ms);
        let hot_ms = now - since;
        if hot_ms < pol.sustain_ms {
            return;
        }
        if protected(p) {
            out.push(act(Act::Spare, hot_ms));
            t.done = true;
        } else if pol.dry_run {
            out.push(act(Act::WouldKill, hot_ms));
            t.done = true;
        } else {
            out.push(act(Act::Term, hot_ms));
            t.term_at = Some(now);
        }
    }

    pub fn end_tick(&mut self) {
        self.tracks.retain(|_, t| t.seen);
        self.last_tick = Some(self.now);
        self.rebase = false;
    }
}
