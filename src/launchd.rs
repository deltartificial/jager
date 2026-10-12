//! `jager install | uninstall | status`: run `jager watch` as a LaunchAgent,
//! started at login and restarted if it dies.

use crate::proc;
use std::path::PathBuf;
use std::process::Command;

const LABEL: &str = "com.deltartificial.jager";

fn home() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
}

fn plist_path() -> PathBuf {
    home().join("Library/LaunchAgents").join(format!("{LABEL}.plist"))
}

fn domain() -> String {
    format!("gui/{}", proc::my_uid())
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn launchctl(args: &[&str]) -> bool {
    Command::new("/bin/launchctl")
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

pub fn install(args: Vec<String>) -> Result<(), String> {
    // Reject bad flags now rather than in a crash-looping agent.
    crate::watch::parse_args(args.iter().cloned())?;

    let exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .map_err(|e| format!("cannot locate own binary: {e}"))?;
    let exe = exe.to_str().ok_or("binary path is not UTF-8")?.to_owned();
    if exe.contains("/target/") {
        eprintln!("warning: installing from a build dir ({exe}); `cargo install --path .` gives a stable path");
    }

    let mut argv = format!("    <string>{}</string>\n    <string>watch</string>\n", xml_escape(&exe));
    for a in &args {
        argv.push_str(&format!("    <string>{}</string>\n", xml_escape(a)));
    }
    let err_log = home().join("Library/Logs/jager.err.log");
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array>
{argv}  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>MallocNanoZone</key>
    <string>0</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ProcessType</key>
  <string>Background</string>
  <key>LowPriorityIO</key>
  <true/>
  <key>Nice</key>
  <integer>10</integer>
  <key>StandardErrorPath</key>
  <string>{}</string>
</dict>
</plist>
"#,
        xml_escape(&err_log.to_string_lossy())
    );

    let path = plist_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let _ = std::fs::create_dir_all(home().join("Library/Logs"));
    std::fs::write(&path, plist).map_err(|e| format!("write {}: {e}", path.display()))?;

    let p = path.to_string_lossy();
    launchctl(&["bootout", &format!("{}/{LABEL}", domain())]);
    if !launchctl(&["bootstrap", &domain(), &p]) {
        return Err(format!("launchctl bootstrap failed for {p}"));
    }
    println!("installed: {p}");
    println!("running:   {exe} watch {}", args.join(" "));
    println!("log:       ~/Library/Logs/jager.log");
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    launchctl(&["bootout", &format!("{}/{LABEL}", domain())]);
    let path = plist_path();
    match std::fs::remove_file(&path) {
        Ok(()) => println!("removed: {}", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => println!("not installed"),
        Err(e) => return Err(e.to_string()),
    }
    Ok(())
}

pub fn status() {
    let loaded = launchctl(&["print", &format!("{}/{LABEL}", domain())]);
    println!("agent:  {}", if loaded { "loaded" } else { "not loaded" });

    // Find the running watcher and report its footprint.
    let me = proc::my_uid();
    let mut found = false;
    let mut buf = [0u8; proc::PATH_MAX];
    proc::scan(|p| {
        if p.uid != me || p.name() != "jager" || p.pid == std::process::id() {
            return;
        }
        found = true;
        let mut rss = String::new();
        let mut cpu = String::new();
        crate::util::fmt_bytes(&mut rss, p.rss);
        crate::util::fmt_dur(&mut cpu, p.cpu_ns / 1_000_000_000);
        let path = proc::path(p.pid, &mut buf).unwrap_or("?");
        println!("pid:    {} ({path})\nrss:    {rss}\ncpu:    {cpu} total ({} ms)", p.pid, p.cpu_ns / 1_000_000);
    });
    if !found {
        println!("pid:    not running");
    }

    let log = home().join("Library/Logs/jager.log");
    if let Ok(text) = std::fs::read_to_string(&log) {
        println!("\nlast events ({}):", log.display());
        let lines: Vec<&str> = text.lines().collect();
        for l in &lines[lines.len().saturating_sub(10)..] {
            match l.split_at_checked(20).and_then(|(ts, rest)| Some((utc_to_local(ts)?, rest))) {
                Some((local, rest)) => println!("  {local}{rest}"),
                None => println!("  {l}"),
            }
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

/// "2026-10-12 21:42:58Z" (as written by the daemon) → local "2026-10-12 23:42:58".
fn utc_to_local(ts: &str) -> Option<String> {
    let ts = ts.strip_suffix('Z')?;
    let num = |r: std::ops::Range<usize>| ts.get(r)?.parse::<i64>().ok();
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hh, mm, ss) = (num(11..13)?, num(14..16)?, num(17..19)?);
    // Howard Hinnant's days_from_civil.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let t = (era * 146_097 + doe - 719_468) * 86_400 + hh * 3600 + mm * 60 + ss;

    let mut tm = std::mem::MaybeUninit::<Tm>::zeroed();
    if unsafe { localtime_r(&t, tm.as_mut_ptr()) }.is_null() {
        return None;
    }
    let tm = unsafe { tm.assume_init() };
    Some(format!(
        "{}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.year + 1900,
        tm.mon + 1,
        tm.mday,
        tm.hour,
        tm.min,
        tm.sec
    ))
}
