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
            println!("  {l}");
        }
    }
}
