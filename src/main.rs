//! jäger — hunts processes that have been running for too long.

mod bench;
mod launchd;
mod proc;
mod scan;
mod util;
mod watch;

const HELP: &str = "\
jäger — hunts processes that have been running for too long (macOS)

USAGE: jager <COMMAND> [OPTIONS]

COMMANDS:
  scan        one-shot report of long-running processes (default)
  watch       resident hunter: kills processes that stay hot for too long
  install     run `watch` at login as a LaunchAgent (takes `watch` options)
  uninstall   remove the LaunchAgent
  status      agent state, footprint and last events
  bench       measure the cost of one hunting tick

Run `jager <COMMAND> --help` for options.
";

fn main() {
    // Behave like a normal Unix tool when piped into `head`: die on SIGPIPE
    // instead of panicking on the failed write.
    unsafe extern "C" {
        fn signal(sig: i32, handler: usize) -> usize;
    }
    unsafe { signal(13, 0) };

    let mut args = std::env::args().skip(1).peekable();
    let cmd = match args.peek().map(String::as_str) {
        Some("scan" | "watch" | "install" | "uninstall" | "status" | "bench") => args.next(),
        Some("-h" | "--help" | "help") => {
            print!("{HELP}");
            return;
        }
        _ => None,
    };
    let res = match cmd.as_deref() {
        Some("watch") => {
            lean_malloc();
            Ok(watch::run(args))
        }
        Some("install") => launchd::install(args.collect()),
        Some("uninstall") => launchd::uninstall(),
        Some("status") => Ok(launchd::status()),
        Some("bench") => Ok(bench::run(args)),
        _ => Ok(scan::run(args)),
    };
    if let Err(e) = res {
        eprintln!("jager: {e}");
        std::process::exit(1);
    }
}

/// The nano malloc zone keeps ~200-400 KB of dirty pages around, even for a
/// C program that never allocates. It can only be turned off before libmalloc
/// initializes, i.e. through the environment, so the daemon re-execs itself
/// once with it disabled. The LaunchAgent sets the variable directly.
fn lean_malloc() {
    use std::os::unix::process::CommandExt;
    if std::env::var_os("MallocNanoZone").is_some_and(|v| v == "0") {
        return;
    }
    let Ok(exe) = std::env::current_exe() else { return };
    // exec only returns on failure; then just run with the default allocator.
    let _ = std::process::Command::new(exe)
        .args(std::env::args_os().skip(1))
        .env("MallocNanoZone", "0")
        .exec();
}
