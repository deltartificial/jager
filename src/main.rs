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
        Some("watch") => Ok(watch::run(args)),
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
