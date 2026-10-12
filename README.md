# jäger

A resident macOS hunter for processes that have been running for too long: infinite loops, `node` servers that won't die, never-ending queries, memory hogs. It runs all the time, decides on its own, and kills them.

- Zero dependencies: direct FFI into `libproc` / `sysctl` (libSystem).
- **~1.6 MB physical footprint**, flat over time (no allocation growth).
- **~0.66 ms CPU per scan** of ~500 processes → ~80 ms of CPU per hour at the default 30 s interval.

## Install

```sh
cargo install --path .
jager install                 # LaunchAgent: starts at login, restarted if it dies
jager install --dry-run       # same, but only logs/notifies what it would kill
jager status                  # agent state, footprint, last events
jager uninstall
```

## Kill policy (`jager watch`)

A process is killed when **all** of these hold:

1. it belongs to you (never root, never other users);
2. it is older than `--min-age` (default **3h**);
3. it has used ≥ `--cpu` of a core (default **80%**) or ≥ `--mem` of RSS (default **25% of RAM**) for `--sustain` in a row (default **10 min**, sampled every `--interval` = 30 s);
4. it is not protected: system paths (`/System`, `/usr/libexec`, `/usr/sbin`, …), GUI apps in `/Applications` (unless `--include-apps`), a short list of essentials, and anything matching `--protect NAME`.

It gets `SIGTERM`, then `SIGKILL` if still alive after `--grace` (15 s). Before each signal the pid's start time and owner are re-checked, so a recycled pid is never hit. After the machine sleeps, CPU counters are rebased so the time spent asleep never counts as "hot". Zombies and stopped processes are reported by `scan` but not killed.

Every decision goes to `~/Library/Logs/jager.log` (rotated at 1 MiB), plus a macOS notification:

```
2026-10-12 23:29:50 TERM pid=58058 age=5h00m cpu=100% rss=2M hot-for=10m00s cmd=/bin/sh -c ...
2026-10-12 23:30:05 KILL pid=58058 age=5h00m cpu=100% rss=2M hot-for=0s cmd=/bin/sh -c ...
```

## One-shot report (`jager scan`)

```sh
jager                 # your processes > 1h that are hot, zombie, stopped, or attached to a terminal
jager -t 30m -c       # > 30 min, sorted by CPU
jager -a -u           # everything, all users (sudo to read other users' processes)
```

| Verdict  | Meaning                               |
|----------|---------------------------------------|
| LOOP     | ≥ 90% of a core: likely a loop        |
| HOT      | ≥ 20% of a core                       |
| ZOMBIE   | dead, not reaped by its parent        |
| STOPPED  | suspended (Ctrl-Z, SIGSTOP)           |
| IDLE     | alive, resting (shown with `-a`)      |

## Tests & benchmarks

```sh
cargo test            # decision engine on a fake clock + real processes and real signals
jager bench -n 500    # cost of one full scan tick
bench/soak.sh 300 1s  # watcher on the whole system (dry-run), memory/CPU over time
```

The integration tests spawn real victims (`yes`, a shell loop that ignores `SIGTERM`, a 300 MB Perl hog, an idle `sleep`) and use the hidden `--time-warp 5h` flag to make them look hours old. `--only-pid` keeps the watcher away from everything else.
