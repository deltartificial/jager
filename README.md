![jäger](assets/banner.jpg)

# jäger

A resident macOS hunter for processes that have been running for too long: infinite loops, `node` servers that won't die, never-ending queries, memory hogs. It runs all the time, decides on its own, and kills them.

- Zero dependencies: direct FFI into `libproc` / `sysctl` (libSystem).
- **865 KB physical footprint**, flat over time: 48 KB above an empty Rust program (817 KB) on the same machine.
- **~0.58 ms CPU per scan** of ~500 processes → ~70 ms of CPU per hour at the default 30 s interval.

## Why it is that small

| Technique | Saved |
|---|---|
| `MallocNanoZone=0` (set in the LaunchAgent, or via a one-time self re-exec) | ~380 KB |
| pid list in a zeroed `static` (BSS) instead of the stack: stack probes would dirty the whole 64 KB | ~110 KB |
| UTC log timestamps: `localtime_r` would load the tz database (~80 KB, resident forever) | ~80 KB |
| zero allocation per tick: sorted `Vec` of 32-byte tracks allocated once (no `HashMap`), log lines and argv formatted into stack buffers, argv read through `mmap`/`munmap`, notifications via `posix_spawn` with an empty env | growth → flat |

Before: 1953 KB and growing. After: 865 KB, flat over 900 ticks.

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

Every decision goes to `~/Library/Logs/jager.log` (rotated at 1 MiB, UTC timestamps; `jager status` shows them in local time), plus a macOS notification:

```
2026-10-12 21:29:50Z TERM pid=58058 age=5h00m cpu=100% rss=2M hot-for=10m00s cmd=/bin/sh -c ...
2026-10-12 21:30:05Z KILL pid=58058 age=5h00m cpu=100% rss=2M hot-for=0s cmd=/bin/sh -c ...
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
