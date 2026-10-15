![jäger](assets/banner.jpg)

# jäger

A resident macOS hunter for processes that have been running for too long: infinite loops, `node` servers that won't die, never-ending queries, memory hogs. It runs all the time, decides on its own, and kills them.

- Zero dependencies: direct FFI into `libproc` / `sysctl` (libSystem).
- **865 KB** physical footprint, flat over time.
- **~0.6 ms** CPU per scan of ~500 processes, ~70 ms of CPU per hour.

## Install

```sh
cargo install --path .
jager install                 # LaunchAgent: starts at login, restarted if it dies
jager install --dry-run       # only logs/notifies what it would kill
jager status                  # agent state, footprint, last events
jager uninstall
```

## Kill policy (`jager watch`)

A process is killed when **all** of these hold:

1. it belongs to you (never root, never other users);
2. it is older than `--min-age` (default **3h**);
3. it has used ≥ `--cpu` of a core (default **80%**) or ≥ `--mem` of RSS (default **25% of RAM**) for `--sustain` in a row (default **10 min**, sampled every 30 s);
4. it is not protected: system paths, GUI apps in `/Applications` (unless `--include-apps`), and anything matching `--protect NAME`.

**Fast lane** for browsers driven by agents (names containing `agent-browser` or `Chrome for Testing`, change with `--fast NAME` / `--no-fast`): min age **10 min**, sustain **2 min**, memory bar **2 GB**, grace 5 s. A detached one (parent = launchd) that stays under 1% CPU for `--fast-idle` (**10 min**) is taken as abandoned by its session and killed; killing the `agent-browser` daemon closes its whole Chrome.

**Stale lane** for dev servers and agent sessions (names containing `node`, `next-server` or `claude`, change with `--stale NAME` / `--no-stale`): once older than `--max-age` (**24h**), one that stays under `--stale-cpu` (**5%**, an idle Claude session still ticks at 1-2%) for `--stale-idle` (**15 min**) is taken as forgotten and killed, even if the session that started it is still open. A busy one is left alone until it calms down.

It gets `SIGTERM`, then `SIGKILL` after `--grace` (15 s). The pid's start time and owner are re-checked before each signal, so a recycled pid is never hit. Time spent asleep never counts as hot.

Every decision goes to `~/Library/Logs/jager.log`, plus a macOS notification:

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

| Verdict  | Meaning                            |
|----------|------------------------------------|
| LOOP     | ≥ 90% of a core: likely a loop     |
| HOT      | ≥ 20% of a core                    |
| ZOMBIE   | dead, not reaped by its parent     |
| STOPPED  | suspended (Ctrl-Z, SIGSTOP)        |
| IDLE     | alive, resting (shown with `-a`)   |

## Tests & benchmarks

```sh
cargo test            # decision engine on a fake clock + real processes and real signals
jager bench -n 500    # cost of one scan tick
bench/soak.sh 300 1s  # whole-system dry-run, memory/CPU over time
```
