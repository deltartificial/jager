# jäger

A macOS hunter for processes that have been running for too long: infinite loops, `node` processes that won't die, never-ending queries, zombies, suspended processes.

- Zero dependencies: direct FFI into `libproc` / `sysctl` (libSystem).
- ~330 KB binary, ~2 MB peak memory.
- Measures **instant** CPU (1 s window) on top of the lifetime average.

```sh
cargo install --path .
jager                 # your processes > 1h that are hot, zombie, stopped, or attached to a terminal
jager -t 30m -c       # > 30 min, sorted by CPU
jager -a -u           # everything, all users (sudo to read other users' processes)
jager -h
```

| Verdict  | Meaning                               |
|----------|---------------------------------------|
| LOOP     | ≥ 90% of a core: likely a loop        |
| HOT      | ≥ 20% of a core                       |
| ZOMBIE   | dead, not reaped by its parent        |
| STOPPED  | suspended (Ctrl-Z, SIGSTOP)           |
| IDLE     | alive, resting (shown with `-a`)      |
