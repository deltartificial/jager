![jäger](assets/banner.jpg)

# jäger

Resident macOS daemon that kills long-running runaway processes.

- No dependencies, direct FFI to `libproc` / `sysctl`
- 865 KB footprint, ~0.6 ms CPU per scan

## Install

```sh
cargo install --path .
jager install            # LaunchAgent, starts at login
jager install --dry-run  # log only, never kill
jager status
jager uninstall
```

## Policy

A process is killed if it is yours, older than 3h, and above 80% CPU or 25% RAM for 10 min. System paths and `/Applications` are skipped. SIGTERM, then SIGKILL after 15 s.

```sh
jager watch --min-age 3h --cpu 80 --mem 25% --sustain 10m --interval 30s --grace 15s --protect NAME
```

Log: `~/Library/Logs/jager.log`

## Scan

```sh
jager            # one-shot report
jager -t 30m -c  # > 30 min, sorted by CPU
```

## Test

```sh
cargo test
jager bench
```
