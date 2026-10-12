//! Small formatting / parsing helpers shared by subcommands.

use std::fmt::Write as _;

pub fn fmt_dur(out: &mut String, s: u64) {
    out.clear();
    let (d, h, m) = (s / 86_400, s / 3600 % 24, s / 60 % 60);
    let _ = if d > 0 {
        write!(out, "{d}d{h:02}h")
    } else if h > 0 {
        write!(out, "{h}h{m:02}m")
    } else if m > 0 {
        write!(out, "{m}m{:02}s", s % 60)
    } else {
        write!(out, "{s}s")
    };
}

pub fn fmt_bytes(out: &mut String, b: u64) {
    out.clear();
    const K: f64 = 1024.0;
    let f = b as f64;
    let _ = if f >= K * K * K {
        write!(out, "{:.1}G", f / (K * K * K))
    } else if f >= K * K {
        write!(out, "{:.0}M", f / (K * K))
    } else {
        write!(out, "{:.0}K", f / K)
    };
}

/// "90s", "30m", "2h", "1d", "500ms", or bare seconds → milliseconds.
pub fn parse_dur(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 = num.parse().map_err(|_| format!("invalid duration: {s:?}"))?;
    let mult = match unit {
        "ms" => 1,
        "" | "s" => 1000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => return Err(format!("unknown unit in {s:?} (ms, s, m, h, d)")),
    };
    Ok(n * mult)
}

pub fn use_color() -> bool {
    unsafe extern "C" {
        fn isatty(fd: i32) -> i32;
    }
    std::env::var_os("NO_COLOR").is_none() && unsafe { isatty(1) } == 1
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
