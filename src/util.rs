//! Small formatting / parsing helpers shared by subcommands.

use std::fmt::{self, Write as _};

/// Human duration from seconds: "3d04h", "5h12m", "42m07s", "9s".
pub struct Dur(pub u64);

impl fmt::Display for Dur {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = self.0;
        let (d, h, m) = (s / 86_400, s / 3600 % 24, s / 60 % 60);
        let mut b = StackBuf::<16>::new();
        let _ = if d > 0 {
            write!(b, "{d}d{h:02}h")
        } else if h > 0 {
            write!(b, "{h}h{m:02}m")
        } else if m > 0 {
            write!(b, "{m}m{:02}s", s % 60)
        } else {
            write!(b, "{s}s")
        };
        f.pad(b.as_str())
    }
}

/// Human size from bytes: "1.2G", "340M", "12K".
pub struct Bytes(pub u64);

impl fmt::Display for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        const K: f64 = 1024.0;
        let v = self.0 as f64;
        let mut b = StackBuf::<16>::new();
        let _ = if v >= K * K * K {
            write!(b, "{:.1}G", v / (K * K * K))
        } else if v >= K * K {
            write!(b, "{:.0}M", v / (K * K))
        } else {
            write!(b, "{:.0}K", v / K)
        };
        f.pad(b.as_str())
    }
}

pub fn fmt_dur(out: &mut String, s: u64) {
    out.clear();
    let _ = write!(out, "{}", Dur(s));
}

pub fn fmt_bytes(out: &mut String, b: u64) {
    out.clear();
    let _ = write!(out, "{}", Bytes(b));
}

/// Fixed-capacity string on the stack. Writes past the end are truncated
/// at a char boundary instead of allocating.
pub struct StackBuf<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> StackBuf<N> {
    pub const fn new() -> Self {
        StackBuf { buf: [0; N], len: 0 }
    }

    pub fn as_str(&self) -> &str {
        // Only whole chars are ever copied in.
        unsafe { std::str::from_utf8_unchecked(&self.buf[..self.len]) }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl<const N: usize> fmt::Write for StackBuf<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let room = N - self.len;
        let mut n = s.len().min(room);
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        if n < s.len() { Err(fmt::Error) } else { Ok(()) }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_buf_truncates_on_char_boundary() {
        let mut b = StackBuf::<5>::new();
        assert!(write!(b, "abcé!").is_err());
        assert_eq!(b.as_str(), "abcé");
        let mut b = StackBuf::<4>::new();
        let _ = write!(b, "abcé");
        assert_eq!(b.as_str(), "abc");
    }

    #[test]
    fn formats_pad() {
        assert_eq!(format!("{:>7}", Dur(5 * 3600 + 120)), "  5h02m");
        assert_eq!(format!("{:>6}", Bytes(3 << 30)), "  3.0G");
        assert_eq!(format!("{}", Dur(86_400 * 2 + 3600)), "2d01h");
    }
}
