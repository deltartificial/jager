//! macOS process layer: libproc + sysctl, straight from libSystem. No crates.

use std::ffi::{c_int, c_uint, c_void};
use std::mem::{MaybeUninit, size_of};

pub const NAME_LEN: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum State {
    Run,
    Sleep,
    Stop,
    Zombie,
    Other,
}

impl State {
    pub fn letter(self) -> char {
        match self {
            State::Run => 'R',
            State::Sleep => 'S',
            State::Stop => 'T',
            State::Zombie => 'Z',
            State::Other => '?',
        }
    }
}

/// One process snapshot. Fixed-size, no heap.
#[derive(Clone, Copy)]
pub struct Proc {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    /// Start time, unix seconds.
    pub start: u64,
    /// Total CPU time (user + system), nanoseconds.
    pub cpu_ns: u64,
    /// Resident memory, bytes.
    pub rss: u64,
    pub state: State,
    /// Has a controlling terminal.
    pub tty: bool,
    pub name: [u8; NAME_LEN],
    pub name_len: u8,
}

impl Proc {
    pub fn name(&self) -> &str {
        std::str::from_utf8(&self.name[..self.name_len as usize]).unwrap_or("?")
    }

    fn set_name(&mut self, src: &[u8]) {
        let n = src.iter().position(|&b| b == 0).unwrap_or(src.len()).min(NAME_LEN);
        self.name[..n].copy_from_slice(&src[..n]);
        self.name_len = n as u8;
    }
}

pub(crate) fn blank() -> Proc {
    Proc {
        pid: 0,
        ppid: 0,
        uid: 0,
        start: 0,
        cpu_ns: 0,
        rss: 0,
        state: State::Other,
        tty: false,
        name: [0; NAME_LEN],
        name_len: 0,
    }
}

/// Append `bytes` to `out`, replacing invalid UTF-8 and control chars,
/// stopping once `out` holds `max` chars.
fn push_clean(out: &mut String, bytes: &[u8], max: usize) {
    let mut n = out.chars().count();
    for ch in String::from_utf8_lossy(bytes).chars() {
        if n >= max {
            return;
        }
        out.push(if ch.is_control() { ' ' } else { ch });
        n += 1;
    }
}

#[repr(C)]
struct Passwd {
    pw_name: *const std::ffi::c_char,
    // Remaining fields differ per platform; only the first one is read.
}

unsafe extern "C" {
    fn getpwuid(uid: u32) -> *const Passwd;
    fn getuid() -> u32;
}

pub fn my_uid() -> u32 {
    unsafe { getuid() }
}

pub fn user_name(uid: u32, out: &mut String) {
    out.clear();
    let pw = unsafe { getpwuid(uid) };
    if !pw.is_null() {
        let name = unsafe { (*pw).pw_name };
        if !name.is_null() {
            let s = unsafe { std::ffi::CStr::from_ptr(name) };
            push_clean(out, s.to_bytes(), 10);
            return;
        }
    }
    use std::fmt::Write;
    let _ = write!(out, "{uid}");
}


const PROC_PIDTASKALLINFO: c_int = 2;
const PROC_FLAG_CONTROLT: u32 = 0x2;
const CTL_KERN: c_int = 1;
const KERN_ARGMAX: c_int = 8;
const KERN_PROCARGS2: c_int = 49;

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct ProcBsdInfo {
    pbi_flags: u32,
    pbi_status: u32,
    pbi_xstatus: u32,
    pbi_pid: u32,
    pbi_ppid: u32,
    pbi_uid: u32,
    pbi_gid: u32,
    pbi_ruid: u32,
    pbi_rgid: u32,
    pbi_svuid: u32,
    pbi_svgid: u32,
    rfu_1: u32,
    pbi_comm: [u8; 16],
    pbi_name: [u8; 32],
    pbi_nfiles: u32,
    pbi_pgid: u32,
    pbi_pjobc: u32,
    e_tdev: u32,
    e_tpgid: u32,
    pbi_nice: i32,
    pbi_start_tvsec: u64,
    pbi_start_tvusec: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct ProcTaskInfo {
    pti_virtual_size: u64,
    pti_resident_size: u64,
    pti_total_user: u64,
    pti_total_system: u64,
    pti_threads_user: u64,
    pti_threads_system: u64,
    pti_policy: i32,
    pti_faults: i32,
    pti_pageins: i32,
    pti_cow_faults: i32,
    pti_messages_sent: i32,
    pti_messages_received: i32,
    pti_syscalls_mach: i32,
    pti_syscalls_unix: i32,
    pti_csw: i32,
    pti_threadnum: i32,
    pti_numrunning: i32,
    pti_priority: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct ProcTaskAllInfo {
    pbsd: ProcBsdInfo,
    ptinfo: ProcTaskInfo,
}

const _: () = assert!(size_of::<ProcBsdInfo>() == 136);
const _: () = assert!(size_of::<ProcTaskInfo>() == 96);

#[repr(C)]
struct TimebaseInfo {
    numer: u32,
    denom: u32,
}

unsafe extern "C" {
    fn proc_listallpids(buf: *mut c_void, size: c_int) -> c_int;
    fn proc_pidinfo(pid: c_int, flavor: c_int, arg: u64, buf: *mut c_void, size: c_int) -> c_int;
    fn proc_pidpath(pid: c_int, buf: *mut c_void, size: u32) -> c_int;
    fn mach_timebase_info(info: *mut TimebaseInfo) -> c_int;
    fn kill(pid: c_int, sig: c_int) -> c_int;
    fn sysctlbyname(
        name: *const std::ffi::c_char,
        oldp: *mut c_void,
        oldlenp: *mut usize,
        newp: *mut c_void,
        newlen: usize,
    ) -> c_int;
    fn sysctl(
        name: *mut c_int,
        namelen: c_uint,
        oldp: *mut c_void,
        oldlenp: *mut usize,
        newp: *mut c_void,
        newlen: usize,
    ) -> c_int;
}

/// pti_total_* are in mach absolute time units (not ns on Apple Silicon).
fn timebase() -> (u64, u64) {
    let mut tb = TimebaseInfo { numer: 1, denom: 1 };
    unsafe { mach_timebase_info(&mut tb) };
    (tb.numer.max(1) as u64, tb.denom.max(1) as u64)
}

fn task_all_info(pid: u32) -> Option<ProcTaskAllInfo> {
    let mut info = MaybeUninit::<ProcTaskAllInfo>::uninit();
    let size = size_of::<ProcTaskAllInfo>() as c_int;
    let n = unsafe {
        proc_pidinfo(pid as c_int, PROC_PIDTASKALLINFO, 0, info.as_mut_ptr().cast(), size)
    };
    (n == size).then(|| unsafe { info.assume_init() })
}

/// Calls `f` for every readable process. Returns how many were unreadable
/// (typically other users' processes when not root).
pub fn scan(mut f: impl FnMut(Proc)) -> usize {
    let count = unsafe { proc_listallpids(std::ptr::null_mut(), 0) };
    if count <= 0 {
        return 0;
    }
    let mut pids: Vec<i32> = vec![0; count as usize + 64];
    let bytes = (pids.len() * size_of::<i32>()) as c_int;
    let n = unsafe { proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
    pids.truncate(n.max(0) as usize);

    let (numer, denom) = timebase();
    let mut unreadable = 0;
    for &pid in &pids {
        if pid <= 0 {
            continue;
        }
        let Some(ti) = task_all_info(pid as u32) else {
            unreadable += 1;
            continue;
        };
        let b = &ti.pbsd;
        let t = &ti.ptinfo;
        let mut p = blank();
        p.pid = b.pbi_pid;
        p.ppid = b.pbi_ppid;
        p.uid = b.pbi_uid;
        p.start = b.pbi_start_tvsec;
        p.cpu_ns = ((t.pti_total_user + t.pti_total_system) as u128 * numer as u128
            / denom as u128) as u64;
        p.rss = t.pti_resident_size;
        p.state = match b.pbi_status {
            2 => {
                if t.pti_numrunning > 0 { State::Run } else { State::Sleep }
            }
            3 => State::Sleep,
            4 => State::Stop,
            5 => State::Zombie,
            _ => State::Other,
        };
        p.tty = b.pbi_flags & PROC_FLAG_CONTROLT != 0 && b.e_tdev != u32::MAX;
        if b.pbi_name[0] != 0 {
            p.set_name(&b.pbi_name);
        } else {
            p.set_name(&b.pbi_comm);
        }
        f(p);
    }
    unreadable
}

/// Fresh total CPU time for one pid, in ns.
pub fn cpu_ns(pid: u32) -> Option<u64> {
    let (numer, denom) = timebase();
    task_all_info(pid).map(|ti| {
        let t = ti.ptinfo;
        ((t.pti_total_user + t.pti_total_system) as u128 * numer as u128 / denom as u128) as u64
    })
}

fn arg_max() -> usize {
    let mut mib = [CTL_KERN, KERN_ARGMAX];
    let mut val: c_int = 0;
    let mut len = size_of::<c_int>();
    let rc = unsafe {
        sysctl(mib.as_mut_ptr(), 2, (&mut val as *mut c_int).cast(), &mut len, std::ptr::null_mut(), 0)
    };
    if rc == 0 && val > 0 { val as usize } else { 256 * 1024 }
}

/// Writes the full command line (argv joined by spaces) into `out`.
/// `scratch` is reused across calls; untouched capacity never becomes resident.
pub fn cmdline(pid: u32, scratch: &mut Vec<u8>, out: &mut String, max: usize) -> bool {
    out.clear();
    if scratch.capacity() == 0 {
        scratch.reserve_exact(arg_max());
    }
    scratch.clear();
    let mut mib = [CTL_KERN, KERN_PROCARGS2, pid as c_int];
    let mut len = scratch.capacity();
    let rc = unsafe {
        sysctl(mib.as_mut_ptr(), 3, scratch.as_mut_ptr().cast(), &mut len, std::ptr::null_mut(), 0)
    };
    if rc != 0 || len < 4 {
        return false;
    }
    unsafe { scratch.set_len(len.min(scratch.capacity())) };

    // Layout: argc (i32) | exec_path \0 | \0 padding | argv[0] \0 ... argv[argc-1] \0 | env...
    let argc = i32::from_ne_bytes([scratch[0], scratch[1], scratch[2], scratch[3]]).max(0) as usize;
    let mut rest = &scratch[4..];
    let skip = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
    rest = &rest[skip..];
    let skip = rest.iter().position(|&c| c != 0).unwrap_or(rest.len());
    rest = &rest[skip..];

    for (i, arg) in rest.split(|&c| c == 0).take(argc).enumerate() {
        if i > 0 {
            out.push(' ');
        }
        push_clean(out, arg, max);
        if out.len() >= max {
            break;
        }
    }
    !out.is_empty()
}

/// (start time, uid) of a live pid, used to make sure a pid was not reused
/// before signalling it.
pub fn identity(pid: u32) -> Option<(u64, u32)> {
    task_all_info(pid).map(|ti| (ti.pbsd.pbi_start_tvsec, ti.pbsd.pbi_uid))
}

pub const PATH_MAX: usize = 4096;

/// Executable path of `pid`, written into `buf`.
pub fn path(pid: u32, buf: &mut [u8; PATH_MAX]) -> Option<&str> {
    let n = unsafe { proc_pidpath(pid as c_int, buf.as_mut_ptr().cast(), PATH_MAX as u32) };
    if n <= 0 {
        return None;
    }
    std::str::from_utf8(&buf[..n as usize]).ok()
}

pub const SIGKILL: i32 = 9;
pub const SIGTERM: i32 = 15;

pub fn signal(pid: u32, sig: i32) -> bool {
    pid > 1 && unsafe { kill(pid as c_int, sig) } == 0
}

/// Installed physical memory, bytes.
pub fn phys_mem() -> u64 {
    let mut val: u64 = 0;
    let mut len = size_of::<u64>();
    let rc = unsafe {
        sysctlbyname(c"hw.memsize".as_ptr(), (&mut val as *mut u64).cast(), &mut len, std::ptr::null_mut(), 0)
    };
    if rc == 0 { val } else { 0 }
}

/// (resident bytes, total CPU ns) of the current process.
pub fn self_usage() -> (u64, u64) {
    let (numer, denom) = timebase();
    task_all_info(std::process::id())
        .map(|ti| {
            let t = ti.ptinfo;
            let cpu = (t.pti_total_user + t.pti_total_system) as u128 * numer as u128 / denom as u128;
            (t.pti_resident_size, cpu as u64)
        })
        .unwrap_or((0, 0))
}
