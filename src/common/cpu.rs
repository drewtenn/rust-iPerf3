//! CPU usage sampling for the test window.
//!
//! Linux-only (via /proc/self/stat). On other platforms the helpers
//! degrade gracefully to zeros so the calling code doesn't need
//! platform cfgs. `CpuUsage` is returned by value from a pure
//! function so the accounting math can be unit-tested without
//! touching /proc.

use std::time::Duration;

/// A snapshot of process-level CPU time. `user_ticks` and
/// `system_ticks` are in units of `sysconf(_SC_CLK_TCK)` (typically
/// 100 Hz on Linux).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CpuSnapshot {
    pub user_ticks: u64,
    pub system_ticks: u64,
}

/// A computed delta between two snapshots, normalised to percent of
/// one core over the wall-clock window.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CpuUsage {
    pub user_pct: f64,
    pub system_pct: f64,
    pub total_pct: f64,
}

impl CpuUsage {
    pub const ZERO: CpuUsage = CpuUsage {
        user_pct: 0.0,
        system_pct: 0.0,
        total_pct: 0.0,
    };
}

/// Sample the current process's user + system tick counts. On
/// platforms without `/proc/self/stat` this returns `CpuSnapshot::
/// default()` — callers can still compute a (zero) delta.
pub fn sample() -> CpuSnapshot {
    #[cfg(target_os = "linux")]
    {
        linux::read_snapshot().unwrap_or_default()
    }
    #[cfg(not(target_os = "linux"))]
    {
        CpuSnapshot::default()
    }
}

/// Clock ticks per second, from `sysconf(_SC_CLK_TCK)`. Defaults to
/// 100 (the usual Linux value) when unavailable.
pub fn clock_ticks_per_sec() -> u64 {
    #[cfg(target_os = "linux")]
    {
        let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if v > 0 {
            v as u64
        } else {
            100
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        100
    }
}

/// Compute CPU usage between two snapshots over `wall`. Percent of one
/// core: 100% = a fully-saturated single core; multi-core workloads
/// can exceed 100.
pub fn usage(start: &CpuSnapshot, end: &CpuSnapshot, wall: Duration) -> CpuUsage {
    let wall_s = wall.as_secs_f64();
    if wall_s <= 0.0 {
        return CpuUsage::ZERO;
    }
    let ticks_per_sec = clock_ticks_per_sec() as f64;
    let user_secs = end.user_ticks.saturating_sub(start.user_ticks) as f64 / ticks_per_sec;
    let sys_secs = end.system_ticks.saturating_sub(start.system_ticks) as f64 / ticks_per_sec;

    CpuUsage {
        user_pct: 100.0 * user_secs / wall_s,
        system_pct: 100.0 * sys_secs / wall_s,
        total_pct: 100.0 * (user_secs + sys_secs) / wall_s,
    }
}

/// Parse `/proc/self/stat`'s single-line format. Exposed so tests can
/// exercise the parsing without touching the filesystem.
pub fn parse_proc_stat(raw: &str) -> Option<CpuSnapshot> {
    // /proc/[pid]/stat format: `pid (comm) state ppid ... utime(14) stime(15) ...`
    // comm can contain spaces and parentheses, so split on the last `)`.
    let close = raw.rfind(')')?;
    let after_comm = raw[close + 1..].trim_start();
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    // After `state` (index 0) the offsets in the man page are 1-indexed
    // starting from `ppid`. utime is the 14th field overall, i.e.
    // index 14 - 2 (pid + comm) - 1 (zero-based) = 11 in `fields`.
    // Equivalently: state=0, ppid=1, pgrp=2, session=3, tty_nr=4,
    // tpgid=5, flags=6, minflt=7, cminflt=8, majflt=9, cmajflt=10,
    // utime=11, stime=12.
    let user = fields.get(11)?.parse::<u64>().ok()?;
    let sys = fields.get(12)?.parse::<u64>().ok()?;
    Some(CpuSnapshot {
        user_ticks: user,
        system_ticks: sys,
    })
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{parse_proc_stat, CpuSnapshot};
    use std::fs;

    pub fn read_snapshot() -> Option<CpuSnapshot> {
        let raw = fs::read_to_string("/proc/self/stat").ok()?;
        parse_proc_stat(&raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_realistic_proc_stat_line() {
        // Minimal but realistic shape; comm contains a space + paren
        // to exercise the rfind(')') split.
        let raw = "1234 (rp )erf) S 1000 1234 1 0 -1 4194304 10 20 0 0 125 250 0 0 20 0 2 0 1234 1 2 3\n";
        let snap = parse_proc_stat(raw).expect("parse");
        assert_eq!(snap.user_ticks, 125);
        assert_eq!(snap.system_ticks, 250);
    }

    #[test]
    fn parse_returns_none_on_malformed_input() {
        assert!(parse_proc_stat("not stat").is_none());
        // Missing utime/stime fields.
        assert!(parse_proc_stat("1 (x) S 2 3 4").is_none());
    }

    #[test]
    fn usage_math_normalises_by_wall_clock() {
        // 100 ticks user + 100 ticks system over 1 second, at 100 Hz
        // tick rate, is 100% user + 100% system = 200% total (two
        // fully-loaded cores).
        let start = CpuSnapshot {
            user_ticks: 0,
            system_ticks: 0,
        };
        let end = CpuSnapshot {
            user_ticks: 100,
            system_ticks: 100,
        };

        // Temporarily assume clk_tck = 100 (the common Linux value).
        // On an oddly-configured box this test could be off, but the
        // math is what we're verifying.
        let ticks_per_sec = clock_ticks_per_sec() as f64;
        let u = usage(&start, &end, Duration::from_secs(1));
        assert!((u.user_pct - 100.0 * 100.0 / ticks_per_sec).abs() < 1e-6);
        assert!((u.system_pct - 100.0 * 100.0 / ticks_per_sec).abs() < 1e-6);
        assert!((u.total_pct - 2.0 * 100.0 * 100.0 / ticks_per_sec).abs() < 1e-6);
    }

    #[test]
    fn usage_is_zero_for_zero_wall_clock() {
        let snap = CpuSnapshot::default();
        assert_eq!(usage(&snap, &snap, Duration::ZERO), CpuUsage::ZERO);
    }

    #[test]
    fn sample_returns_something_on_this_platform() {
        // Not asserting specific values (too flaky), just that the
        // call doesn't panic. On Linux this should return non-zero
        // ticks fairly quickly; on other platforms it's zero.
        let _ = sample();
    }
}
