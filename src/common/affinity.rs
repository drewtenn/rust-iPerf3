//! CPU affinity helper for the `-A / --affinity` flag.
//!
//! Pins the calling thread to a single CPU index. Only implemented on
//! Linux via `sched_setaffinity(2)`; all other platforms emit a warning
//! and return without error.

/// Pin the calling thread to the CPU identified by `spec`.
///
/// `spec` must be a single non-negative integer (e.g. `"0"` or `"3"`).
/// Range / list syntax (`"0-3"`, `"0,1"`) is intentionally deferred to
/// a follow-up; only the simple single-index form is implemented here.
///
/// On non-Linux platforms the function logs a warning and is a no-op.
#[cfg(target_os = "linux")]
pub fn set_affinity(spec: &str) {
    let Ok(cpu) = spec.parse::<usize>() else {
        eprintln!(
            "warning: invalid -A value '{}', expected integer CPU id",
            spec
        );
        return;
    };
    // SAFETY: We zero-initialize `cpu_set_t`, set exactly one bit via the
    // CPU_SET macro, then call sched_setaffinity(0, ...) targeting the
    // current thread. All pointers are valid stack references.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu, &mut set);
        if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) != 0 {
            eprintln!(
                "sched_setaffinity failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn set_affinity(_spec: &str) {
    eprintln!("warning: -A/--affinity is Linux-only; ignoring");
}
