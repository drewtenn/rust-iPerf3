use clap::Parser;

use rperf3::cli::{Cli, Mode};

fn main() {
    let parsed = Cli::parse();
    let mode = parsed.into_mode();
    let config_ref = match &mode {
        Mode::Client(c) | Mode::Server(c) => c,
    };
    if let Some(t) = config_ref.title.clone() {
        rperf3::common::stream::set_title(t);
    }
    if let Some(spec) = &config_ref.affinity {
        rperf3::common::affinity::set_affinity(spec);
    }
    if let Some(p) = &config_ref.logfile {
        #[cfg(unix)]
        if let Err(e) = redirect_stdout_to_file(p) {
            eprintln!("failed to open logfile {:?}: {:?}", p, e);
            std::process::exit(2);
        }
        #[cfg(not(unix))]
        {
            eprintln!("--logfile is not supported on this platform (non-unix)");
            let _ = p;
        }
    }
    match mode {
        Mode::Client(config) => rperf3::run_client(config),
        Mode::Server(config) => rperf3::run_server(config),
    }
}

/// Redirect stdout (fd 1) to `path` by appending/creating and dup2-ing.
///
/// SAFETY: `f` is a valid open file descriptor and fd 1 is the well-known
/// stdout. `dup2` is a POSIX syscall with well-defined semantics; we verify
/// the return value and propagate any error.
#[cfg(unix)]
fn redirect_stdout_to_file(path: &std::path::Path) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::os::unix::io::AsRawFd;

    let f = OpenOptions::new().create(true).append(true).open(path)?;
    // SAFETY: the file is valid, fd 1 is valid, dup2 is a safe POSIX syscall.
    unsafe {
        let r = libc::dup2(f.as_raw_fd(), 1);
        if r < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    // Keep file open so fd 1 remains valid after the local `f` would drop.
    std::mem::forget(f);
    Ok(())
}
