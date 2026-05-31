//! iPerf3-compatible server mode.
//!
//! Mirrors the client state machine from the other side of the wire:
//! accepts a control connection, reads the cookie, negotiates options,
//! opens data streams, receives bytes until the client says TestEnd,
//! then exchanges results. The functions in this module are built
//! small so each piece can be unit-tested against a loopback
//! `TcpListener` without spinning up the full binary.

use std::io;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use crate::common::auth;
use crate::common::cookie::{recv_cookie, COOKIE_LEN};
use crate::common::cpu::{self, CpuUsage};
use crate::common::interval::IntervalReporter;
use crate::common::protocol::{Protocol, Tcp, TuningOpts};
use crate::common::test::Config;
use crate::common::udp_session::{accept_udp_streams, bind_udp, run_udp_receiver};
use crate::common::wire::{
    recv_control_byte, recv_framed_json, send_control_byte, send_framed_json, send_u16_be,
    ClientOptions, Results, StreamResults,
};
use crate::common::Message;

/// Global auth configuration set once at server startup via `set_auth_config`.
/// Tests that don't go through `run_server` never populate this, so auth is
/// effectively disabled for them.
static AUTH_CONFIG: OnceLock<(Option<PathBuf>, Option<PathBuf>)> = OnceLock::new();

/// Configure the server's RSA private key and authorized-users file paths.
/// Must be called before `run_server_loop` / `serve_one_session` runs.
/// Subsequent calls are silently ignored (OnceLock semantics).
pub fn set_auth_config(priv_key: Option<PathBuf>, authorized: Option<PathBuf>) {
    let _ = AUTH_CONFIG.set((priv_key, authorized));
}

/// Validate an incoming `ClientOptions` authtoken against the global
/// `AUTH_CONFIG`. Returns `Ok(())` when:
/// * auth is not configured (no private key / no users file), or
/// * a valid, in-window authtoken is present and the user is known.
fn check_auth(control: &mut Protocol, opts: &ClientOptions) -> io::Result<()> {
    let Some((Some(pk_path), Some(users_path))) = AUTH_CONFIG
        .get()
        .map(|(a, b)| (a.as_ref(), b.as_ref()))
        .map(|(a, b)| (a.cloned(), b.cloned()))
    else {
        return Ok(()); // auth not configured
    };

    let deny = |control: &mut Protocol, msg: &str| -> io::Result<()> {
        eprintln!("auth failed: {}", msg);
        let _ = send_control_byte(control.transfer.as_mut(), Message::AccessDenied);
        Err(io::Error::new(io::ErrorKind::PermissionDenied, msg.to_string()))
    };

    let privkey = match auth::load_private_key_pem(&pk_path) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("auth config error: {}", e);
            let _ = send_control_byte(control.transfer.as_mut(), Message::AccessDenied);
            return Err(io::Error::new(io::ErrorKind::InvalidInput, e));
        }
    };
    let users = match auth::load_authorized_users(&users_path) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("auth config error: {}", e);
            let _ = send_control_byte(control.transfer.as_mut(), Message::AccessDenied);
            return Err(io::Error::new(io::ErrorKind::InvalidInput, e));
        }
    };

    let token = match opts.authtoken.as_ref() {
        Some(t) => t,
        None => return deny(control, "missing authtoken"),
    };

    let claim = match auth::decode_authtoken(&privkey, token) {
        Ok(c) => c,
        Err(e) => return deny(control, &e),
    };

    if let Err(e) = auth::validate_timestamp(&claim, auth::TIMESTAMP_SKEW_SECS) {
        return deny(control, &e);
    }

    if let Err(e) = auth::authorize(&claim, &users) {
        return deny(control, &e);
    }

    Ok(())
}

/// What a single reader thread observed. Keeps byte counts split into
/// omit / measured plus the timestamps of the first byte, first
/// post-omit byte, and last byte. This lets the server report steady-
/// state throughput separately from the full test window.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StreamReceipt {
    pub bytes: u64,
    pub bytes_omit: u64,
    pub first_byte_at: Option<Instant>,
    pub first_measured_at: Option<Instant>,
    pub last_byte_at: Option<Instant>,
    pub jitter_ms: f64,
    pub lost: u64,
    pub ooo: u64,
    pub packets: u64,
}

impl StreamReceipt {
    pub fn empty() -> Self {
        Self {
            bytes: 0,
            bytes_omit: 0,
            first_byte_at: None,
            first_measured_at: None,
            last_byte_at: None,
            jitter_ms: 0.0,
            lost: 0,
            ooo: 0,
            packets: 0,
        }
    }

    /// Bytes attributed to the measurement window (post-omit).
    pub fn bytes_measured(&self) -> u64 {
        self.bytes.saturating_sub(self.bytes_omit)
    }

    /// Duration between first and last observed byte on this stream,
    /// or zero if no bytes were seen. Includes the omit window.
    pub fn elapsed(&self) -> Duration {
        match (self.first_byte_at, self.last_byte_at) {
            (Some(f), Some(l)) if l >= f => l - f,
            _ => Duration::ZERO,
        }
    }

    /// Wall-clock span from first post-omit byte to last byte.
    pub fn measured_elapsed(&self) -> Duration {
        match (self.first_measured_at, self.last_byte_at) {
            (Some(f), Some(l)) if l >= f => l - f,
            _ => Duration::ZERO,
        }
    }
}

/// Default read timeout applied to the control channel during the
/// handshake phases (before and after the data-transfer window).
/// Generous enough for slow networks, tight enough that a vanished peer
/// unblocks the server within half a minute.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Peer closed the control channel without fully participating in the
/// post-test control-channel handshake. iperf3 3.21 TCP clients do this
/// routinely after sending TEST_END.
fn is_peer_closed(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::BrokenPipe
    )
}

/// Entry point invoked from `main` when `-s` is given. Binds the
/// configured address, then loops forever accepting sessions (unless
/// `--one-off` was passed, in which case it exits after the first test).
pub fn run_server(config: Config) {
    // Configure auth before entering the accept loop so every session sees it.
    if config.rsa_private_key.is_some() {
        set_auth_config(config.rsa_private_key.clone(), config.authorized_users.clone());
    }

    let bind_addr = config.host_port();
    let listener = match TcpListener::bind(&bind_addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("failed to bind {}: {:?}", bind_addr, e);
            return;
        }
    };
    println!("-----------------------------------------------------------");
    println!("Server listening on {}", config.port);
    println!("-----------------------------------------------------------");

    if let Err(e) = run_server_loop(listener, &config, Some(DEFAULT_HANDSHAKE_TIMEOUT)) {
        eprintln!("server session ended with error: {:?}", e);
    }
}

/// Drive a full session against a pre-bound `TcpListener`. Returns the
/// total number of bytes received across all data streams. Broken out
/// from `run_server` so integration tests (and callers that want to
/// grab an ephemeral port with `127.0.0.1:0`) can bind first and hand
/// the listener in.
pub fn run_server_on(listener: TcpListener) -> io::Result<u64> {
    run_server_on_timeout(listener, Some(DEFAULT_HANDSHAKE_TIMEOUT))
}

/// Like `run_server_on` but lets callers override the handshake
/// timeout. Passing `None` disables timeouts (the legacy
/// hang-indefinitely-on-silent-peer behavior). Primarily useful for
/// integration tests that want to provoke a fast-failing timeout.
pub fn run_server_on_timeout(
    listener: TcpListener,
    handshake_timeout: Option<Duration>,
) -> io::Result<u64> {
    serve_one_session(&listener, handshake_timeout)
}

/// Loop forever accepting sessions (or just once if `config.one_off`).
///
/// When `max_concurrent > 1` the server enters concurrent mode: a single
/// accept loop demuxes connections by cookie and dispatches each session
/// onto its own thread. In that mode `one_off` is ignored — use
/// `--max-concurrent 1` together with `--one-off` for the one-shot path.
///
/// UDP is supported in concurrent mode via an rPerf3 extension: each session
/// gets its own ephemeral UDP socket, and its port is communicated to the
/// client via `SetDataPort` on the control channel. iperf3 cross-interop in
/// concurrent UDP mode is not supported.
pub fn run_server_loop(
    listener: TcpListener,
    config: &Config,
    handshake_timeout: Option<Duration>,
) -> io::Result<()> {
    if config.max_concurrent > 1 {
        return run_concurrent_accept_loop(listener, handshake_timeout, config.max_concurrent);
    }
    loop {
        match serve_one_session(&listener, handshake_timeout) {
            Ok(_) => {}
            Err(e) => eprintln!("session ended with error: {:?}", e),
        }
        if config.one_off {
            return Ok(());
        }
    }
}

/// Accept loop for `max_concurrent > 1`. A single thread calls
/// `listener.accept()` in a loop, reads the cookie from each new
/// connection, then either:
///
/// * Pushes the connection onto an existing session's data channel
///   (cookie matches a live session), or
/// * Creates a new session and spawns a thread to run it (new cookie,
///   registry not full), or
/// * Sends `AccessDenied` and closes the connection (registry full).
///
/// UDP sessions are now supported in concurrent mode: each session binds its
/// own ephemeral UDP socket and communicates the port to the client via
/// `SetDataPort`. This is an rPerf3-only extension; iperf3 interop in
/// concurrent UDP mode is not supported.
fn run_concurrent_accept_loop(
    listener: TcpListener,
    handshake_timeout: Option<Duration>,
    max_concurrent: u32,
) -> io::Result<()> {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    let registry: Arc<
        Mutex<HashMap<[u8; crate::common::cookie::COOKIE_LEN], crate::common::session::SessionHandle>>,
    > = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let (sock, _addr) = listener.accept()?;
        let mut tcp = tcp_protocol(sock);
        tcp.transfer.set_read_timeout(handshake_timeout)?;
        let cookie = match recv_cookie(tcp.transfer.as_mut()) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("cookie read failed: {:?}", e);
                continue;
            }
        };

        let mut reg = registry.lock().unwrap();
        if let Some(handle) = reg.get(&cookie) {
            if handle.data_tx.send(tcp).is_err() {
                eprintln!(
                    "session channel closed; dropping stream for cookie {:?}",
                    &cookie[..8]
                );
            }
        } else if reg.len() >= max_concurrent as usize {
            drop(reg);
            let _ = send_control_byte(tcp.transfer.as_mut(), Message::AccessDenied);
        } else {
            let (session, handle) =
                crate::common::session::Session::new(cookie, tcp);
            reg.insert(cookie, handle);
            drop(reg);
            let registry_cleanup = registry.clone();
            std::thread::spawn(move || {
                let _ = serve_session_from_channel(session, handshake_timeout);
                registry_cleanup.lock().unwrap().remove(&cookie);
            });
        }
    }
}

/// Run one session whose control connection and data streams arrive via
/// the concurrent accept loop. The control `Protocol` and data-stream
/// `Receiver` are bundled in `session`.
///
/// UDP sessions in concurrent mode are supported via an rPerf3 extension:
/// the server binds an ephemeral UDP port, sends its number to the client
/// via `SetDataPort` + u16-be, then runs the normal UDP branch on that
/// socket. iperf3 cross-interop in concurrent UDP mode is not supported.
fn serve_session_from_channel(
    mut session: crate::common::session::Session,
    handshake_timeout: Option<Duration>,
) -> io::Result<u64> {
    let cpu_start = cpu::sample();
    let opts = negotiate_options(&mut session.control)?;
    check_auth(&mut session.control, &opts)?;

    if opts.udp {
        // Bind an ephemeral UDP socket for this session so multiple
        // concurrent sessions don't fight over the same port.
        let udp = bind_udp("0.0.0.0:0", handshake_timeout)?;
        let data_port = udp.local_addr()?.port();

        // Tell the client which port to send data to.
        send_control_byte(session.control.transfer.as_mut(), Message::SetDataPort)?;
        send_u16_be(session.control.transfer.as_mut(), data_port)?;

        // Now run the normal UDP branch against our ephemeral socket.
        send_control_byte(session.control.transfer.as_mut(), Message::CreateStreams)?;
        let addrs = accept_udp_streams(&udp, &session.cookie, opts.parallel)?;
        udp.set_read_timeout(None)?;

        send_test_start_running(&mut session.control)?;
        println!("{}", crate::common::stream::INTERVAL_HEADER);

        let run_timeout =
            handshake_timeout.map(|h| h + Duration::from_secs((opts.time + opts.omit) as u64));
        session.control.transfer.set_read_timeout(run_timeout)?;

        let omit_window = Duration::from_secs(opts.omit as u64);
        let receipts = if opts.bidirectional {
            let send_socket = udp.try_clone()?;
            let recv_socket = udp;
            let stop = Arc::new(AtomicBool::new(false));
            let receiver_stop = stop.clone();
            let recv_addrs = addrs.clone();
            let recv_handle = std::thread::spawn(move || {
                run_udp_receiver(recv_socket, recv_addrs, omit_window, receiver_stop)
            });
            let mut send_receipts = run_udp_send_streams(send_socket, addrs, &opts);
            let _ = wait_for_test_end(&mut session.control);
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            let mut recv_receipts = recv_handle.join().unwrap_or_default();
            send_receipts.append(&mut recv_receipts);
            send_receipts
        } else if opts.reverse {
            let r = run_udp_send_streams(udp, addrs, &opts);
            let _ = wait_for_test_end(&mut session.control);
            r
        } else {
            let stop = Arc::new(AtomicBool::new(false));
            let receiver_stop = stop.clone();
            let handle = std::thread::spawn(move || {
                run_udp_receiver(udp, addrs, omit_window, receiver_stop)
            });
            wait_for_test_end(&mut session.control)?;
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            handle.join().unwrap_or_default()
        };
        if opts.reverse {
            let _ = wait_for_test_end(&mut session.control);
        }

        let total_bytes: u64 = receipts.iter().map(|r| r.bytes).sum();
        let measured_bytes: u64 = receipts.iter().map(|r| r.bytes_measured()).sum();
        let raw = measured_duration(&receipts);
        let steady = measured_steady_state(&receipts);

        session.control.transfer.set_read_timeout(handshake_timeout)?;
        let wall = if !steady.is_zero() {
            steady
        } else if !raw.is_zero() {
            raw
        } else {
            Duration::ZERO
        };
        let cpu_end = cpu::sample();
        let cpu_usage = cpu::usage(&cpu_start, &cpu_end, wall);

        if let Err(e) = exchange_results(&mut session.control, &receipts, &cpu_usage) {
            if !is_peer_closed(&e) {
                return Err(e);
            }
        }
        if let Err(e) = finalize_test(&mut session.control) {
            if !is_peer_closed(&e) {
                return Err(e);
            }
        }

        let (summary_bytes, summary_duration) = if opts.omit > 0 && !steady.is_zero() {
            (measured_bytes, steady)
        } else if !raw.is_zero() {
            (total_bytes, raw)
        } else {
            (total_bytes, Duration::from_secs(opts.time as u64))
        };

        println!("{}", crate::common::stream::SUMMARY_SEPARATOR);
        println!("{}", crate::common::stream::INTERVAL_HEADER);
        println!(
            "{}  receiver",
            crate::common::stream::prefix_title(crate::common::stream::format_interval_row(
                1,
                0.0,
                summary_duration.as_secs_f64(),
                summary_bytes
            )),
        );
        println!("rPerf3 Done.");
        return Ok(total_bytes);
    }

    // TCP path: tell the client to open data streams, then pull them
    // from the channel (the accept loop reads the cookies and routes
    // each data connection here).
    send_control_byte(session.control.transfer.as_mut(), Message::CreateStreams)?;
    let streams = crate::common::session::accept_streams_from_channel(
        &session.data_rx,
        opts.parallel,
        handshake_timeout,
    )?;
    // Apply socket tuning the client negotiated.
    let tuning = TuningOpts {
        window_size: opts.window_size,
        mss: opts.mss,
        congestion: opts.congestion.clone(),
        tos: opts.tos,
    };
    for s in &streams {
        let _ = s.transfer.apply_tuning(&tuning);
    }
    send_test_start_running(&mut session.control)?;
    println!("{}", crate::common::stream::INTERVAL_HEADER);

    let run_timeout =
        handshake_timeout.map(|h| h + Duration::from_secs((opts.time + opts.omit) as u64));
    session.control.transfer.set_read_timeout(run_timeout)?;

    let omit_window = Duration::from_secs(opts.omit as u64);
    let receipts = if opts.reverse {
        let r = run_tcp_send_streams(streams, &opts);
        let _ = wait_for_test_end(&mut session.control);
        r
    } else if opts.bidirectional {
        let mut send_protos = Vec::with_capacity(streams.len());
        let mut recv_protos = Vec::with_capacity(streams.len());
        for proto in streams {
            let cloned = proto.transfer.try_clone_tcp()?;
            send_protos.push(Protocol { transfer: cloned });
            recv_protos.push(proto);
        }
        let send_handle = std::thread::spawn({
            let opts = opts.clone();
            move || run_tcp_send_streams(send_protos, &opts)
        });
        let handles = spawn_stream_readers(recv_protos, omit_window);
        wait_for_test_end(&mut session.control)?;
        let mut receipts = join_stream_totals(handles);
        receipts.extend(send_handle.join().unwrap_or_default());
        receipts
    } else {
        let handles = spawn_stream_readers(streams, omit_window);
        wait_for_test_end(&mut session.control)?;
        join_stream_totals(handles)
    };

    let total_bytes: u64 = receipts.iter().map(|r| r.bytes).sum();
    let measured_bytes: u64 = receipts.iter().map(|r| r.bytes_measured()).sum();
    let raw = measured_duration(&receipts);
    let steady = measured_steady_state(&receipts);

    session
        .control
        .transfer
        .set_read_timeout(handshake_timeout)?;
    let wall = if !steady.is_zero() {
        steady
    } else if !raw.is_zero() {
        raw
    } else {
        Duration::ZERO
    };
    let cpu_end = cpu::sample();
    let cpu_usage = cpu::usage(&cpu_start, &cpu_end, wall);

    if let Err(e) = exchange_results(&mut session.control, &receipts, &cpu_usage) {
        if !is_peer_closed(&e) {
            return Err(e);
        }
    }
    if let Err(e) = finalize_test(&mut session.control) {
        if !is_peer_closed(&e) {
            return Err(e);
        }
    }

    let (summary_bytes, summary_duration) = if opts.omit > 0 && !steady.is_zero() {
        (measured_bytes, steady)
    } else if !raw.is_zero() {
        (total_bytes, raw)
    } else {
        (total_bytes, Duration::from_secs(opts.time as u64))
    };

    println!("{}", crate::common::stream::SUMMARY_SEPARATOR);
    println!("{}", crate::common::stream::INTERVAL_HEADER);
    println!(
        "{}  receiver",
        crate::common::stream::prefix_title(crate::common::stream::format_interval_row(
            1,
            0.0,
            summary_duration.as_secs_f64(),
            summary_bytes
        )),
    );
    if cpu_usage.total_pct > 0.0 {
        println!(
            "CPU: {:.2}% total ({:.2}% user, {:.2}% system)",
            cpu_usage.total_pct, cpu_usage.user_pct, cpu_usage.system_pct,
        );
    }
    println!("rPerf3 Done.");
    Ok(total_bytes)
}

/// Drive a single test session end-to-end. Returns the total bytes
/// received across all data streams so callers (the binary's
/// `run_server`, integration tests) can surface it.
fn serve_one_session(listener: &TcpListener, handshake_timeout: Option<Duration>) -> io::Result<u64> {
    let (mut control, cookie) = accept_control(listener, handshake_timeout)?;
    let cpu_start = cpu::sample();
    let _ = cookie_display(&cookie);

    let opts = negotiate_options(&mut control)?;
    check_auth(&mut control, &opts)?;

    let receipts = if opts.udp {
        run_udp_branch(&mut control, listener, &cookie, &opts, handshake_timeout)?
    } else {
        run_tcp_branch(&mut control, listener, &cookie, &opts, handshake_timeout)?
    };

    let total_bytes: u64 = receipts.iter().map(|r| r.bytes).sum();
    let measured_bytes: u64 = receipts.iter().map(|r| r.bytes_measured()).sum();
    let raw = measured_duration(&receipts);
    let steady = measured_steady_state(&receipts);

    control.transfer.set_read_timeout(handshake_timeout)?;
    let wall = if !steady.is_zero() { steady } else if !raw.is_zero() { raw } else { Duration::ZERO };
    let cpu_end = cpu::sample();
    let cpu_usage = cpu::usage(&cpu_start, &cpu_end, wall);

    if let Err(e) = exchange_results(&mut control, &receipts, &cpu_usage) {
        if !is_peer_closed(&e) {
            return Err(e);
        }
    }
    if let Err(e) = finalize_test(&mut control) {
        if !is_peer_closed(&e) {
            return Err(e);
        }
    }

    let (summary_bytes, summary_duration) = if opts.omit > 0 && !steady.is_zero() {
        (measured_bytes, steady)
    } else if !raw.is_zero() {
        (total_bytes, raw)
    } else {
        (total_bytes, Duration::from_secs(opts.time as u64))
    };

    // iPerf3-style sender/receiver summary block.
    println!("{}", crate::common::stream::SUMMARY_SEPARATOR);
    println!("{}", crate::common::stream::INTERVAL_HEADER);
    println!(
        "{}  receiver",
        crate::common::stream::prefix_title(crate::common::stream::format_interval_row(
            1, 0.0, summary_duration.as_secs_f64(), summary_bytes,
        )),
    );
    if cpu_usage.total_pct > 0.0 {
        println!(
            "CPU: {:.2}% total ({:.2}% user, {:.2}% system)",
            cpu_usage.total_pct, cpu_usage.user_pct, cpu_usage.system_pct,
        );
    }
    println!("rPerf3 Done.");
    Ok(total_bytes)
}

fn run_tcp_branch(
    control: &mut Protocol,
    listener: &TcpListener,
    cookie: &[u8; COOKIE_LEN],
    opts: &ClientOptions,
    handshake_timeout: Option<Duration>,
) -> io::Result<Vec<StreamReceipt>> {
    let streams = accept_streams_via_listener(control, listener, cookie, opts.parallel, handshake_timeout)?;
    // Apply socket tuning options the client negotiated.
    let tuning = TuningOpts {
        window_size: opts.window_size,
        mss: opts.mss,
        congestion: opts.congestion.clone(),
        tos: opts.tos,
    };
    for s in &streams {
        let _ = s.transfer.apply_tuning(&tuning);
    }
    send_test_start_running(control)?;
    println!("{}", crate::common::stream::INTERVAL_HEADER);

    let run_timeout = handshake_timeout
        .map(|h| h + Duration::from_secs((opts.time + opts.omit) as u64));
    control.transfer.set_read_timeout(run_timeout)?;

    let omit_window = Duration::from_secs(opts.omit as u64);
    let receipts = if opts.bidirectional {
        // Split each stream into a send half and a receive half via
        // try_clone on the underlying TcpStream (full-duplex).
        let mut send_protos = Vec::with_capacity(streams.len());
        let mut recv_protos = Vec::with_capacity(streams.len());
        for proto in streams {
            let cloned = match proto.transfer.try_clone_tcp() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("bidir clone failed: {:?}", e);
                    return Err(e);
                }
            };
            send_protos.push(Protocol { transfer: cloned });
            recv_protos.push(proto);
        }
        let send_opts = opts.clone();
        let send_handle =
            std::thread::spawn(move || run_tcp_send_streams(send_protos, &send_opts));
        // Receive side drains inbound bytes concurrently.
        let handles = spawn_stream_readers(recv_protos, omit_window);
        wait_for_test_end(control)?;
        let mut receipts = join_stream_totals(handles);
        receipts.extend(send_handle.join().unwrap_or_default());
        receipts
    } else if opts.reverse {
        // Server is sender. Join all sender threads ourselves; the client
        // will send TestEnd when its receive duration elapses, so we still
        // wait_for_test_end on the control channel afterwards (non-blocking
        // on the reverse side — if it arrives first, great; if not, we
        // still see it after sending completes).
        let r = run_tcp_send_streams(streams, opts);
        // Best-effort: peek for TEST_END on control so finalize_test below
        // works. Ignored errors — client may have half-closed already.
        let _ = wait_for_test_end(control);
        r
    } else {
        let handles = spawn_stream_readers(streams, omit_window);
        wait_for_test_end(control)?;
        join_stream_totals(handles)
    };
    Ok(receipts)
}

fn run_tcp_send_streams(
    streams: Vec<Protocol>,
    opts: &ClientOptions,
) -> Vec<StreamReceipt> {
    use crate::common::stream::{build_payload, format_interval_row};
    use crate::common::timer::Timer;

    let duration = Duration::from_secs((opts.time + opts.omit) as u64);
    let omit = Duration::from_secs(opts.omit as u64);
    let len = opts.len as usize;
    let tuning = TuningOpts {
        window_size: opts.window_size,
        mss: opts.mss,
        congestion: opts.congestion.clone(),
        tos: opts.tos,
    };
    let max_bytes = opts.total_bytes;
    let max_blocks = opts.total_blocks;

    let handles: Vec<_> = streams
        .into_iter()
        .enumerate()
        .map(|(i, mut proto)| {
            let stream_id = (i + 1) as u32;
            let tuning = tuning.clone();
            std::thread::spawn(move || {
                let _ = proto.transfer.set_nonblocking(false);
                let _ = proto.transfer.apply_tuning(&tuning);
                let mut receipt = StreamReceipt::empty();
                let mut reporter = IntervalReporter::new(stream_id, Duration::from_secs(1));
                let timer = Timer::new();
                let buf = build_payload(len);
                while !timer.is_elapsed(duration) {
                    if let Some(mb) = max_bytes {
                        if receipt.bytes >= mb {
                            break;
                        }
                    }
                    if let Some(mb) = max_blocks {
                        if (receipt.bytes / len as u64) >= mb {
                            break;
                        }
                    }
                    match proto.transfer.send(&buf) {
                        Ok(n) if n > 0 => {
                            let now = Instant::now();
                            if receipt.first_byte_at.is_none() {
                                receipt.first_byte_at = Some(now);
                            }
                            receipt.last_byte_at = Some(now);
                            receipt.bytes += n as u64;
                            let first = receipt.first_byte_at.expect("set");
                            if now.duration_since(first) < omit {
                                receipt.bytes_omit += n as u64;
                            } else if receipt.first_measured_at.is_none() {
                                receipt.first_measured_at = Some(now);
                            }
                            if let Some(snap) = reporter.on_bytes(n as u64, now) {
                                println!(
                                    "{}",
                                    crate::common::stream::prefix_title(format_interval_row(
                                        snap.stream_id,
                                        snap.start_sec,
                                        snap.end_sec,
                                        snap.bytes,
                                    ))
                                );
                            }
                        }
                        Ok(_) => continue,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                        Err(_) => break,
                    }
                }
                receipt
            })
        })
        .collect();
    handles
        .into_iter()
        .map(|h| h.join().unwrap_or_else(|_| StreamReceipt::empty()))
        .collect()
}

fn run_udp_branch(
    control: &mut Protocol,
    listener: &TcpListener,
    cookie: &[u8; COOKIE_LEN],
    opts: &ClientOptions,
    handshake_timeout: Option<Duration>,
) -> io::Result<Vec<StreamReceipt>> {
    let local = listener.local_addr()?;
    let bind_str = format!("{}:{}", local.ip(), local.port());
    let udp = bind_udp(&bind_str, handshake_timeout)?;

    send_control_byte(control.transfer.as_mut(), Message::CreateStreams)?;
    let addrs = accept_udp_streams(&udp, cookie, opts.parallel)?;

    udp.set_read_timeout(None)?;

    send_test_start_running(control)?;
    println!("{}", crate::common::stream::INTERVAL_HEADER);

    let run_timeout = handshake_timeout
        .map(|h| h + Duration::from_secs((opts.time + opts.omit) as u64));
    control.transfer.set_read_timeout(run_timeout)?;

    let receipts = if opts.bidirectional {
        // Spawn both sender and receiver on cloned sockets.
        let send_socket = udp.try_clone()?;
        let recv_socket = udp;
        let stop = Arc::new(AtomicBool::new(false));
        let receiver_stop = stop.clone();
        let omit_window = Duration::from_secs(opts.omit as u64);
        let recv_addrs = addrs.clone();
        let recv_handle = std::thread::spawn(move || {
            run_udp_receiver(recv_socket, recv_addrs, omit_window, receiver_stop)
        });
        // Sender runs on this thread and returns its own receipts.
        let mut send_receipts = run_udp_send_streams(send_socket, addrs, opts);
        // Best-effort TestEnd; then stop the receiver.
        let _ = wait_for_test_end(control);
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let mut recv_receipts = recv_handle.join().unwrap_or_default();
        send_receipts.append(&mut recv_receipts);
        send_receipts
    } else if opts.reverse {
        run_udp_send_streams(udp, addrs, opts)
    } else {
        let stop = Arc::new(AtomicBool::new(false));
        let receiver_stop = stop.clone();
        let omit_window = Duration::from_secs(opts.omit as u64);
        let handle = std::thread::spawn(move || {
            run_udp_receiver(udp, addrs, omit_window, receiver_stop)
        });
        wait_for_test_end(control)?;
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        handle.join().unwrap_or_default()
    };
    // For reverse: best-effort read of client's TestEnd on control channel.
    if opts.reverse {
        let _ = wait_for_test_end(control);
    }
    Ok(receipts)
}

fn run_udp_send_streams(
    socket: std::net::UdpSocket,
    addrs: Vec<std::net::SocketAddr>,
    opts: &ClientOptions,
) -> Vec<StreamReceipt> {
    use crate::common::pacing::TokenBucket;
    use crate::common::stream::format_interval_row;
    use crate::common::timer::Timer;
    use crate::common::udp_header::{UdpHeader, UDP_HEADER_LEN};

    let duration = Duration::from_secs((opts.time + opts.omit) as u64);
    let omit = Duration::from_secs(opts.omit as u64);
    let len = (opts.len as usize).max(UDP_HEADER_LEN);
    let bandwidth = opts.bandwidth;

    let handles: Vec<_> = addrs
        .into_iter()
        .enumerate()
        .map(|(i, peer)| {
            let stream_id = (i + 1) as u32;
            let sock = socket.try_clone().expect("udp try_clone");
            std::thread::spawn(move || {
                let mut receipt = StreamReceipt::empty();
                let mut reporter = IntervalReporter::new(stream_id, Duration::from_secs(1));
                let timer = Timer::new();
                let mut bucket = TokenBucket::new(bandwidth, Instant::now());
                let mut seq: i64 = 0;
                let mut packet = vec![1u8; len];
                while !timer.is_elapsed(duration) {
                    let now = Instant::now();
                    if let Some(wait) = bucket.wait(now) {
                        std::thread::sleep(wait);
                        continue;
                    }
                    let epoch = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default();
                    let hdr = UdpHeader {
                        tv_sec: epoch.as_secs() as u32,
                        tv_usec: epoch.subsec_micros(),
                        seq,
                    };
                    if hdr.encode(&mut packet[..UDP_HEADER_LEN]).is_err() {
                        break;
                    }
                    match sock.send_to(&packet, peer) {
                        Ok(n) if n > 0 => {
                            bucket.record(n as u64);
                            let now = Instant::now();
                            if receipt.first_byte_at.is_none() {
                                receipt.first_byte_at = Some(now);
                            }
                            receipt.last_byte_at = Some(now);
                            receipt.bytes += n as u64;
                            receipt.packets += 1;
                            seq += 1;
                            let first = receipt.first_byte_at.expect("set");
                            if now.duration_since(first) < omit {
                                receipt.bytes_omit += n as u64;
                            } else if receipt.first_measured_at.is_none() {
                                receipt.first_measured_at = Some(now);
                            }
                            if let Some(snap) = reporter.on_bytes(n as u64, now) {
                                println!(
                                    "{}",
                                    crate::common::stream::prefix_title(format_interval_row(
                                        snap.stream_id,
                                        snap.start_sec,
                                        snap.end_sec,
                                        snap.bytes,
                                    ))
                                );
                            }
                        }
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }
                // Sentinel
                let epoch = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                let sentinel = UdpHeader {
                    tv_sec: epoch.as_secs() as u32,
                    tv_usec: epoch.subsec_micros(),
                    seq: -1,
                };
                let mut fin = [0u8; UDP_HEADER_LEN];
                if sentinel.encode(&mut fin).is_ok() {
                    let _ = sock.send_to(&fin, peer);
                }
                receipt
            })
        })
        .collect();
    handles
        .into_iter()
        .map(|h| h.join().unwrap_or_else(|_| StreamReceipt::empty()))
        .collect()
}

/// Send DisplayResults and block until the client signals it's done.
/// rPerf3 clients send IperfDone; iperf3 3.21 clients send ClientTerminate
/// (and close the socket) — both mean the same thing here.
pub fn finalize_test(control: &mut Protocol) -> io::Result<()> {
    send_control_byte(control.transfer.as_mut(), Message::DisplayResults)?;
    loop {
        match recv_control_byte(control.transfer.as_mut())? {
            Message::IperfDone | Message::ClientTerminate => return Ok(()),
            other => eprintln!("unexpected control byte while awaiting IperfDone: {:?}", other),
        }
    }
}

/// Produce a human-readable summary line. Retained for external callers
/// / legacy tests that compose their own `[SUMMARY]` prefix; the
/// interactive output uses `stream::format_interval_row` directly.
pub fn format_summary(total_bytes: u64, duration: std::time::Duration, streams: usize) -> String {
    let secs = duration.as_secs_f64().max(0.000_001);
    format!(
        "{} across {} stream(s) in {:.2}s ({})",
        crate::common::format::bytes(total_bytes),
        streams,
        secs,
        crate::common::format::bitrate(total_bytes, secs),
    )
}

/// Block on the control channel until the client sends `TestEnd`. Any
/// other control byte is unexpected here and gets logged but does not
/// abort (matches iPerf3's tolerance of extra frames).
pub fn wait_for_test_end(control: &mut Protocol) -> io::Result<()> {
    loop {
        match recv_control_byte(control.transfer.as_mut())? {
            Message::TestEnd => return Ok(()),
            other => eprintln!("unexpected control byte while awaiting TestEnd: {:?}", other),
        }
    }
}

/// Join every reader handle, returning one `StreamReceipt` per stream.
/// Panicked threads contribute an empty receipt.
pub fn join_stream_totals(
    handles: Vec<std::thread::JoinHandle<StreamReceipt>>,
) -> Vec<StreamReceipt> {
    handles
        .into_iter()
        .map(|h| h.join().unwrap_or_else(|_| StreamReceipt::empty()))
        .collect()
}

/// Duration spanned by the earliest `first_byte_at` to the latest
/// `last_byte_at` across every stream. This is the actual wall-clock
/// window data was flowing on the server side — the number to use for
/// throughput calculations instead of the client-advertised duration.
pub fn measured_duration(receipts: &[StreamReceipt]) -> Duration {
    let first = receipts.iter().filter_map(|r| r.first_byte_at).min();
    let last = receipts.iter().filter_map(|r| r.last_byte_at).max();
    match (first, last) {
        (Some(f), Some(l)) if l >= f => l - f,
        _ => Duration::ZERO,
    }
}

/// Duration of the steady-state measurement window: from the earliest
/// post-omit byte to the latest byte. Used for the Mbits/sec line when
/// `--omit` was requested.
pub fn measured_steady_state(receipts: &[StreamReceipt]) -> Duration {
    let first = receipts.iter().filter_map(|r| r.first_measured_at).min();
    let last = receipts.iter().filter_map(|r| r.last_byte_at).max();
    match (first, last) {
        (Some(f), Some(l)) if l >= f => l - f,
        _ => Duration::ZERO,
    }
}

/// Send ExchangeResults, immediately send our Results JSON, then read
/// the client's Results JSON.
///
/// iperf3 3.21 sends its server-side JSON *before* waiting for the
/// client to reciprocate — the client only sends its JSON after it has
/// received the ExchangeResults byte. If the server waits to read the
/// client JSON first (old behaviour) both sides block waiting for the
/// other: a classic deadlock. Sending ours first breaks the deadlock
/// because the client reads ExchangeResults, sends its JSON, then reads
/// ours — which is already in-flight.
///
/// The DisplayResults byte is appended immediately after the server JSON
/// so that iperf3 clients transition to their "display" state without
/// waiting for a separate control-byte round-trip.
///
/// iperf3 3.21 TCP clients may half-close the control channel before
/// sending their Results JSON, so we tolerate read failures gracefully.
pub fn exchange_results(
    control: &mut Protocol,
    receipts: &[StreamReceipt],
    cpu: &CpuUsage,
) -> io::Result<()> {
    send_control_byte(control.transfer.as_mut(), Message::ExchangeResults)?;

    // Send our results first so the client isn't blocked waiting for
    // them (iperf3 3.21 reads server JSON before sending client JSON).
    let server_results = build_server_results(receipts, cpu);
    let _ = send_framed_json(control.transfer.as_mut(), &server_results);

    // Now try to read the client's Results JSON (best-effort).
    let read_result: io::Result<Results> = recv_framed_json(control.transfer.as_mut());
    if let Err(ref e) = read_result {
        if !is_peer_closed(e) {
            return Err(io::Error::new(e.kind(), e.to_string()));
        }
    }
    Ok(())
}

/// Build the Results payload the server reports back. Per-stream bytes
/// come from the reader threads; UDP fields (jitter, lost, packets) are
/// populated from the receipt when available.
pub fn build_server_results(receipts: &[StreamReceipt], cpu: &CpuUsage) -> Results {
    let streams = receipts
        .iter()
        .enumerate()
        .map(|(i, r)| StreamResults {
            id: (i + 1) as u32,
            bytes: r.bytes,
            retransmits: 0,
            jitter: r.jitter_ms,
            errors: r.lost,
            packets: r.packets,
        })
        .collect();

    Results {
        cpu_util_total: cpu.total_pct,
        cpu_util_user: cpu.user_pct,
        cpu_util_system: cpu.system_pct,
        sender_has_retransmits: 0,
        streams,
    }
}

/// Spawn one thread per data stream, each draining its connection into
/// a byte counter. Returns the join handles so the caller can collect
/// per-stream totals after TestEnd. Each thread gets its own
/// IntervalReporter so per-stream rows print independently.
pub fn spawn_stream_readers(
    streams: Vec<Protocol>,
    omit: Duration,
) -> Vec<std::thread::JoinHandle<StreamReceipt>> {
    streams
        .into_iter()
        .enumerate()
        .map(|(i, mut protocol)| {
            let reporter = Some(IntervalReporter::new((i + 1) as u32, Duration::from_secs(1)));
            std::thread::spawn(move || recv_stream_bytes(&mut protocol, omit, reporter))
        })
        .collect()
}

/// Accept one TCP connection from `listener` and read the 37-byte cookie
/// the peer sends immediately after connecting. Returns the wrapped
/// `Protocol` along with the cookie bytes so a caller can match
/// subsequent data streams against it. The handshake timeout (if set)
/// is applied before the cookie read so a peer that connects and
/// never sends data cannot hang the server indefinitely.
pub fn accept_control(
    listener: &TcpListener,
    handshake_timeout: Option<Duration>,
) -> io::Result<(Protocol, [u8; COOKIE_LEN])> {
    let (stream, _addr) = listener.accept()?;
    let mut control = tcp_protocol(stream);
    control.transfer.set_read_timeout(handshake_timeout)?;
    let cookie = recv_cookie(control.transfer.as_mut())?;
    Ok((control, cookie))
}

/// Send `ParamExchange` to the client, then read the framed
/// `ClientOptions` JSON the client sends in reply.
pub fn negotiate_options(control: &mut Protocol) -> io::Result<ClientOptions> {
    send_control_byte(control.transfer.as_mut(), Message::ParamExchange)?;
    recv_framed_json::<ClientOptions>(control.transfer.as_mut())
}

/// Tell the client to open its data streams, then accept exactly `n`
/// additional connections on `listener` and verify each one sends the
/// same cookie as the control channel. Returns the accepted streams in
/// the order they arrived. The handshake timeout (if set) is applied
/// to the data socket while its cookie is read, then cleared so the
/// reader thread can block on the test workload without a spurious
/// timeout.
///
/// Used by the single-session path. For concurrent sessions use
/// `crate::common::session::accept_streams_from_channel` instead.
pub fn accept_streams_via_listener(
    control: &mut Protocol,
    listener: &TcpListener,
    expected_cookie: &[u8; COOKIE_LEN],
    n: u32,
    handshake_timeout: Option<Duration>,
) -> io::Result<Vec<Protocol>> {
    send_control_byte(control.transfer.as_mut(), Message::CreateStreams)?;

    let mut streams = Vec::with_capacity(n as usize);
    for i in 0..n {
        let (stream, _addr) = listener.accept()?;
        let mut data = tcp_protocol(stream);
        data.transfer.set_read_timeout(handshake_timeout)?;
        let got = recv_cookie(data.transfer.as_mut())?;
        if &got != expected_cookie {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("stream {} cookie mismatch", i),
            ));
        }
        // Clear the deadline: the data stream now blocks on the actual
        // test payload, which must not be artificially capped.
        data.transfer.set_read_timeout(None)?;
        streams.push(data);
    }
    Ok(streams)
}

/// Notify the client that the test is starting and then running. These
/// are two separate 1-byte control messages — matching iPerf3's
/// sequence and what `client::handle_message_client` already expects.
pub fn send_test_start_running(control: &mut Protocol) -> io::Result<()> {
    send_control_byte(control.transfer.as_mut(), Message::TestStart)?;
    send_control_byte(control.transfer.as_mut(), Message::TestRunning)?;
    Ok(())
}

/// Drain `protocol` into the bit bucket until the peer closes or an
/// error occurs. Records the timestamps of the first and last bytes so
/// the server can report real measured throughput. Bytes received
/// within `omit` of the first byte are attributed to the omit window
/// and excluded from the measurement totals.
pub fn recv_stream_bytes(
    protocol: &mut Protocol,
    omit: Duration,
    mut reporter: Option<IntervalReporter>,
) -> StreamReceipt {
    let mut buf = [0u8; crate::common::wire::DEFAULT_TCP_LEN];
    let mut receipt = StreamReceipt::empty();
    loop {
        match protocol.transfer.recv(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let now = Instant::now();
                if receipt.first_byte_at.is_none() {
                    receipt.first_byte_at = Some(now);
                }
                receipt.last_byte_at = Some(now);
                receipt.bytes += n as u64;

                let first = receipt.first_byte_at.expect("first_byte_at just set");
                let in_omit = now.duration_since(first) < omit;
                if in_omit {
                    receipt.bytes_omit += n as u64;
                } else if receipt.first_measured_at.is_none() {
                    receipt.first_measured_at = Some(now);
                }

                if let Some(r) = reporter.as_mut() {
                    if let Some(snap) = r.on_bytes(n as u64, now) {
                        println!(
                            "{}",
                            crate::common::stream::prefix_title(
                                crate::common::stream::format_interval_row(
                                    snap.stream_id,
                                    snap.start_sec,
                                    snap.end_sec,
                                    snap.bytes,
                                )
                            )
                        );
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }

    if let Some(mut r) = reporter {
        if let Some(snap) = receipt.last_byte_at.and_then(|t| r.flush(t)) {
            if snap.bytes > 0 {
                println!(
                    "{}",
                    crate::common::stream::prefix_title(
                        crate::common::stream::format_interval_row(
                            snap.stream_id,
                            snap.start_sec,
                            snap.end_sec,
                            snap.bytes,
                        )
                    )
                );
            }
        }
    }

    receipt
}

/// Wrap a blocking `TcpStream` in our `Protocol` abstraction. Kept
/// centralized so every accepted connection goes through the same
/// construction path (and so test code can reuse it).
pub fn tcp_protocol(stream: TcpStream) -> Protocol {
    Protocol {
        transfer: Box::new(Tcp::new(stream)),
    }
}

fn cookie_display(cookie: &[u8; COOKIE_LEN]) -> String {
    // The first 36 bytes are ASCII alphanumerics; the last is NUL.
    String::from_utf8_lossy(&cookie[..COOKIE_LEN - 1]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::cookie::generate_cookie;
    use crate::common::wire::{send_framed_json, DEFAULT_TCP_LEN};
    use std::io::Write;
    use std::net::TcpStream;
    use std::thread;

    /// Bind a `TcpListener` on an ephemeral loopback port and return it
    /// along with its concrete address so the test client can reach it.
    fn bind_loopback() -> (TcpListener, std::net::SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let addr = listener.local_addr().expect("local_addr");
        (listener, addr)
    }

    #[test]
    fn accepts_tcp_connection_and_reads_37_byte_cookie() {
        let (listener, addr) = bind_loopback();
        let cookie = generate_cookie();

        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).expect("connect");
            stream.write_all(&cookie).expect("send cookie");
            // Keep the connection open so the accept side doesn't race EOF.
            stream
        });

        let (_control, received) = accept_control(&listener, None).expect("accept");
        assert_eq!(received, cookie);

        drop(client.join().expect("client thread"));
    }

    #[test]
    fn negotiate_options_sends_param_exchange_then_parses_options() {
        let (listener, addr) = bind_loopback();
        let cookie = generate_cookie();
        let expected = ClientOptions::tcp_defaults(4, 2, DEFAULT_TCP_LEN as u32);

        let client_opts = expected.clone();
        let client = thread::spawn(move || {
            let stream = TcpStream::connect(addr).expect("connect");
            let mut proto = tcp_protocol(stream);

            // 1. Send cookie.
            proto
                .transfer
                .send(&cookie)
                .expect("client send cookie");

            // 2. Read the single ParamExchange byte.
            let mut byte = [0u8; 1];
            let n = proto.transfer.recv(&mut byte).expect("client recv byte");
            assert_eq!(n, 1);
            assert_eq!(byte[0], Message::ParamExchange as u8);

            // 3. Send options JSON back.
            send_framed_json(proto.transfer.as_mut(), &client_opts).expect("client send opts");
        });

        let (mut control, _cookie) = accept_control(&listener, None).expect("accept");
        let opts = negotiate_options(&mut control).expect("negotiate");
        assert_eq!(opts, expected);

        client.join().expect("client thread");
    }

    #[test]
    fn accept_streams_returns_n_protocols_with_matching_cookie() {
        let (listener, addr) = bind_loopback();
        let cookie = generate_cookie();
        let parallel: u32 = 3;

        // Client: opens 1 control + 3 data connections, all sending the same
        // cookie. Reads ParamExchange + CreateStreams to keep the control
        // channel drained.
        let client_cookie = cookie;
        let client = thread::spawn(move || {
            let mut ctrl = TcpStream::connect(addr).expect("ctrl connect");
            ctrl.write_all(&client_cookie).expect("ctrl cookie");

            // Drain ParamExchange from the server.
            let mut byte = [0u8; 1];
            std::io::Read::read_exact(&mut ctrl, &mut byte).expect("ctrl recv pe");
            assert_eq!(byte[0], Message::ParamExchange as u8);

            // Send options via the Socket helper around the stream.
            let mut ctrl_proto = tcp_protocol(ctrl);
            send_framed_json(
                ctrl_proto.transfer.as_mut(),
                &ClientOptions::tcp_defaults(1, parallel, DEFAULT_TCP_LEN as u32),
            )
            .expect("send opts");

            // Expect CreateStreams on the control channel.
            let mut byte = [0u8; 1];
            ctrl_proto.transfer.recv(&mut byte).expect("ctrl recv cs");
            assert_eq!(byte[0], Message::CreateStreams as u8);

            // Open N data streams, each with the same cookie. Hold them
            // until the server returns; _data_conns is intentionally
            // retained in-thread (Protocol is !Send, so it cannot be
            // returned from a thread closure).
            let mut _data_conns: Vec<TcpStream> = Vec::new();
            for _ in 0..parallel {
                let mut s = TcpStream::connect(addr).expect("data connect");
                s.write_all(&client_cookie).expect("data cookie");
                _data_conns.push(s);
            }

            // Keep the sockets alive until the test's assertions run.
            std::thread::sleep(std::time::Duration::from_millis(100));
        });

        let (mut control, got_cookie) = accept_control(&listener, None).expect("accept control");
        assert_eq!(got_cookie, cookie);

        let opts = negotiate_options(&mut control).expect("negotiate");
        assert_eq!(opts.parallel, parallel);

        let streams =
            accept_streams_via_listener(&mut control, &listener, &cookie, opts.parallel, None).expect("streams");
        assert_eq!(streams.len(), parallel as usize);

        client.join().expect("client thread");
    }

    #[test]
    fn accept_streams_rejects_mismatched_cookie() {
        let (listener, addr) = bind_loopback();
        let good = generate_cookie();
        let mut bad = good;
        bad[0] = if bad[0] == b'A' { b'B' } else { b'A' };

        let client_cookie = good;
        let bad_cookie = bad;
        let client = thread::spawn(move || {
            let mut ctrl = TcpStream::connect(addr).expect("ctrl connect");
            ctrl.write_all(&client_cookie).expect("ctrl cookie");

            let mut byte = [0u8; 1];
            std::io::Read::read_exact(&mut ctrl, &mut byte).expect("ctrl recv pe");

            let mut ctrl_proto = tcp_protocol(ctrl);
            send_framed_json(
                ctrl_proto.transfer.as_mut(),
                &ClientOptions::tcp_defaults(1, 1, DEFAULT_TCP_LEN as u32),
            )
            .expect("send opts");

            let mut byte = [0u8; 1];
            ctrl_proto.transfer.recv(&mut byte).expect("ctrl recv cs");

            // Data stream with the WRONG cookie.
            let mut s = TcpStream::connect(addr).expect("data connect");
            s.write_all(&bad_cookie).expect("data bad cookie");

            std::thread::sleep(std::time::Duration::from_millis(100));
        });

        let (mut control, _cookie) = accept_control(&listener, None).expect("accept control");
        let _ = negotiate_options(&mut control).expect("negotiate");

        let err = match accept_streams_via_listener(&mut control, &listener, &good, 1, None) {
            Ok(_) => panic!("expected cookie mismatch error"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let _ = client.join();
    }

    #[test]
    fn recv_stream_bytes_sums_until_peer_closes() {
        let (listener, addr) = bind_loopback();
        const CHUNKS: usize = 4;
        const CHUNK_SIZE: usize = 8192;
        let expected = (CHUNKS * CHUNK_SIZE) as u64;

        let writer = thread::spawn(move || {
            let mut s = TcpStream::connect(addr).expect("writer connect");
            let chunk = vec![0xABu8; CHUNK_SIZE];
            for _ in 0..CHUNKS {
                s.write_all(&chunk).expect("write chunk");
            }
            // Drop s -> EOF on the receiver.
        });

        let (stream, _addr) = listener.accept().expect("accept");
        let mut proto = tcp_protocol(stream);
        let receipt = recv_stream_bytes(&mut proto, Duration::ZERO, None);

        writer.join().expect("writer");
        assert_eq!(receipt.bytes, expected);
        assert!(receipt.first_byte_at.is_some(), "first byte timestamp should be set");
        assert!(receipt.last_byte_at.is_some(), "last byte timestamp should be set");
        // Elapsed must be non-negative and bounded above by a sanity ceiling.
        let elapsed = receipt.elapsed();
        assert!(elapsed < Duration::from_secs(5), "unexpectedly long: {:?}", elapsed);
    }

    #[test]
    fn recv_stream_bytes_is_zero_on_immediate_close() {
        let (listener, addr) = bind_loopback();

        let writer = thread::spawn(move || {
            let _ = TcpStream::connect(addr).expect("connect then drop");
            // immediate drop -> peer closes with no payload
        });

        let (stream, _addr) = listener.accept().expect("accept");
        let mut proto = tcp_protocol(stream);
        let receipt = recv_stream_bytes(&mut proto, Duration::ZERO, None);

        writer.join().expect("writer");
        assert_eq!(receipt.bytes, 0);
        assert!(receipt.first_byte_at.is_none());
        assert!(receipt.last_byte_at.is_none());
        assert_eq!(receipt.elapsed(), Duration::ZERO);
    }

    #[test]
    fn spawn_stream_readers_returns_handle_per_stream() {
        let (listener, addr) = bind_loopback();
        let n = 2;
        const BYTES_PER_STREAM: usize = 1024;

        // Two writer threads, each sending a fixed payload then closing.
        let writers: Vec<_> = (0..n)
            .map(|_| {
                thread::spawn(move || {
                    let mut s = TcpStream::connect(addr).expect("connect");
                    s.write_all(&vec![7u8; BYTES_PER_STREAM]).expect("write");
                })
            })
            .collect();

        let mut accepted = Vec::new();
        for _ in 0..n {
            let (stream, _) = listener.accept().expect("accept");
            accepted.push(tcp_protocol(stream));
        }

        let handles = spawn_stream_readers(accepted, Duration::ZERO);
        assert_eq!(handles.len(), n);
        let mut total: u64 = 0;
        for h in handles {
            total += h.join().unwrap().bytes;
        }
        assert_eq!(total, (n * BYTES_PER_STREAM) as u64);

        for w in writers {
            w.join().expect("writer");
        }
    }

    #[test]
    fn send_test_start_running_emits_two_bytes_in_order() {
        use crate::common::protocol::testing::MockSocket;

        let mock = MockSocket::new();
        let written = mock.written.clone();
        let mut control = Protocol {
            transfer: Box::new(mock),
        };

        send_test_start_running(&mut control).expect("send");
        let buf = written.lock().unwrap().clone();

        assert_eq!(buf, vec![Message::TestStart as u8, Message::TestRunning as u8]);
    }

    #[test]
    fn wait_for_test_end_returns_on_test_end_byte() {
        use crate::common::protocol::testing::MockSocket;

        let mock = MockSocket::new();
        mock.recv_queue
            .lock()
            .unwrap()
            .push(vec![Message::TestEnd as u8]);
        let mut control = Protocol {
            transfer: Box::new(mock),
        };

        wait_for_test_end(&mut control).expect("ok");
    }

    #[test]
    fn wait_for_test_end_skips_unexpected_bytes() {
        use crate::common::protocol::testing::MockSocket;

        let mock = MockSocket::new();
        mock.recv_queue
            .lock()
            .unwrap()
            .push(vec![Message::TestRunning as u8]);
        mock.recv_queue
            .lock()
            .unwrap()
            .push(vec![Message::TestEnd as u8]);
        let mut control = Protocol {
            transfer: Box::new(mock),
        };

        wait_for_test_end(&mut control).expect("ok");
    }

    fn receipt_with(
        bytes: u64,
        first: Option<Instant>,
        last: Option<Instant>,
    ) -> StreamReceipt {
        StreamReceipt {
            bytes,
            bytes_omit: 0,
            first_byte_at: first,
            first_measured_at: first,
            last_byte_at: last,
            jitter_ms: 0.0,
            lost: 0,
            ooo: 0,
            packets: 0,
        }
    }

    #[test]
    fn build_server_results_populates_one_stream_per_total() {
        let receipts = [receipt_with(1_000, None, None), receipt_with(2_500, None, None)];
        let r = build_server_results(&receipts, &CpuUsage::ZERO);
        assert_eq!(r.streams.len(), 2);
        assert_eq!(r.streams[0].id, 1);
        assert_eq!(r.streams[0].bytes, 1_000);
        assert_eq!(r.streams[1].id, 2);
        assert_eq!(r.streams[1].bytes, 2_500);
    }

    #[test]
    fn measured_duration_spans_earliest_first_to_latest_last() {
        let base = Instant::now();
        let r1 = receipt_with(10, Some(base), Some(base + Duration::from_millis(800)));
        let r2 = receipt_with(
            20,
            Some(base + Duration::from_millis(100)),
            Some(base + Duration::from_millis(1_000)),
        );

        assert_eq!(measured_duration(&[r1, r2]), Duration::from_millis(1_000));
    }

    #[test]
    fn recv_stream_bytes_attributes_early_bytes_to_omit() {
        let (listener, addr) = bind_loopback();

        let writer = thread::spawn(move || {
            let mut s = TcpStream::connect(addr).expect("writer connect");
            // Send some early bytes, sleep past the omit window, send more.
            s.write_all(&[0u8; 1024]).expect("early write");
            thread::sleep(Duration::from_millis(120));
            s.write_all(&[0u8; 2048]).expect("late write");
        });

        let (stream, _) = listener.accept().expect("accept");
        let mut proto = tcp_protocol(stream);
        let receipt = recv_stream_bytes(&mut proto, Duration::from_millis(80), None);

        writer.join().expect("writer");

        assert_eq!(receipt.bytes, 3072);
        assert!(receipt.bytes_omit > 0, "expected some bytes to land in omit window");
        assert!(
            receipt.bytes_measured() > 0,
            "expected some bytes to land in the measurement window"
        );
        assert!(receipt.first_measured_at.is_some());
    }

    #[test]
    fn measured_duration_is_zero_when_no_bytes_observed() {
        assert_eq!(
            measured_duration(&[StreamReceipt::empty(), StreamReceipt::empty()]),
            Duration::ZERO
        );
    }

    #[test]
    fn stream_receipt_elapsed_is_zero_without_bytes() {
        assert_eq!(StreamReceipt::empty().elapsed(), Duration::ZERO);
    }

    #[test]
    fn finalize_test_sends_display_results_then_waits_for_iperf_done() {
        use crate::common::protocol::testing::MockSocket;

        let mock = MockSocket::new();
        let written = mock.written.clone();
        mock.recv_queue
            .lock()
            .unwrap()
            .push(vec![Message::IperfDone as u8]);

        let mut control = Protocol {
            transfer: Box::new(mock),
        };

        finalize_test(&mut control).expect("ok");
        let buf = written.lock().unwrap().clone();
        assert_eq!(buf, vec![Message::DisplayResults as u8]);
    }

    #[test]
    fn finalize_test_tolerates_extra_bytes_before_iperf_done() {
        use crate::common::protocol::testing::MockSocket;

        let mock = MockSocket::new();
        mock.recv_queue
            .lock()
            .unwrap()
            .push(vec![Message::TestRunning as u8]);
        mock.recv_queue
            .lock()
            .unwrap()
            .push(vec![Message::IperfDone as u8]);

        let mut control = Protocol {
            transfer: Box::new(mock),
        };
        finalize_test(&mut control).expect("ok");
    }

    #[test]
    fn format_summary_contains_bytes_and_throughput() {
        let line = format_summary(10_000_000, std::time::Duration::from_secs(1), 1);
        // Human-readable output now: "9.54 MBytes across 1 stream(s) in 1.00s (80.00 Mbits/sec)".
        assert!(line.contains("MBytes"));
        assert!(line.contains("stream"));
        assert!(line.contains("bits/sec"));
    }

    #[test]
    fn format_summary_handles_zero_duration_without_panic() {
        // Just make sure we don't divide by zero.
        let _ = format_summary(1_000, std::time::Duration::from_secs(0), 1);
    }

    #[test]
    fn build_server_results_populates_udp_fields_from_receipts() {
        let r = StreamReceipt {
            bytes: 1000,
            bytes_omit: 0,
            first_byte_at: None,
            first_measured_at: None,
            last_byte_at: None,
            jitter_ms: 2.5,
            lost: 7,
            ooo: 1,
            packets: 50,
        };
        let results = build_server_results(&[r], &CpuUsage::ZERO);
        assert_eq!(results.streams[0].jitter, 2.5);
        assert_eq!(results.streams[0].errors, 7);
        assert_eq!(results.streams[0].packets, 50);
    }

    #[test]
    fn server_receipt_empty_zeros_udp_fields() {
        let r = StreamReceipt::empty();
        assert_eq!(r.jitter_ms, 0.0);
        assert_eq!(r.lost, 0);
        assert_eq!(r.ooo, 0);
        assert_eq!(r.packets, 0);
    }

    #[test]
    fn exchange_results_sends_server_results_with_totals() {
        use crate::common::protocol::testing::MockSocket;

        let mock = MockSocket::new();
        let written = mock.written.clone();

        // Seed the client-side Results the server expects to receive.
        let client_results = Results::empty();
        let client_bytes = serde_json::to_vec(&client_results).unwrap();
        let len_prefix = (client_bytes.len() as u32).to_be_bytes().to_vec();
        {
            let mut q = mock.recv_queue.lock().unwrap();
            q.push(len_prefix);
            q.push(client_bytes);
        }

        let mut control = Protocol {
            transfer: Box::new(mock),
        };
        let receipts = [
            receipt_with(4096, None, None),
            receipt_with(8192, None, None),
        ];
        exchange_results(&mut control, &receipts, &CpuUsage::ZERO).expect("exchange");

        let buf = written.lock().unwrap().clone();
        // First byte: ExchangeResults, then 4-byte BE length, then body.
        assert_eq!(buf[0], Message::ExchangeResults as u8);
        let body_len = u32::from_be_bytes(buf[1..5].try_into().unwrap()) as usize;
        let body = &buf[5..5 + body_len];
        let sent: Results = serde_json::from_slice(body).unwrap();
        assert_eq!(sent.streams.len(), 2);
        assert_eq!(sent.streams[0].bytes, 4096);
        assert_eq!(sent.streams[1].bytes, 8192);
    }
}
