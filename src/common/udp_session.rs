//! Server-side UDP session: bind one socket on the test port, read one
//! cookie-bearing datagram per expected stream, then demux incoming
//! datagrams by source address into per-stream receipts.

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::cookie::COOKIE_LEN;
use super::jitter;
use super::udp_header::{UdpHeader, UDP_HEADER_LEN};
use crate::server::StreamReceipt;

/// The 4-byte "stream-init" datagram that iperf3 3.x clients send to the
/// server's UDP port after the TCP `CreateStreams` control byte.  The
/// server must reply with `UDP_STREAM_ACK` to complete the handshake.
#[cfg(test)]
const UDP_STREAM_INIT: &[u8] = b"9876";

/// The 4-byte acknowledgment the server sends back to the client after
/// receiving `UDP_STREAM_INIT`.  This is what iperf3 3.x expects; without
/// it the client interprets the silence as a failure and aborts.
const UDP_STREAM_ACK: &[u8] = b"6789";

pub fn bind_udp(addr: &str, handshake_timeout: Option<Duration>) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(addr)?;
    socket.set_read_timeout(handshake_timeout)?;
    Ok(socket)
}

/// Wait for `n` UDP "stream init" datagrams and register each sender's
/// address as a stream.
///
/// # iperf3 wire protocol
///
/// When using iperf3 3.x as the client, the client sends a 4-byte
/// `b"9876"` datagram to the server's UDP port after receiving the
/// `CreateStreams` control byte on the TCP channel.  The server must
/// reply with `b"6789"` to that same source address; without this reply
/// the client considers stream setup to have failed and immediately
/// terminates the test.
///
/// When using rPerf3 as the client, the client sends the 37-byte session
/// cookie instead.  Both formats are accepted here: any datagram whose
/// source address has not been seen before is treated as a stream-init
/// and acknowledged with `b"6789"`.
pub fn accept_udp_streams(
    socket: &UdpSocket,
    _expected_cookie: &[u8; COOKIE_LEN],
    n: u32,
) -> io::Result<Vec<SocketAddr>> {
    let mut addrs = Vec::with_capacity(n as usize);
    let mut buf = [0u8; 65_536];
    for _ in 0..n {
        let (_len, src) = socket.recv_from(&mut buf)?;
        // Reply with the iperf3 stream-init acknowledgment.  rPerf3 clients
        // ignore this extra datagram; iperf3 clients require it to proceed.
        let _ = socket.send_to(UDP_STREAM_ACK, src);
        addrs.push(src);
    }
    Ok(addrs)
}

struct StreamState {
    receipt: StreamReceipt,
    max_seq: i64,
    last_transit_ms: Option<f64>,
    saw_sentinel: bool,
}

impl StreamState {
    fn new() -> Self {
        Self {
            receipt: StreamReceipt::empty(),
            max_seq: -1,
            last_transit_ms: None,
            saw_sentinel: false,
        }
    }
}

pub fn run_udp_receiver(
    socket: UdpSocket,
    stream_order: Vec<SocketAddr>,
    omit: Duration,
    stop_flag: Arc<AtomicBool>,
) -> Vec<StreamReceipt> {
    let _ = socket.set_read_timeout(Some(Duration::from_millis(100)));

    let mut states: HashMap<SocketAddr, StreamState> = stream_order
        .iter()
        .map(|a| (*a, StreamState::new()))
        .collect();
    let mut buf = [0u8; 65_536];

    // Wall-clock deadline set the first time stop_flag is observed.  Once
    // the deadline passes we break unconditionally, even if packets keep
    // arriving and the sentinel was never received (e.g. dropped on an
    // unreliable link).
    let mut grace_deadline: Option<Instant> = None;
    // Guard to avoid repeated set_read_timeout syscalls on every iteration.
    let mut short_timeout_set = false;

    loop {
        if stop_flag.load(Ordering::Relaxed) {
            let deadline = *grace_deadline.get_or_insert_with(|| {
                Instant::now() + Duration::from_millis(500)
            });

            // Reduce the read timeout once (at the stop transition) so that
            // a steady stream of non-sentinel packets wakes up quickly enough
            // to check the wall-clock deadline.
            if !short_timeout_set {
                let _ = socket.set_read_timeout(Some(Duration::from_millis(50)));
                short_timeout_set = true;
            }

            if states.values().all(|s| s.saw_sentinel) || Instant::now() >= deadline {
                break;
            }
        }

        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                if len < UDP_HEADER_LEN {
                    continue;
                }
                let Some(state) = states.get_mut(&src) else {
                    continue;
                };
                let hdr = match UdpHeader::decode(&buf[..UDP_HEADER_LEN]) {
                    Ok(h) => h,
                    Err(_) => continue,
                };
                let now = Instant::now();

                if hdr.is_sentinel() {
                    state.saw_sentinel = true;
                    continue;
                }

                if state.receipt.first_byte_at.is_none() {
                    state.receipt.first_byte_at = Some(now);
                }
                state.receipt.last_byte_at = Some(now);
                state.receipt.bytes += len as u64;
                state.receipt.packets += 1;

                let first = state.receipt.first_byte_at.unwrap();
                let in_omit = now.duration_since(first) < omit;
                if in_omit {
                    state.receipt.bytes_omit += len as u64;
                } else if state.receipt.first_measured_at.is_none() {
                    state.receipt.first_measured_at = Some(now);
                }

                if hdr.seq <= state.max_seq {
                    state.receipt.ooo += 1;
                } else {
                    if hdr.seq > state.max_seq + 1 {
                        let gap = (hdr.seq - state.max_seq - 1) as u64;
                        state.receipt.lost = state.receipt.lost.saturating_add(gap);
                    }
                    state.max_seq = hdr.seq;
                }

                let recv_ms = now
                    .duration_since(state.receipt.first_byte_at.unwrap())
                    .as_secs_f64()
                    * 1_000.0;
                let send_ms = (hdr.tv_sec as f64) * 1_000.0 + (hdr.tv_usec as f64) / 1_000.0;
                let transit = recv_ms - send_ms;
                if let Some(prev) = state.last_transit_ms {
                    let d = transit - prev;
                    state.receipt.jitter_ms = jitter::update(state.receipt.jitter_ms, d);
                }
                state.last_transit_ms = Some(transit);
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut =>
            {
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }
                continue;
            }
            Err(_) => break,
        }
    }

    stream_order
        .into_iter()
        .map(|addr| {
            states
                .remove(&addr)
                .map(|s| s.receipt)
                .unwrap_or_else(StreamReceipt::empty)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::cookie::generate_cookie;
    use std::thread;

    #[test]
    fn bind_udp_returns_socket_bound_to_addr() {
        let socket = bind_udp("127.0.0.1:0", None).expect("bind");
        assert!(socket.local_addr().is_ok());
    }

    /// Verify that accept_udp_streams accepts any datagram (rPerf3-style
    /// 37-byte cookie) and replies with the iperf3 acknowledgment `b"6789"`.
    #[test]
    fn accept_udp_streams_accepts_rperf_cookie_and_replies_ack() {
        let server = bind_udp("127.0.0.1:0", Some(Duration::from_secs(2))).expect("bind");
        let cookie = generate_cookie();
        let server_addr = server.local_addr().unwrap();

        let client = thread::spawn(move || {
            let sock = UdpSocket::bind("127.0.0.1:0").expect("client bind");
            sock.connect(server_addr).expect("client connect");
            sock.send(&cookie).expect("client send cookie");
            // Read back the ack the server should send.
            sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut buf = [0u8; 16];
            let n = sock.recv(&mut buf).expect("recv ack");
            (n, buf)
        });

        let addrs = accept_udp_streams(&server, &cookie, 1).expect("accept");
        assert_eq!(addrs.len(), 1);

        let (n, buf) = client.join().unwrap();
        assert_eq!(&buf[..n], UDP_STREAM_ACK, "server should reply with 6789");
    }

    /// Verify that accept_udp_streams also accepts the iperf3 3.x style
    /// 4-byte b"9876" init datagram and still replies with b"6789".
    #[test]
    fn accept_udp_streams_accepts_iperf3_init_and_replies_ack() {
        let server = bind_udp("127.0.0.1:0", Some(Duration::from_secs(2))).expect("bind");
        let cookie = generate_cookie();
        let server_addr = server.local_addr().unwrap();

        let client = thread::spawn(move || {
            let sock = UdpSocket::bind("127.0.0.1:0").expect("client bind");
            sock.connect(server_addr).expect("client connect");
            // Simulate iperf3 3.x: send 4-byte init instead of 37-byte cookie.
            sock.send(UDP_STREAM_INIT).expect("client send init");
            sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut buf = [0u8; 16];
            let n = sock.recv(&mut buf).expect("recv ack");
            (n, buf)
        });

        let addrs = accept_udp_streams(&server, &cookie, 1).expect("accept");
        assert_eq!(addrs.len(), 1);

        let (n, buf) = client.join().unwrap();
        assert_eq!(&buf[..n], UDP_STREAM_ACK, "server should reply with 6789 for iperf3 init");
    }

    /// Verify that `run_udp_receiver` terminates within the grace deadline
    /// even when the sender never sends a sentinel (simulating a dropped
    /// sentinel on an unreliable UDP link).  The test sets `stop_flag`
    /// before calling the receiver, sends 5 data packets, and asserts the
    /// call returns within 600 ms.
    #[test]
    fn run_udp_receiver_returns_within_grace_deadline_without_sentinel() {
        let server = bind_udp("127.0.0.1:0", Some(Duration::from_secs(3))).expect("bind");
        let cookie = generate_cookie();
        let server_addr = server.local_addr().unwrap();

        // Collect the sender address so we can register it as a stream.
        // We need the client socket to be bound before accept_udp_streams,
        // so we send the init datagram first.
        let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("client bind");
        client_sock.connect(server_addr).expect("client connect");
        let client_addr = client_sock.local_addr().unwrap();

        // Register the client address manually (bypassing accept_udp_streams)
        // by calling it in a thread so the handshake completes.
        let cookie2 = cookie;
        let sender = thread::spawn(move || {
            // Send the init datagram so accept_udp_streams is satisfied.
            client_sock.send(&cookie2).expect("send init");

            // Discard the ack (or ignore timeout).
            let mut ack_buf = [0u8; 16];
            let _ = client_sock.recv(&mut ack_buf);

            // Send 5 data packets with no sentinel.
            for seq in 0i64..5 {
                let mut buf = [0u8; 64];
                UdpHeader { tv_sec: 0, tv_usec: 0, seq }
                    .encode(&mut buf[..UDP_HEADER_LEN])
                    .unwrap();
                client_sock.send(&buf).expect("send data");
                thread::sleep(Duration::from_millis(5));
            }
            // No sentinel sent — the receiver must time out on the grace deadline.
            client_addr
        });

        let stream_addrs = accept_udp_streams(&server, &cookie, 1).expect("accept");
        assert_eq!(stream_addrs.len(), 1);

        // stop_flag already set: the receiver must honour the grace deadline.
        let stop = Arc::new(AtomicBool::new(true));
        let deadline = std::time::Instant::now() + Duration::from_millis(600);
        let receipts = run_udp_receiver(server, stream_addrs, Duration::ZERO, stop);

        assert!(
            std::time::Instant::now() <= deadline,
            "run_udp_receiver did not return within 600 ms grace deadline"
        );
        assert_eq!(receipts.len(), 1, "one stream registered");
        // We may have received some or all 5 packets before breaking.
        assert!(receipts[0].packets <= 5);

        let _ = sender.join();
    }

    #[test]
    fn run_udp_receiver_accounts_packets_and_stops_on_sentinel() {
        let server = bind_udp("127.0.0.1:0", Some(Duration::from_secs(3))).expect("bind");
        let cookie = generate_cookie();
        let server_addr = server.local_addr().unwrap();

        let sender = thread::spawn(move || {
            let sock = UdpSocket::bind("127.0.0.1:0").expect("client bind");
            sock.connect(server_addr).expect("client connect");
            sock.send(&cookie).expect("send cookie");

            for seq in 0i64..5 {
                let mut buf = [0u8; 64];
                UdpHeader { tv_sec: 0, tv_usec: 0, seq }
                    .encode(&mut buf[..UDP_HEADER_LEN])
                    .unwrap();
                sock.send(&buf).expect("send data");
                thread::sleep(Duration::from_millis(5));
            }
            let mut buf = [0u8; UDP_HEADER_LEN];
            UdpHeader { tv_sec: 0, tv_usec: 0, seq: -1 }.encode(&mut buf).unwrap();
            sock.send(&buf).expect("send sentinel");
        });

        let stream_addrs = accept_udp_streams(&server, &cookie, 1).expect("accept");
        assert_eq!(stream_addrs.len(), 1);

        let stop = Arc::new(AtomicBool::new(true));
        let receipts = run_udp_receiver(server, stream_addrs, Duration::ZERO, stop);
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].packets, 5);
        assert_eq!(receipts[0].bytes, 5 * 64);
        assert_eq!(receipts[0].lost, 0);
        assert_eq!(receipts[0].ooo, 0);

        let _ = sender.join();
    }
}
