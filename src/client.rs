use crate::common::auth;
use crate::common::cpu::{self, CpuUsage};
use crate::common::stream::{self, Stream};
use crate::common::test::{Config, Test};
use crate::common::wire::{
    self, recv_control_byte, recv_framed_json, recv_u16_be, send_control_byte, send_framed_json,
    ClientOptions, Results, StreamResults,
};
use crate::common::{connect, Message};

pub fn run_client(config: Config) {
    let mut test = Test::new(config);
    if !test.config.json {
        println!("Connecting to host {}, port {}", test.config.host, test.config.port);
    }
    let host_port = test.config.host_port();
    test.control_channel = connect(host_port, &test.cookie);
    test.cpu_start = Some(cpu::sample());

    client_loop(&mut test);
    if !test.config.json {
        println!("rPerf3 Done.");
    }
}

fn client_recv(test: &mut Test) -> bool {
    if let Some(protocol) = &mut test.control_channel {
        match recv_control_byte(protocol.transfer.as_mut()) {
            Ok(message) => return handle_message_client(test, message),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => eprintln!("control recv error: {:?}", e),
        }
    } else {
        return true;
    }
    false
}

fn client_loop(test: &mut Test) {
    // One TestEnd (on the control channel) is enough no matter how
    // many stream threads finish — iPerf3's state machine only expects
    // a single transition. Streams count themselves off here.
    let mut streams_finished: u32 = 0;
    let mut test_end_sent = false;

    loop {
        if client_recv(test) {
            break;
        }

        // Drain any finished-stream receipts as they arrive so they're
        // ready when ExchangeResults fires.
        test.drain_receipts();

        if let Ok(message) = test.rx_channel.try_recv() {
            match message {
                Message::TestEnd => {
                    streams_finished += 1;
                    let expected_streams = test.config.parallel.max(1)
                        * if test.config.direction.is_bidirectional() { 2 } else { 1 };
                    if streams_finished >= expected_streams && !test_end_sent {
                        if let Some(protocol) = test.control_channel.as_mut() {
                            log_send(
                                wire::send_control_byte(
                                    protocol.transfer.as_mut(),
                                    Message::TestEnd,
                                ),
                                "Test end sent.",
                                "TestEnd",
                            );
                            test_end_sent = true;
                        }
                    }
                }
                _ => eprintln!("Unknown message from stream thread: {:?}", message),
            }
        }
    }

    // Final drain to make sure nothing arrived between the last
    // try_recv and the loop-exiting control message.
    test.drain_receipts();
}

fn handle_message_client(test: &mut Test, message: Message) -> bool {
    let mut is_done = false;

    match message {
        Message::ParamExchange => {
            send_options(test);
        }

        Message::CreateStreams => {
            create_streams(test);
        }

        Message::TestStart => {
            test.is_started = true;
        }

        Message::TestRunning => {
            test.is_running = true;
            if !test.config.json {
                println!("{}", stream::INTERVAL_HEADER);
            }
        }

        Message::ExchangeResults => {
            exchange_results(test);
        }

        Message::DisplayResults => {
            send_iperf_done(test);
            is_done = true;
        }

        Message::IperfDone => {
            is_done = true;
        }

        Message::AccessDenied => {
            eprintln!("error: server rejected connection (access denied)");
            is_done = true;
        }

        Message::SetDataPort => {
            // rPerf3 extension: server tells us which ephemeral UDP port to
            // use for data streams in concurrent mode. Read the 2-byte
            // big-endian port that immediately follows this control byte.
            // The control socket is in non-blocking mode, so we briefly
            // switch to blocking to guarantee a complete 2-byte read.
            if let Some(protocol) = test.control_channel.as_mut() {
                let _ = protocol.transfer.set_nonblocking(false);
                let result = recv_u16_be(protocol.transfer.as_mut());
                let _ = protocol.transfer.set_nonblocking(true);
                match result {
                    Ok(port) => test.data_port_override = Some(port),
                    Err(e) => eprintln!("failed to read SetDataPort payload: {:?}", e),
                }
            }
        }

        _ => eprintln!("Received unknown control message."),
    }

    is_done
}

fn exchange_results(test: &mut Test) {
    // Make sure every finished-stream receipt is accounted for before
    // we build our Results payload.
    test.drain_receipts();
    let cpu_usage = match test.cpu_start {
        Some(start) => {
            let now = cpu::sample();
            let wall = client_session_duration(&test.receipts)
                .unwrap_or(std::time::Duration::ZERO);
            cpu::usage(&start, &now, wall)
        }
        None => CpuUsage::ZERO,
    };
    let client_results = build_client_results(&test.receipts, &cpu_usage);

    let steady = client_measured_duration(&test.receipts);
    let session = client_session_duration(&test.receipts).unwrap_or(std::time::Duration::ZERO);
    let (sender_bytes, sender_duration) = if test.config.omit > 0 && !steady.is_zero() {
        (
            test.receipts.iter().map(|r| r.bytes_measured()).sum::<u64>(),
            steady,
        )
    } else {
        (
            test.receipts.iter().map(|r| r.bytes_sent).sum::<u64>(),
            session,
        )
    };
    let sender_secs = sender_duration.as_secs_f64();
    let retransmits: u64 = test.receipts.iter().map(|r| r.retransmits as u64).sum();

    let dir = test.config.direction;

    // Text summary (suppressed when --json is active).
    if !test.config.json {
        let client_role = if dir.is_bidirectional() {
            "sender"
        } else if dir.is_reverse() {
            "receiver"
        } else {
            "sender"
        };

        println!("{}", stream::SUMMARY_SEPARATOR);
        println!("{}", stream::INTERVAL_HEADER);
        println!(
            "{}  {}",
            stream::prefix_title(stream::format_interval_row(1, 0.0, sender_secs, sender_bytes)),
            client_role,
        );
    }

    // Server-side receiver row comes from the exchanged Results payload.
    // We build it best-effort after actually reading the peer's results.
    let Some(ref mut protocol) = test.control_channel else {
        return;
    };

    if let Err(e) = send_framed_json(protocol.transfer.as_mut(), &client_results) {
        eprintln!("failed to send results: {:?}", e);
        return;
    }

    if let Err(e) = protocol.transfer.set_nonblocking(false) {
        eprintln!("failed to set blocking for results read: {:?}", e);
        return;
    }

    let server_result = recv_framed_json::<Results>(protocol.transfer.as_mut());

    if let Err(e) = protocol.transfer.set_nonblocking(true) {
        eprintln!("failed to restore non-blocking after results read: {:?}", e);
    }

    match server_result {
        Ok(server) => {
            let server_bytes = server.streams.iter().map(|s| s.bytes).sum::<u64>();

            if test.config.json {
                // Emit iperf3-compatible JSON summary instead of text table.
                use crate::common::json_output::{
                    render, JsonConnectingTo, JsonEnd, JsonOutput, JsonStart, JsonSum,
                    JsonTestStart,
                };
                let j = JsonOutput {
                    start: JsonStart {
                        connecting_to: Some(JsonConnectingTo {
                            host: test.config.host.clone(),
                            port: test.config.port,
                        }),
                        test_start: JsonTestStart {
                            protocol: if test.config.transport.is_udp() {
                                "UDP".into()
                            } else {
                                "TCP".into()
                            },
                            num_streams: test.config.parallel,
                            blksize: test.config.len,
                            duration: test.config.time,
                            reverse: u32::from(dir.is_reverse()),
                            bidir: u32::from(dir.is_bidirectional()),
                        },
                    },
                    end: JsonEnd {
                        sum_sent: JsonSum::new(sender_bytes, sender_secs),
                        sum_received: JsonSum::new(server_bytes, sender_secs),
                    },
                };
                println!("{}", render(&j));
            } else {
                let server_role = if dir.is_bidirectional() {
                    "receiver"
                } else if dir.is_reverse() {
                    "sender"
                } else {
                    "receiver"
                };
                println!(
                    "{}  {}",
                    stream::prefix_title(stream::format_interval_row(1, 0.0, sender_secs, server_bytes)),
                    server_role,
                );

                // Optional extras (text mode only).
                if retransmits > 0 {
                    println!("TCP retransmits: {}", retransmits);
                }
                if cpu_usage.total_pct > 0.0 {
                    println!(
                        "CPU: {:.2}% total ({:.2}% user, {:.2}% system)",
                        cpu_usage.total_pct, cpu_usage.user_pct, cpu_usage.system_pct,
                    );
                }
            }
        }
        Err(e) => eprintln!("could not receive/parse server results: {:?}", e),
    }
}

/// Build the client-side `Results` payload from the receipts each
/// stream thread returned. Per-stream bytes come straight from the
/// send loop's accumulator — nothing derived from the wall clock here,
/// so a slow or fast TCP stack gets attributed fairly.
pub fn build_client_results(
    receipts: &[crate::common::test::ClientStreamReceipt],
    cpu: &CpuUsage,
) -> Results {
    let any_retrans = receipts.iter().any(|r| r.retransmits > 0);
    let streams = receipts
        .iter()
        .map(|r| StreamResults {
            id: r.stream_id,
            bytes: r.bytes_sent,
            retransmits: r.retransmits as i64,
            jitter: r.jitter_ms,
            errors: r.lost,
            packets: r.packets,
        })
        .collect();

    Results {
        cpu_util_total: cpu.total_pct,
        cpu_util_user: cpu.user_pct,
        cpu_util_system: cpu.system_pct,
        sender_has_retransmits: if any_retrans { 1 } else { 0 },
        streams,
    }
}

/// Measured test duration on the client side: from the earliest
/// first-send across any stream to the latest last-send across any
/// stream. `None` if no stream saw any bytes.
pub fn client_session_duration(
    receipts: &[crate::common::test::ClientStreamReceipt],
) -> Option<std::time::Duration> {
    let first = receipts.iter().filter_map(|r| r.first_send_at).min()?;
    let last = receipts.iter().filter_map(|r| r.last_send_at).max()?;
    if last >= first {
        Some(last - first)
    } else {
        None
    }
}

/// Steady-state duration on the client side: from the earliest
/// first-measured-send (post-omit) to the latest last-send. Zero when
/// no post-omit bytes were observed.
pub fn client_measured_duration(
    receipts: &[crate::common::test::ClientStreamReceipt],
) -> std::time::Duration {
    let first = receipts.iter().filter_map(|r| r.first_measured_at).min();
    let last = receipts.iter().filter_map(|r| r.last_send_at).max();
    match (first, last) {
        (Some(f), Some(l)) if l >= f => l - f,
        _ => std::time::Duration::ZERO,
    }
}

fn create_streams(test: &Test) {
    // For UDP in concurrent mode the server may have assigned an ephemeral
    // port via SetDataPort. Use that if present, otherwise fall back to the
    // control-channel port (single-session / iperf3-compat path).
    let data_port = test
        .data_port_override
        .unwrap_or(test.config.port);
    let data_host = format!("{}:{}", test.config.host, data_port);
    let control_host = test.config.host_port();

    let n = test.config.parallel.max(1);
    let is_udp = test.config.transport.is_udp();
    let dir = test.config.direction;
    for stream_id in 1..=n {
        if dir.client_sends() {
            if is_udp {
                Stream::start_udp(test, data_host.clone(), test.cookie, stream_id);
            } else {
                Stream::start(test, control_host.clone(), test.cookie, stream_id);
            }
        }
        if dir.client_receives() {
            if is_udp {
                Stream::start_udp_recv(test, data_host.clone(), test.cookie, stream_id);
            } else {
                Stream::start_recv(test, control_host.clone(), test.cookie, stream_id);
            }
        }
    }
}

fn send_iperf_done(test: &mut Test) {
    if let Some(ref mut protocol) = test.control_channel {
        log_send(
            send_control_byte(protocol.transfer.as_mut(), Message::IperfDone),
            "iPerf done sent.",
            "IperfDone",
        );
    }
}

fn send_options(test: &mut Test) {
    let Some(ref mut protocol) = test.control_channel else {
        return;
    };

    let mut options =
        ClientOptions::tcp_defaults(test.config.time, test.config.parallel, test.config.len);
    options.omit = test.config.omit;
    options.udp = test.config.transport.is_udp();
    options.bandwidth = test.config.bandwidth;
    if options.udp {
        options.tcp = false;
    }
    options.reverse = test.config.direction.is_reverse();
    options.bidirectional = test.config.direction.is_bidirectional();
    options.window_size = test.config.window_size;
    options.mss = test.config.mss;
    options.congestion = test.config.congestion.clone();
    options.tos = test.config.tos;
    options.total_bytes = test.config.total_bytes;
    options.total_blocks = test.config.total_blocks;

    // Attach RSA authtoken when a public key and username are configured.
    if let (Some(pk_path), Some(user)) = (&test.config.rsa_public_key, &test.config.username) {
        match auth::load_public_key_pem(pk_path) {
            Ok(pubkey) => {
                let password = test.config.password.clone().unwrap_or_else(|| {
                    rpassword::prompt_password("Password: ").unwrap_or_default()
                });
                match auth::build_authtoken(&pubkey, user, &password) {
                    Ok(token) => options.authtoken = Some(token),
                    Err(e) => eprintln!("auth token build failed: {}", e),
                }
            }
            Err(e) => eprintln!("load pubkey failed: {}", e),
        }
    }

    if let Err(e) = send_framed_json(protocol.transfer.as_mut(), &options) {
        eprintln!("failed to send options: {:?}", e);
    }
}

fn log_send(result: std::io::Result<()>, _success: &str, what: &str) {
    if let Err(e) = result {
        eprintln!("failed to send {}: {:?}", what, e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::test::ClientStreamReceipt;
    use std::time::{Duration, Instant};

    fn client_receipt_with(
        stream_id: u32,
        bytes: u64,
        first: Option<Instant>,
        last: Option<Instant>,
    ) -> ClientStreamReceipt {
        ClientStreamReceipt {
            stream_id,
            bytes_sent: bytes,
            bytes_omit: 0,
            first_send_at: first,
            first_measured_at: first,
            last_send_at: last,
            retransmits: 0,
            jitter_ms: 0.0,
            lost: 0,
            ooo: 0,
            packets: 0,
        }
    }

    #[test]
    fn build_client_results_populates_one_stream_per_receipt() {
        let receipts = [
            client_receipt_with(1, 1_024, None, None),
            client_receipt_with(2, 4_096, None, None),
        ];

        let r = build_client_results(&receipts, &CpuUsage::ZERO);
        assert_eq!(r.streams.len(), 2);
        assert_eq!(r.streams[0].id, 1);
        assert_eq!(r.streams[0].bytes, 1_024);
        assert_eq!(r.streams[1].id, 2);
        assert_eq!(r.streams[1].bytes, 4_096);
    }

    #[test]
    fn build_client_results_is_empty_on_no_receipts() {
        let r = build_client_results(&[], &CpuUsage::ZERO);
        assert!(r.streams.is_empty());
    }

    #[test]
    fn client_recv_stops_when_control_channel_is_missing() {
        let mut test = Test::new(Config::with_host("127.0.0.1"));
        assert!(client_recv(&mut test));
    }

    #[test]
    fn client_session_duration_spans_earliest_to_latest() {
        let base = Instant::now();
        let receipts = [
            client_receipt_with(1, 10, Some(base), Some(base + Duration::from_millis(500))),
            client_receipt_with(
                2,
                20,
                Some(base + Duration::from_millis(100)),
                Some(base + Duration::from_millis(900)),
            ),
        ];
        assert_eq!(
            client_session_duration(&receipts),
            Some(Duration::from_millis(900))
        );
    }

    #[test]
    fn client_session_duration_is_none_when_no_bytes_sent() {
        let receipts = [
            ClientStreamReceipt::empty(1),
            ClientStreamReceipt::empty(2),
        ];
        assert_eq!(client_session_duration(&receipts), None);
    }

    #[test]
    fn client_measured_duration_uses_first_measured_at() {
        let base = Instant::now();
        // No post-omit bytes: returns zero.
        let unmeasured = ClientStreamReceipt::empty(1);
        assert_eq!(
            client_measured_duration(&[unmeasured]),
            Duration::ZERO
        );

        // With first_measured_at set, spans first_measured_at -> last.
        let mut r = ClientStreamReceipt::empty(2);
        r.bytes_sent = 100;
        r.first_send_at = Some(base);
        r.first_measured_at = Some(base + Duration::from_millis(200));
        r.last_send_at = Some(base + Duration::from_millis(800));
        assert_eq!(
            client_measured_duration(&[r]),
            Duration::from_millis(600)
        );
    }

    #[test]
    fn build_client_results_populates_udp_fields() {
        let mut r = ClientStreamReceipt::empty(1);
        r.bytes_sent = 2048;
        r.jitter_ms = 0.75;
        r.lost = 3;
        r.packets = 40;
        let out = build_client_results(&[r], &CpuUsage::ZERO);
        assert_eq!(out.streams[0].jitter, 0.75);
        assert_eq!(out.streams[0].errors, 3);
        assert_eq!(out.streams[0].packets, 40);
    }
}
