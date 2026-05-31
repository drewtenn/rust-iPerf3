//! Serializable iPerf3 control-channel payloads and framing helpers.
//!
//! This module owns both the shape of the JSON blobs iPerf3 exchanges
//! (`ClientOptions`, `Results`) and the primitives used to push them
//! across a control socket: single-byte `Message` codes and
//! length-prefixed JSON bodies. Keeping them together lets both the
//! client and the server reach for the same helpers without touching
//! raw byte arithmetic.

use std::io;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::common::protocol::Socket;
use crate::common::Message;

/// The client_version field iPerf3 expects during ParamExchange. We claim
/// 3.1.3 for compatibility with the subset of the protocol we implement.
pub const CLIENT_VERSION: &str = "3.1.3";

/// Default bytes per write for TCP tests, matching iPerf3's default.
pub const DEFAULT_TCP_LEN: usize = 131_072;

/// Maximum accepted control-channel JSON frame size. Normal iPerf3
/// option/result payloads are tiny; this keeps a malicious peer from
/// forcing an unbounded allocation by advertising a huge frame length.
pub const MAX_JSON_FRAME_LEN: usize = 16 * 1024 * 1024;

/// Options sent during ParamExchange.
///
/// Field names are lowercase to match iPerf3's wire format.
///
/// `tcp` carries `#[serde(default)]` because iperf3 3.x omits the field
/// entirely when running in UDP mode — the absence of `tcp` implicitly
/// means `false` (i.e. it is a UDP test).  Without the default the
/// deserializer returns a "missing field" error and the handshake fails.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClientOptions {
    #[serde(default)]
    pub tcp: bool,
    pub omit: u32,
    pub time: u32,
    pub parallel: u32,
    pub len: u32,
    pub client_version: String,
    // Skip these on the wire when they're at their defaults. iperf3 3.21
    // alters its state machine when it sees unexpected fields, so TCP
    // mode must look like the legacy payload did.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub udp: bool,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub bandwidth: u64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reverse: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub bidirectional: bool,
    /// SO_SNDBUF / SO_RCVBUF size in bytes (-w). Only sent when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_size: Option<u32>,
    /// TCP_MAXSEG override (-M). Only sent when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mss: Option<u32>,
    /// TCP congestion algorithm name (-C). Only sent when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub congestion: Option<String>,
    /// IP_TOS value (-S). Only sent when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tos: Option<u8>,
    /// Terminate after this many bytes (-n). Only sent when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
    /// Terminate after this many blocks (-k). Only sent when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_blocks: Option<u64>,
    /// RSA-OAEP-SHA256 encrypted authtoken (base64). Only sent when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authtoken: Option<String>,
}

fn is_zero_u64(n: &u64) -> bool {
    *n == 0
}

impl ClientOptions {
    pub fn tcp_defaults(time_secs: u32, parallel: u32, len: u32) -> Self {
        Self {
            tcp: true,
            omit: 0,
            time: time_secs,
            parallel,
            len,
            client_version: CLIENT_VERSION.to_string(),
            udp: false,
            bandwidth: 0,
            reverse: false,
            bidirectional: false,
            window_size: None,
            mss: None,
            congestion: None,
            tos: None,
            total_bytes: None,
            total_blocks: None,
            authtoken: None,
        }
    }
}

/// Per-stream accounting reported at ExchangeResults time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StreamResults {
    pub id: u32,
    pub bytes: u64,
    pub retransmits: i64,
    pub jitter: f64,
    pub errors: u64,
    pub packets: u64,
}

/// Full results payload exchanged at the end of a test.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Results {
    pub cpu_util_total: f64,
    pub cpu_util_user: f64,
    pub cpu_util_system: f64,
    pub sender_has_retransmits: i32,
    pub streams: Vec<StreamResults>,
}

impl Results {
    pub fn empty() -> Self {
        Self {
            cpu_util_total: 0.0,
            cpu_util_user: 0.0,
            cpu_util_system: 0.0,
            sender_has_retransmits: 0,
            streams: Vec::new(),
        }
    }
}

/// Send a single-byte control Message. Mirrors iPerf3's 1-byte framing
/// for state-machine transitions on the control channel.
pub fn send_control_byte(sock: &mut dyn Socket, msg: Message) -> io::Result<()> {
    let byte: [u8; 1] = [msg as u8];
    write_all(sock, &byte)
}

/// Blocking-style read of a single-byte control Message. Callers that
/// need non-blocking polling should check `io::ErrorKind::WouldBlock`
/// from the returned error and retry.
pub fn recv_control_byte(sock: &mut dyn Socket) -> io::Result<Message> {
    let mut buf = [0u8; 1];
    read_exact(sock, &mut buf)?;
    Message::try_from(buf[0] as i8).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown control byte: {}", buf[0]),
        )
    })
}

/// Send a 2-byte big-endian unsigned integer. Used with `SetDataPort` to
/// communicate the server's ephemeral UDP port to the client.
pub fn send_u16_be(sock: &mut dyn Socket, value: u16) -> io::Result<()> {
    write_all(sock, &value.to_be_bytes())
}

/// Read a 2-byte big-endian unsigned integer. Pair of `send_u16_be`.
pub fn recv_u16_be(sock: &mut dyn Socket) -> io::Result<u16> {
    let mut buf = [0u8; 2];
    read_exact(sock, &mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

/// Serialize `value` to JSON and send it prefixed with a 4-byte
/// big-endian length.
pub fn send_framed_json<T: Serialize>(sock: &mut dyn Socket, value: &T) -> io::Result<()> {
    let body = serde_json::to_vec(value)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let len = u32::try_from(body.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "payload too large"))?;
    write_all(sock, &len.to_be_bytes())?;
    write_all(sock, &body)?;
    Ok(())
}

/// Read a 4-byte big-endian length, then exactly that many bytes, and
/// deserialize them as JSON into `T`. Reassembles short reads.
pub fn recv_framed_json<T: DeserializeOwned>(sock: &mut dyn Socket) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    read_exact(sock, &mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_JSON_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("JSON frame too large: {} bytes", len),
        ));
    }

    let mut body = vec![0u8; len];
    read_exact(sock, &mut body)?;

    serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Loop until `buf` is fully written. Mirrors `Write::write_all` but
/// works through the `Socket` trait (which only exposes a single
/// `send(&[u8])` call).
fn write_all(sock: &mut dyn Socket, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        match sock.send(buf)? {
            0 => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "socket returned 0-byte send",
                ));
            }
            n => buf = &buf[n..],
        }
    }
    Ok(())
}

/// Loop until `buf` is fully populated. Needed because a single
/// `recv` may short-read on TCP streams.
fn read_exact(sock: &mut dyn Socket, buf: &mut [u8]) -> io::Result<()> {
    let mut read = 0;
    while read < buf.len() {
        match sock.recv(&mut buf[read..])? {
            0 => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed mid-frame",
                ));
            }
            n => read += n,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_has_expected_fields() {
        let opts = ClientOptions::tcp_defaults(1, 1, DEFAULT_TCP_LEN as u32);
        let json = serde_json::to_string(&opts).expect("serialize options");

        for field in ["tcp", "omit", "time", "parallel", "len", "client_version"] {
            assert!(
                json.contains(&format!("\"{}\"", field)),
                "options JSON missing field {}: {}",
                field,
                json
            );
        }
    }

    #[test]
    fn options_roundtrip() {
        let opts = ClientOptions::tcp_defaults(5, 4, 65_536);
        let json = serde_json::to_string(&opts).unwrap();
        let back: ClientOptions = serde_json::from_str(&json).unwrap();
        assert_eq!(opts, back);
    }

    #[test]
    fn results_roundtrip() {
        let results = Results {
            cpu_util_total: 1.5,
            cpu_util_user: 0.7,
            cpu_util_system: 0.8,
            sender_has_retransmits: 1,
            streams: vec![StreamResults {
                id: 1,
                bytes: 552_730_624,
                retransmits: -1,
                jitter: 0.0,
                errors: 0,
                packets: 0,
            }],
        };

        let json = serde_json::to_string(&results).unwrap();
        let back: Results = serde_json::from_str(&json).unwrap();
        assert_eq!(results, back);
    }

    #[test]
    fn results_accepts_real_iperf3_payload() {
        // Shape observed from a real iPerf3 server reply.
        let raw = r#"{"cpu_util_total":0.5,"cpu_util_user":0.1,"cpu_util_system":0.4,
                      "sender_has_retransmits":0,
                      "streams":[{"id":1,"bytes":1024,"retransmits":0,
                                  "jitter":0.0,"errors":0,"packets":0}]}"#;
        let parsed: Results = serde_json::from_str(raw).expect("parse real payload");
        assert_eq!(parsed.streams.len(), 1);
        assert_eq!(parsed.streams[0].bytes, 1024);
    }

    // -------- framing helpers --------

    use crate::common::protocol::testing::MockSocket;

    /// Queue a sequence of recv responses on a MockSocket.
    fn seed_recv(mock: &MockSocket, chunks: Vec<Vec<u8>>) {
        let mut q = mock.recv_queue.lock().unwrap();
        *q = chunks;
    }

    #[test]
    fn send_control_byte_writes_single_byte() {
        let mut mock = MockSocket::new();
        let written = mock.written.clone();

        send_control_byte(&mut mock, Message::ParamExchange).unwrap();

        assert_eq!(&*written.lock().unwrap(), &[Message::ParamExchange as u8]);
    }

    #[test]
    fn recv_control_byte_parses_known_variant() {
        let mut mock = MockSocket::new();
        seed_recv(&mock, vec![vec![Message::TestStart as u8]]);

        let msg = recv_control_byte(&mut mock).unwrap();
        assert_eq!(msg, Message::TestStart);
    }

    #[test]
    fn recv_control_byte_errors_on_unknown_code() {
        let mut mock = MockSocket::new();
        seed_recv(&mock, vec![vec![0u8]]);

        let err = recv_control_byte(&mut mock).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn send_framed_json_prefixes_be_length() {
        let mut mock = MockSocket::new();
        let written = mock.written.clone();
        let opts = ClientOptions::tcp_defaults(3, 1, DEFAULT_TCP_LEN as u32);

        send_framed_json(&mut mock, &opts).unwrap();

        let buf = written.lock().unwrap().clone();
        assert!(buf.len() > 4, "should write length + body");

        let expected_body = serde_json::to_vec(&opts).unwrap();
        let len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;

        assert_eq!(len, expected_body.len(), "big-endian length prefix");
        assert_eq!(&buf[4..], &expected_body[..], "body follows length");
    }

    #[test]
    fn recv_framed_json_roundtrips_client_options() {
        let opts = ClientOptions::tcp_defaults(7, 2, 65_536);
        let body = serde_json::to_vec(&opts).unwrap();
        let len_bytes = (body.len() as u32).to_be_bytes().to_vec();

        let mut mock = MockSocket::new();
        seed_recv(&mock, vec![len_bytes, body]);

        let back: ClientOptions = recv_framed_json(&mut mock).unwrap();
        assert_eq!(back, opts);
    }

    #[test]
    fn recv_framed_json_reassembles_short_reads() {
        // Simulate TCP splitting: length prefix across two reads, body across three.
        let opts = ClientOptions::tcp_defaults(1, 1, 1024);
        let body = serde_json::to_vec(&opts).unwrap();
        let len_bytes = (body.len() as u32).to_be_bytes();

        let len_half_a = len_bytes[..2].to_vec();
        let len_half_b = len_bytes[2..].to_vec();
        let (b1, rest) = body.split_at(body.len() / 3);
        let (b2, b3) = rest.split_at(rest.len() / 2);

        let mut mock = MockSocket::new();
        seed_recv(
            &mock,
            vec![
                len_half_a,
                len_half_b,
                b1.to_vec(),
                b2.to_vec(),
                b3.to_vec(),
            ],
        );

        let back: ClientOptions = recv_framed_json(&mut mock).unwrap();
        assert_eq!(back, opts);
    }

    #[test]
    fn recv_framed_json_errors_on_truncated_body() {
        // Length says 64 bytes but we only deliver 4 then EOF (empty chunk).
        let mut mock = MockSocket::new();
        seed_recv(
            &mock,
            vec![64u32.to_be_bytes().to_vec(), vec![1, 2, 3, 4], Vec::new()],
        );

        let err: io::Error = recv_framed_json::<Results>(&mut mock).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn recv_framed_json_rejects_oversized_frame_before_body_read() {
        let mut mock = MockSocket::new();
        let oversized = (MAX_JSON_FRAME_LEN as u32 + 1).to_be_bytes().to_vec();
        seed_recv(&mock, vec![oversized]);

        let err: io::Error = recv_framed_json::<Results>(&mut mock).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            mock.recv_queue.lock().unwrap().len(),
            0,
            "only the length prefix should be consumed"
        );
    }

    #[test]
    fn options_defaults_udp_false_and_bandwidth_zero() {
        let opts = ClientOptions::tcp_defaults(1, 1, DEFAULT_TCP_LEN as u32);
        assert!(!opts.udp);
        assert_eq!(opts.bandwidth, 0);
    }

    #[test]
    fn options_udp_roundtrip() {
        let mut opts = ClientOptions::tcp_defaults(1, 1, DEFAULT_TCP_LEN as u32);
        opts.udp = true;
        opts.bandwidth = 1_000_000;

        let json = serde_json::to_string(&opts).unwrap();
        assert!(json.contains("\"udp\":true"));
        assert!(json.contains("\"bandwidth\":1000000"));

        let back: ClientOptions = serde_json::from_str(&json).unwrap();
        assert_eq!(back, opts);
    }

    #[test]
    fn options_parses_legacy_payload_without_udp_or_bandwidth() {
        let legacy = r#"{"tcp":true,"omit":0,"time":5,"parallel":1,"len":131072,"client_version":"3.1.3"}"#;
        let opts: ClientOptions = serde_json::from_str(legacy).expect("parse legacy");
        assert!(!opts.udp);
        assert_eq!(opts.bandwidth, 0);
    }

    /// Regression test: the exact JSON that iperf3 3.21 sends when invoked with
    /// `-u` (UDP mode).  The `tcp` field is absent — iperf3 3.x omits it for
    /// UDP tests — which used to cause a serde "missing field" error and close
    /// the control socket before the handshake completed.
    #[test]
    fn options_parses_iperf3_321_udp_payload() {
        let body = r#"{"udp":true,"omit":0,"time":1,"num":0,"blockcount":0,"parallel":1,"len":16332,"bandwidth":1000000,"pacing_timer":1000,"gso":0,"gso_dg_size":0,"gso_bf_size":65507,"gro":0,"gro_bf_size":65507,"client_version":"3.21"}"#;
        let opts: ClientOptions = serde_json::from_str(body).expect("should parse iperf3 3.21 UDP options");
        assert!(opts.udp, "udp should be true");
        assert!(!opts.tcp, "tcp should default to false when absent");
        assert_eq!(opts.time, 1);
        assert_eq!(opts.parallel, 1);
        assert_eq!(opts.bandwidth, 1_000_000);
        assert_eq!(opts.client_version, "3.21");
    }

    #[test]
    fn options_defaults_reverse_and_bidirectional_false() {
        let opts = ClientOptions::tcp_defaults(1, 1, DEFAULT_TCP_LEN as u32);
        assert!(!opts.reverse);
        assert!(!opts.bidirectional);
    }

    #[test]
    fn options_tcp_forward_does_not_emit_direction_fields() {
        let opts = ClientOptions::tcp_defaults(1, 1, DEFAULT_TCP_LEN as u32);
        let json = serde_json::to_string(&opts).unwrap();
        assert!(!json.contains("reverse"), "unexpected reverse key: {}", json);
        assert!(!json.contains("bidirectional"), "unexpected bidirectional key: {}", json);
    }

    #[test]
    fn options_reverse_roundtrip() {
        let mut opts = ClientOptions::tcp_defaults(1, 1, DEFAULT_TCP_LEN as u32);
        opts.reverse = true;
        let json = serde_json::to_string(&opts).unwrap();
        assert!(json.contains("\"reverse\":true"));
        let back: ClientOptions = serde_json::from_str(&json).unwrap();
        assert_eq!(back, opts);
    }

    #[test]
    fn options_bidirectional_roundtrip() {
        let mut opts = ClientOptions::tcp_defaults(1, 1, DEFAULT_TCP_LEN as u32);
        opts.bidirectional = true;
        let json = serde_json::to_string(&opts).unwrap();
        assert!(json.contains("\"bidirectional\":true"));
        let back: ClientOptions = serde_json::from_str(&json).unwrap();
        assert_eq!(back, opts);
    }
}
