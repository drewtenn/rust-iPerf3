use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::cookie::COOKIE_LEN;
use super::cpu::CpuSnapshot;
use super::protocol::Protocol;
use super::stream::Stream;
use super::wire::DEFAULT_TCP_LEN;
use super::Message;
use crate::common::Direction;
use crate::common::TransportKind;

/// Per-stream bookkeeping the client's stream thread sends back to the
/// main loop on exit. Carries real bytes-sent, bytes-omitted, and
/// send-timestamp bounds so ExchangeResults can report actual measured
/// throughput rather than zeros.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ClientStreamReceipt {
	pub stream_id: u32,
	pub bytes_sent: u64,
	/// Bytes sent during the omit window at the start of the test.
	/// Included in `bytes_sent` — subtract to get measured bytes.
	pub bytes_omit: u64,
	pub first_send_at: Option<Instant>,
	/// First send that fell outside the omit window. `None` until the
	/// omit deadline passes (or if `omit == 0`, equals first_send_at).
	pub first_measured_at: Option<Instant>,
	pub last_send_at: Option<Instant>,
	/// TCP segment retransmissions observed on this stream (Linux
	/// only; zero on unsupported platforms).
	pub retransmits: u32,
	/// RFC 3550 jitter estimate for UDP streams (milliseconds). Zero for TCP.
	pub jitter_ms: f64,
	/// UDP datagrams lost during this stream (server-side count). Zero for TCP.
	pub lost: u64,
	/// UDP datagrams received out-of-order. Zero for TCP.
	pub ooo: u64,
	/// Total UDP datagrams sent by this stream. Zero for TCP.
	pub packets: u64,
}

impl ClientStreamReceipt {
	pub fn empty(stream_id: u32) -> Self {
		Self {
			stream_id,
			bytes_sent: 0,
			bytes_omit: 0,
			first_send_at: None,
			first_measured_at: None,
			last_send_at: None,
			retransmits: 0,
			jitter_ms: 0.0,
			lost: 0,
			ooo: 0,
			packets: 0,
		}
	}

	/// Bytes attributed to the measurement window (post-omit).
	pub fn bytes_measured(&self) -> u64 {
		self.bytes_sent.saturating_sub(self.bytes_omit)
	}

	/// Wall-clock duration between the first and last send, or zero if
	/// no bytes were ever written. Includes the omit window — use
	/// `measured_elapsed` for steady-state throughput.
	pub fn elapsed(&self) -> Duration {
		match (self.first_send_at, self.last_send_at) {
			(Some(f), Some(l)) if l >= f => l - f,
			_ => Duration::ZERO,
		}
	}

	/// Wall-clock span from first post-omit byte to last byte. Zero if
	/// nothing was measured.
	pub fn measured_elapsed(&self) -> Duration {
		match (self.first_measured_at, self.last_send_at) {
			(Some(f), Some(l)) if l >= f => l - f,
			_ => Duration::ZERO,
		}
	}
}

/// Runtime configuration for a single rPerf3 test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
	pub host: String,
	pub port: u16,
	pub time: u32,
	pub parallel: u32,
	pub len: u32,
	/// Seconds at the start of each stream whose bytes are excluded
	/// from the reported measurement window (skips TCP slow-start).
	pub omit: u32,
	pub transport: TransportKind,
	/// Sender-side bandwidth limit in bits per second. 0 = unlimited.
	/// Applies to UDP by default (matching iperf3) and to TCP when
	/// explicitly set via `-b`.
	pub bandwidth: u64,
	/// iperf3-compat: server exits after one test (default: loop forever).
	pub one_off: bool,
	/// Max simultaneous sessions the server will accept. `1` matches
	/// iperf3's default (one at a time, reject others with AccessDenied);
	/// `N > 1` is an rperf3 extension.
	pub max_concurrent: u32,
	pub direction: Direction,
	/// Emit iperf3-compatible JSON instead of text at end-of-test.
	pub json: bool,
	/// Force a specific format unit for text output (k, K, m, M, g, G). None = auto-scale.
	pub format_unit: Option<char>,
	/// Redirect all output to this file path.
	pub logfile: Option<std::path::PathBuf>,
	/// SO_SNDBUF / SO_RCVBUF in bytes (-w).
	pub window_size: Option<u32>,
	/// TCP_MAXSEG in bytes (-M). Linux-only; silently ignored elsewhere.
	pub mss: Option<u32>,
	/// TCP congestion algorithm name (-C). Linux-only; silently ignored elsewhere.
	pub congestion: Option<String>,
	/// IP_TOS value (-S).
	pub tos: Option<u8>,
	/// Zero-copy mode (-Z). Parsed stub — not yet implemented.
	pub zero_copy: bool,
	/// Terminate after this many bytes sent/received (-n).
	pub total_bytes: Option<u64>,
	/// Terminate after this many blocks (writes) sent/received (-k).
	pub total_blocks: Option<u64>,
	/// Title prefix for text output lines (-T).
	pub title: Option<String>,
	/// CPU affinity spec (-A). Linux-only; silently ignored elsewhere.
	pub affinity: Option<String>,
	/// Client: username for RSA authentication.
	pub username: Option<String>,
	/// Client: password for RSA authentication (prompt if None when public key is set).
	pub password: Option<String>,
	/// Client: path to the server's RSA public key PEM file.
	pub rsa_public_key: Option<std::path::PathBuf>,
	/// Server: path to the server's RSA private key PEM file.
	pub rsa_private_key: Option<std::path::PathBuf>,
	/// Server: path to the authorized users CSV file (user,sha256hex).
	pub authorized_users: Option<std::path::PathBuf>,
}

impl Config {
	/// iPerf3-matching defaults: TCP, 10s, one stream, 128 KiB writes.
	#[allow(dead_code)] // Convenience constructor used from tests/future call sites.
	pub fn with_host(host: impl Into<String>) -> Self {
		Self {
			host: host.into(),
			port: 5201,
			time: 10,
			parallel: 1,
			len: DEFAULT_TCP_LEN as u32,
			omit: 0,
			transport: TransportKind::Tcp,
			bandwidth: 0,
			one_off: false,
			max_concurrent: 1,
			direction: Direction::Forward,
			json: false,
			format_unit: None,
			logfile: None,
			window_size: None,
			mss: None,
			congestion: None,
			tos: None,
			zero_copy: false,
			total_bytes: None,
			total_blocks: None,
			title: None,
			affinity: None,
			username: None,
			password: None,
			rsa_public_key: None,
			rsa_private_key: None,
			authorized_users: None,
		}
	}

	pub fn host_port(&self) -> String {
		format!("{}:{}", self.host, self.port)
	}
}

pub struct Test {
	pub config: Config,
	/// Session cookie generated once at the start of a test and sent on
	/// both the control channel and every data stream. iPerf3 uses it
	/// to multiplex control and data onto one server port.
	pub cookie: [u8; COOKIE_LEN],
	pub control_channel: Option<Protocol>,
	// Placeholder for future parallel-stream bookkeeping; currently Stream::start
	// spawns its own thread and doesn't hand a handle back.
	#[allow(dead_code)]
	pub stream: Option<Stream>,
	pub is_started: bool,
	pub is_running: bool,
	// Reserved for future state-machine tracking; the handlers in client.rs
	// operate directly on Message variants today.
	#[allow(dead_code)]
	pub state: Message,
	pub rx_channel: std::sync::mpsc::Receiver<Message>,
	pub tx_channel: std::sync::mpsc::Sender<Message>,
	pub receipt_rx: std::sync::mpsc::Receiver<ClientStreamReceipt>,
	pub receipt_tx: std::sync::mpsc::Sender<ClientStreamReceipt>,
	/// Receipts drained from `receipt_rx` once the test window closes.
	/// Populated by the main loop before ExchangeResults fires.
	pub receipts: Vec<ClientStreamReceipt>,
	/// CPU-time snapshot taken at the start of the test for the
	/// client-side Results.cpu_util_* fields.
	pub cpu_start: Option<CpuSnapshot>,
	/// rPerf3 extension: when the server sends `SetDataPort` in concurrent
	/// UDP mode, this overrides the port used for UDP data streams. `None`
	/// means use the same port as the TCP control channel (legacy behavior).
	pub data_port_override: Option<u16>,
}

impl Test {
	pub fn new(config: Config) -> Self {
		let (send, recv) = mpsc::channel();
		let (rsend, rrecv) = mpsc::channel();

		Self {
			config,
			cookie: super::cookie::generate_cookie(),
			control_channel: None,
			stream: None,
			is_started: false,
			is_running: false,
			rx_channel: recv,
			tx_channel: send,
			receipt_rx: rrecv,
			receipt_tx: rsend,
			receipts: Vec::new(),
			cpu_start: None,
			state: Message::TestStart,
			data_port_override: None,
		}
	}

	/// Drain any pending receipts on `receipt_rx` into `self.receipts`.
	/// Non-blocking.
	pub fn drain_receipts(&mut self) {
		while let Ok(r) = self.receipt_rx.try_recv() {
			self.receipts.push(r);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn config_with_host_uses_iperf3_defaults() {
		let cfg = Config::with_host("localhost");
		assert_eq!(cfg.host, "localhost");
		assert_eq!(cfg.port, 5201);
		assert_eq!(cfg.time, 10);
		assert_eq!(cfg.parallel, 1);
		assert_eq!(cfg.len, DEFAULT_TCP_LEN as u32);
	}

	#[test]
	fn config_host_port_formats_correctly() {
		let cfg = Config {
			host: "10.1.10.3".to_string(),
			port: 5202,
			time: 1,
			parallel: 1,
			len: DEFAULT_TCP_LEN as u32,
			omit: 0,
			transport: TransportKind::Tcp,
			bandwidth: 0,
			one_off: false,
			max_concurrent: 1,
			direction: Direction::Forward,
			json: false,
			format_unit: None,
			logfile: None,
			window_size: None,
			mss: None,
			congestion: None,
			tos: None,
			zero_copy: false,
			total_bytes: None,
			total_blocks: None,
			title: None,
			affinity: None,
			username: None,
			password: None,
			rsa_public_key: None,
			rsa_private_key: None,
			authorized_users: None,
		};
		assert_eq!(cfg.host_port(), "10.1.10.3:5202");
	}

	#[test]
	fn config_with_host_defaults_tcp_and_unlimited_bandwidth() {
		let cfg = Config::with_host("h");
		assert_eq!(cfg.transport, crate::common::TransportKind::Tcp);
		assert_eq!(cfg.bandwidth, 0);
	}

	#[test]
	fn test_new_stores_config() {
		let cfg = Config::with_host("server.local");
		let t = Test::new(cfg.clone());
		assert_eq!(t.config, cfg);
		assert!(!t.is_started);
		assert!(!t.is_running);
		assert!(t.control_channel.is_none());
	}

	#[test]
	fn config_with_host_defaults_forward() {
		let cfg = Config::with_host("h");
		assert_eq!(cfg.direction, crate::common::Direction::Forward);
	}

	#[test]
	fn client_receipt_empty_zeros_udp_fields() {
		let r = ClientStreamReceipt::empty(1);
		assert_eq!(r.jitter_ms, 0.0);
		assert_eq!(r.lost, 0);
		assert_eq!(r.ooo, 0);
		assert_eq!(r.packets, 0);
	}

	#[test]
	fn config_with_host_defaults_multi_test_server() {
		let cfg = Config::with_host("h");
		assert!(!cfg.one_off);
		assert_eq!(cfg.max_concurrent, 1);
	}
}
