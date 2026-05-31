use std::{net::TcpStream, net::UdpSocket, io::{Write, Read, self}, time::Duration};
use std::os::unix::io::AsRawFd;

pub struct Protocol {
	pub transfer : Box<dyn Socket + Send>,
}

/// Socket-level tuning options applied after a connection is established.
/// Mirrors the CLI knobs `-w` (window), `-M` (MSS), `-C` (congestion), `-S` (TOS).
#[derive(Debug, Clone, Default)]
pub struct TuningOpts {
    pub window_size: Option<u32>,
    pub mss: Option<u32>,
    pub congestion: Option<String>,
    pub tos: Option<u8>,
}

impl Protocol {
	pub fn new_tcp(host: String) -> Option<Self> {
		match TcpStream::connect(host) {
			Ok(tcp) => {
				let mut transfer = Tcp::new(tcp);
				if let Err(e) = transfer.set_nonblocking(true) {
					log_io_err(&e);
					return None;
				}
				Some(Self { transfer: Box::new(transfer) })
			}
			Err(e) => { log_io_err(&e); None }
		}
	}

	#[allow(dead_code)] // Will be used once the UDP test path lands.
	pub fn new_udp(host: String) -> Option<Self> {
		match UdpSocket::bind(host) {
			Ok(udp) => { Some(Self { transfer : Box::new(Udp::new(udp)) })},
			Err(e) => { log_io_err(&e); None }
		}
	}
}

fn log_io_err(e: &io::Error) {
	eprintln!("{:?}", e);
}

pub struct Tcp {
	stream: TcpStream
}

#[allow(dead_code)] // UDP path is planned but not yet wired into the client.
pub struct Udp {
	socket: UdpSocket
}

impl Tcp {
	pub fn new(stream: TcpStream) -> Self {
		Self { stream }
	}

	/// Return a second `Tcp` wrapper around a cloned TCP stream handle
	/// so one thread can read while another writes on the same socket
	/// (full-duplex). Used by bidirectional mode on the server side.
	pub fn try_clone(&self) -> io::Result<Tcp> {
		Ok(Tcp::new(self.stream.try_clone()?))
	}
}

#[allow(dead_code)]
impl Udp {
	pub fn new(socket: UdpSocket) -> Self {
		Self { socket }
	 }
}

pub trait Socket {
	fn recv(&mut self, buf: &mut[u8]) -> io::Result<usize>;
	fn send(&mut self, buf: &[u8]) -> io::Result<usize>;
	fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()>;
	/// Configure how long a blocking `recv` waits before returning an
	/// error. Pass `None` to clear any previously-set deadline.
	fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()>;
	/// Total TCP segment retransmissions on this socket since the
	/// connection was established. Linux-only (via getsockopt +
	/// TCP_INFO); other platforms return `Unsupported`.
	fn tcp_retransmits(&self) -> io::Result<u32>;
	/// Clone the underlying TCP stream handle so a second thread can
	/// write while this one reads (full-duplex). Only implemented for
	/// `Tcp`; all other socket types return `Unsupported`.
	fn try_clone_tcp(&self) -> io::Result<Box<dyn Socket + Send>> {
		Err(io::Error::new(
			io::ErrorKind::Unsupported,
			"socket does not support clone",
		))
	}
	/// Apply socket-level tuning options (buffer sizes, TOS, MSS,
	/// congestion algorithm). The default no-op is correct for all
	/// non-TCP socket types; `Tcp` overrides with `setsockopt` calls.
	fn apply_tuning(&self, _opts: &TuningOpts) -> io::Result<()> {
		Ok(())
	}
}

impl Socket for Tcp {
	fn recv(&mut self, buf: &mut[u8]) -> io::Result<usize> { self.stream.read(buf) }
	fn send(&mut self, buf: &[u8]) -> io::Result<usize> { self.stream.write(buf) }
	fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> { self.stream.set_nonblocking(nonblocking) }
	fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> { self.stream.set_read_timeout(timeout) }
	fn try_clone_tcp(&self) -> io::Result<Box<dyn Socket + Send>> {
		Ok(Box::new(self.try_clone()?))
	}
	fn tcp_retransmits(&self) -> io::Result<u32> {
		#[cfg(target_os = "linux")]
		{ linux_tcp::total_retrans(&self.stream) }
		#[cfg(not(target_os = "linux"))]
		{ Err(io::Error::new(io::ErrorKind::Unsupported, "TCP_INFO not available on this platform")) }
	}

	fn apply_tuning(&self, opts: &TuningOpts) -> io::Result<()> {
		let fd = self.stream.as_raw_fd();

		if let Some(w) = opts.window_size {
			let size: libc::c_int = w as libc::c_int;
			let r = unsafe {
				libc::setsockopt(
					fd,
					libc::SOL_SOCKET,
					libc::SO_SNDBUF,
					&size as *const _ as *const libc::c_void,
					std::mem::size_of::<libc::c_int>() as libc::socklen_t,
				)
			};
			if r != 0 {
				eprintln!("SO_SNDBUF failed: {}", io::Error::last_os_error());
			}
			let r = unsafe {
				libc::setsockopt(
					fd,
					libc::SOL_SOCKET,
					libc::SO_RCVBUF,
					&size as *const _ as *const libc::c_void,
					std::mem::size_of::<libc::c_int>() as libc::socklen_t,
				)
			};
			if r != 0 {
				eprintln!("SO_RCVBUF failed: {}", io::Error::last_os_error());
			}
		}

		if let Some(tos) = opts.tos {
			let val: libc::c_int = tos as libc::c_int;
			let r = unsafe {
				libc::setsockopt(
					fd,
					libc::IPPROTO_IP,
					libc::IP_TOS,
					&val as *const _ as *const libc::c_void,
					std::mem::size_of::<libc::c_int>() as libc::socklen_t,
				)
			};
			if r != 0 {
				eprintln!("IP_TOS failed: {}", io::Error::last_os_error());
			}
		}

		#[cfg(target_os = "linux")]
		{
			if let Some(mss) = opts.mss {
				let size: libc::c_int = mss as libc::c_int;
				let r = unsafe {
					libc::setsockopt(
						fd,
						libc::IPPROTO_TCP,
						libc::TCP_MAXSEG,
						&size as *const _ as *const libc::c_void,
						std::mem::size_of::<libc::c_int>() as libc::socklen_t,
					)
				};
				if r != 0 {
					eprintln!("TCP_MAXSEG failed: {}", io::Error::last_os_error());
				}
			}
			if let Some(algo) = &opts.congestion {
				let bytes = algo.as_bytes();
				let r = unsafe {
					libc::setsockopt(
						fd,
						libc::IPPROTO_TCP,
						libc::TCP_CONGESTION,
						bytes.as_ptr() as *const libc::c_void,
						bytes.len() as libc::socklen_t,
					)
				};
				if r != 0 {
					eprintln!("TCP_CONGESTION failed: {}", io::Error::last_os_error());
				}
			}
		}
		#[cfg(not(target_os = "linux"))]
		{
			if opts.mss.is_some() {
				eprintln!("warning: -M/--set-mss is Linux-only; ignoring");
			}
			if opts.congestion.is_some() {
				eprintln!("warning: -C/--congestion is Linux-only; ignoring");
			}
		}

		Ok(())
	}
}

impl Socket for Udp {
	fn recv(&mut self, buf: &mut[u8]) -> io::Result<usize> { self.socket.recv_from(buf).map(|(n, _)| n) }
	fn send(&mut self, buf: &[u8]) -> io::Result<usize> { self.socket.send(buf) }
	fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> { self.socket.set_nonblocking(nonblocking) }
	fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> { self.socket.set_read_timeout(timeout) }
	fn tcp_retransmits(&self) -> io::Result<u32> {
		Err(io::Error::new(io::ErrorKind::Unsupported, "UDP has no retransmits"))
	}
}

#[cfg(target_os = "linux")]
mod linux_tcp {
	use std::io;
	use std::mem::MaybeUninit;
	use std::net::TcpStream;
	use std::os::unix::io::AsRawFd;

	/// Read `tcpi_total_retrans` from `TCP_INFO` on the given stream.
	/// Zero on a healthy connection; climbs when the stack retransmits.
	pub fn total_retrans(stream: &TcpStream) -> io::Result<u32> {
		let fd = stream.as_raw_fd();
		let mut info = MaybeUninit::<libc::tcp_info>::uninit();
		let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
		let rc = unsafe {
			libc::getsockopt(
				fd,
				libc::IPPROTO_TCP,
				libc::TCP_INFO,
				info.as_mut_ptr() as *mut libc::c_void,
				&mut len,
			)
		};
		if rc != 0 {
			return Err(io::Error::last_os_error());
		}
		// SAFETY: getsockopt returned success, so the struct was
		// populated to at least `len` bytes. tcp_info's layout matches
		// the kernel struct via libc bindings.
		let info = unsafe { info.assume_init() };
		Ok(info.tcpi_total_retrans)
	}
}

/// Test-only helpers for exercising `Socket`-consuming code without a
/// real network. Gated behind `#[cfg(test)]` so nothing ships into the
/// binary, but kept `pub` within the crate so other modules' test
/// blocks can reach it.
#[cfg(test)]
pub(crate) mod testing {
	use super::Socket;
	use std::io;
	use std::sync::{Arc, Mutex};

	/// In-memory Socket that records every byte sent and returns
	/// caller-supplied responses (or canned errors) on recv/send.
	pub struct MockSocket {
		pub written: Arc<Mutex<Vec<u8>>>,
		pub send_err: Option<io::Error>,
		pub recv_queue: Arc<Mutex<Vec<Vec<u8>>>>,
		pub nonblocking: Option<bool>,
		pub read_timeout: Option<Option<std::time::Duration>>,
	}

	impl MockSocket {
		pub fn new() -> Self {
			Self {
				written: Arc::new(Mutex::new(Vec::new())),
				send_err: None,
				recv_queue: Arc::new(Mutex::new(Vec::new())),
				nonblocking: None,
				read_timeout: None,
			}
		}

		pub fn with_send_error(mut self, e: io::Error) -> Self {
			self.send_err = Some(e);
			self
		}
	}

	impl Socket for MockSocket {
		fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
			let mut q = self.recv_queue.lock().unwrap();
			if q.is_empty() {
				return Err(io::Error::new(io::ErrorKind::WouldBlock, "no data"));
			}
			let next = q.remove(0);
			let n = next.len().min(buf.len());
			buf[..n].copy_from_slice(&next[..n]);
			Ok(n)
		}

		fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
			if let Some(ref e) = self.send_err {
				return Err(io::Error::new(e.kind(), e.to_string()));
			}
			self.written.lock().unwrap().extend_from_slice(buf);
			Ok(buf.len())
		}

		fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
			self.nonblocking = Some(nonblocking);
			Ok(())
		}

		fn set_read_timeout(&mut self, timeout: Option<std::time::Duration>) -> io::Result<()> {
			self.read_timeout = Some(timeout);
			Ok(())
		}

		fn tcp_retransmits(&self) -> io::Result<u32> {
			Ok(0)
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::time::Duration;

	#[test]
	fn udp_recv_returns_err_not_panic_on_timeout() {
		let socket = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral udp port");
		socket
			.set_read_timeout(Some(Duration::from_millis(50)))
			.expect("set_read_timeout");

		let mut udp = Udp::new(socket);
		let mut buf = [0u8; 16];
		let result = udp.recv(&mut buf);

		assert!(
			result.is_err(),
			"expected Err on timeout, got Ok({:?})",
			result
		);
	}

	#[test]
	fn udp_set_nonblocking_round_trip() {
		let socket = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral udp port");
		let mut udp = Udp::new(socket);

		assert!(udp.set_nonblocking(true).is_ok());
		assert!(udp.set_nonblocking(false).is_ok());
	}

	#[test]
	fn mock_socket_records_sent_bytes() {
		use super::testing::MockSocket;

		let mut mock = MockSocket::new();
		let written = mock.written.clone();

		assert_eq!(mock.send(b"abc").unwrap(), 3);
		assert_eq!(mock.send(b"de").unwrap(), 2);
		assert_eq!(&*written.lock().unwrap(), b"abcde");
	}

	#[test]
	fn mock_socket_returns_send_err_when_configured() {
		use super::testing::MockSocket;
		use std::io::{Error, ErrorKind};

		let mut mock = MockSocket::new().with_send_error(Error::new(ErrorKind::BrokenPipe, "nope"));
		let err = mock.send(b"x").unwrap_err();
		assert_eq!(err.kind(), ErrorKind::BrokenPipe);
	}

	#[cfg(target_os = "linux")]
	#[test]
	fn tcp_retransmits_on_fresh_loopback_is_zero() {
		use std::net::TcpListener;
		use std::thread;

		let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
		let addr = listener.local_addr().unwrap();
		let _client = thread::spawn(move || {
			let _s = TcpStream::connect(addr).expect("connect");
			std::thread::sleep(Duration::from_millis(50));
		});

		let (stream, _) = listener.accept().expect("accept");
		let tcp = Tcp::new(stream);
		let retransmits = tcp.tcp_retransmits().expect("tcp_retransmits");
		assert_eq!(retransmits, 0, "fresh loopback should have zero retransmits");
	}

	#[test]
	fn udp_tcp_retransmits_is_unsupported() {
		let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
		let udp = Udp::new(socket);
		let err = udp.tcp_retransmits().unwrap_err();
		assert_eq!(err.kind(), io::ErrorKind::Unsupported);
	}

	#[test]
	fn mock_socket_records_read_timeout() {
		use super::testing::MockSocket;

		let mut mock = MockSocket::new();
		assert!(mock.set_read_timeout(Some(Duration::from_millis(250))).is_ok());
		assert_eq!(mock.read_timeout, Some(Some(Duration::from_millis(250))));

		assert!(mock.set_read_timeout(None).is_ok());
		assert_eq!(mock.read_timeout, Some(None));
	}

	#[test]
	fn tuning_sets_recv_buffer() {
		use std::net::{TcpListener, TcpStream};
		let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
		let addr = listener.local_addr().unwrap();
		let client_thread = std::thread::spawn(move || {
			TcpStream::connect(addr).expect("connect");
		});
		let (stream, _) = listener.accept().expect("accept");
		let tcp = Tcp::new(stream);
		tcp.apply_tuning(&TuningOpts { window_size: Some(131072), ..Default::default() }).unwrap();
		client_thread.join().unwrap();
	}

	#[test]
	fn tcp_set_read_timeout_causes_blocking_recv_to_return_err() {
		use std::net::TcpListener;

		let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
		let addr = listener.local_addr().unwrap();

		let _writer = std::thread::spawn(move || {
			// Connect then do nothing — server's recv will time out.
			let _s = TcpStream::connect(addr).expect("connect");
			std::thread::sleep(Duration::from_millis(500));
		});

		let (stream, _) = listener.accept().expect("accept");
		let mut tcp = Tcp::new(stream);
		tcp.set_read_timeout(Some(Duration::from_millis(50))).expect("set_read_timeout");

		let start = std::time::Instant::now();
		let mut buf = [0u8; 8];
		let result = tcp.recv(&mut buf);
		let elapsed = start.elapsed();

		assert!(result.is_err(), "expected timeout error, got {:?}", result);
		let kind = result.unwrap_err().kind();
		assert!(
			matches!(kind, io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut),
			"unexpected error kind: {:?}",
			kind
		);
		// Should have returned within ~100ms — well under 500ms.
		assert!(elapsed < Duration::from_millis(300), "recv took too long: {:?}", elapsed);
	}
}
