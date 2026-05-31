//! Multi-session server orchestration. Owns the session registry and
//! handles data-stream demux by cookie so multiple concurrent tests
//! can share one listen port.

use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Duration;

use super::cookie::COOKIE_LEN;
use super::protocol::Protocol;

/// Handle held by the accept loop for pushing newly-arriving data
/// streams to the session that owns the cookie.
pub struct SessionHandle {
    pub data_tx: Sender<Protocol>,
}

/// A test session driven by its own thread. Construct via `Session::new`,
/// drive via `Session::take_control_and_receiver` inside the spawned
/// thread.
pub struct Session {
    pub cookie: [u8; COOKIE_LEN],
    pub control: Protocol,
    pub data_rx: Receiver<Protocol>,
}

impl Session {
    pub fn new(cookie: [u8; COOKIE_LEN], control: Protocol) -> (Self, SessionHandle) {
        let (tx, rx) = channel();
        (
            Self {
                cookie,
                control,
                data_rx: rx,
            },
            SessionHandle { data_tx: tx },
        )
    }
}

/// Collect `n` data-stream sockets from the channel, waiting up to
/// `timeout` for each. Returns an error if any one times out.
pub fn accept_streams_from_channel(
    data_rx: &Receiver<Protocol>,
    n: u32,
    timeout: Option<Duration>,
) -> std::io::Result<Vec<Protocol>> {
    let mut out = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let stream = match timeout {
            Some(t) => data_rx.recv_timeout(t).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timed out waiting for data stream",
                )
            })?,
            None => data_rx.recv().map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "data-stream channel closed",
                )
            })?,
        };
        out.push(stream);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::cookie::generate_cookie;
    use crate::common::protocol::testing::MockSocket;
    use crate::common::protocol::Protocol;

    fn dummy_protocol() -> Protocol {
        Protocol {
            transfer: Box::new(MockSocket::new()),
        }
    }

    #[test]
    fn session_new_pairs_channel() {
        let cookie = generate_cookie();
        let (session, handle) = Session::new(cookie, dummy_protocol());
        assert_eq!(session.cookie, cookie);
        // Send across the pair:
        handle.data_tx.send(dummy_protocol()).expect("send");
        assert!(session.data_rx.try_recv().is_ok());
    }

    #[test]
    fn accept_streams_from_channel_collects_n() {
        let cookie = generate_cookie();
        let (session, handle) = Session::new(cookie, dummy_protocol());
        handle.data_tx.send(dummy_protocol()).unwrap();
        handle.data_tx.send(dummy_protocol()).unwrap();
        let streams = accept_streams_from_channel(
            &session.data_rx,
            2,
            Some(Duration::from_millis(100)),
        )
        .unwrap();
        assert_eq!(streams.len(), 2);
    }

    #[test]
    fn accept_streams_from_channel_times_out() {
        let cookie = generate_cookie();
        let (session, _handle) = Session::new(cookie, dummy_protocol());
        match accept_streams_from_channel(&session.data_rx, 1, Some(Duration::from_millis(50))) {
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::TimedOut),
            Ok(_) => panic!("expected a timeout error"),
        }
    }
}
