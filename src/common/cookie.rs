use std::io;

use rand::{distributions::Alphanumeric, Rng};

use super::protocol::Socket;

/// Length of an iPerf3 cookie on the wire: 36 random ASCII alphanumerics
/// followed by a trailing NUL byte.
pub const COOKIE_LEN: usize = 37;

/// Generate a fresh cookie matching iPerf3's format:
/// 36 ASCII alphanumeric characters followed by `\0`.
pub fn generate_cookie() -> [u8; COOKIE_LEN] {
    let mut cookie = [0u8; COOKIE_LEN];
    let mut rng = rand::thread_rng();
    for slot in cookie.iter_mut().take(COOKIE_LEN - 1) {
        *slot = rng.sample(Alphanumeric);
    }
    // Last byte is left as 0 (NUL terminator).
    cookie
}

/// Read exactly `COOKIE_LEN` bytes from `sock`. This is the first thing
/// an iPerf3 server sees on any accepted connection — control channel
/// and data streams both begin with a cookie so the server can
/// multiplex them.
pub fn recv_cookie(sock: &mut dyn Socket) -> io::Result<[u8; COOKIE_LEN]> {
    let mut buf = [0u8; COOKIE_LEN];
    let mut read = 0;
    while read < buf.len() {
        match sock.recv(&mut buf[read..])? {
            0 => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed before cookie was fully received",
                ));
            }
            n => read += n,
        }
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_is_36_alnum_plus_null() {
        let cookie = generate_cookie();
        assert_eq!(cookie.len(), 37);
        assert_eq!(cookie[36], 0, "last byte must be NUL");
        for (i, b) in cookie[..36].iter().enumerate() {
            assert!(
                b.is_ascii_alphanumeric(),
                "byte {} = {} is not ASCII alphanumeric",
                i,
                b
            );
        }
    }

    #[test]
    fn two_cookies_differ() {
        // Astronomically unlikely to collide; if this fails, fix your RNG.
        let a = generate_cookie();
        let b = generate_cookie();
        assert_ne!(a, b, "two consecutive cookies should not match");
    }

    #[test]
    fn recv_cookie_reads_exact_37_bytes() {
        use crate::common::protocol::testing::MockSocket;

        let cookie = generate_cookie();
        let mut mock = MockSocket::new();
        mock.recv_queue.lock().unwrap().push(cookie.to_vec());

        let received = recv_cookie(&mut mock).unwrap();
        assert_eq!(received, cookie);
    }

    #[test]
    fn recv_cookie_reassembles_short_reads() {
        use crate::common::protocol::testing::MockSocket;

        let cookie = generate_cookie();
        let mut mock = MockSocket::new();
        // Split into three short reads.
        {
            let mut q = mock.recv_queue.lock().unwrap();
            q.push(cookie[..10].to_vec());
            q.push(cookie[10..25].to_vec());
            q.push(cookie[25..].to_vec());
        }

        let received = recv_cookie(&mut mock).unwrap();
        assert_eq!(received, cookie);
    }

    #[test]
    fn recv_cookie_errors_on_premature_close() {
        use crate::common::protocol::testing::MockSocket;

        let mut mock = MockSocket::new();
        // Only 5 bytes delivered, then EOF (empty chunk).
        mock.recv_queue.lock().unwrap().push(vec![b'x'; 5]);
        mock.recv_queue.lock().unwrap().push(Vec::new());

        let err = recv_cookie(&mut mock).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
