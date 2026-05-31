use num_enum::TryFromPrimitive;

use self::cookie::COOKIE_LEN;
use self::protocol::Protocol;

pub use direction::Direction;
pub use transport_kind::TransportKind;

pub mod affinity;
pub mod auth;
pub mod bandwidth;
pub mod cookie;
pub mod direction;
pub mod cpu;
pub mod format;
pub mod interval;
pub mod json_output;
pub mod jitter;
pub mod pacing;
pub mod protocol;
pub mod session;
pub mod test;
pub mod timer;
pub mod stream;
pub mod transport_kind;
pub mod udp_header;
pub mod udp_session;
pub mod wire;

#[derive(Debug, Clone, Copy, Eq, PartialEq, TryFromPrimitive)]
#[repr(i8)]
pub enum Message {
    TestStart = 1,
    TestRunning = 2,
    ResultRequest = 3,
    TestEnd = 4,
    StreamBegin = 5,
    StreamRunning = 6,
    StreamEnd = 7,
    AllStreamsEnd = 8,
    ParamExchange = 9,
    CreateStreams = 10,
    ServerTerminate = 11,
    ClientTerminate = 12,
    ExchangeResults = 13,
    DisplayResults = 14,
    IperfStart = 15,
    IperfDone = 16,
    /// rPerf3 extension: server sends this byte followed by a 2-byte
    /// big-endian port number to tell the client which ephemeral UDP
    /// port to direct its data streams at. Only used in concurrent mode
    /// (max_concurrent > 1) for UDP sessions.
    SetDataPort = 17,
    AccessDenied = -1,
    ServerError = -2,
}

/// Open a TCP connection to `host` and immediately send the session's
/// cookie. iPerf3 multiplexes control and data streams over the same
/// server port using the cookie as the session key — so every stream
/// in one session must send the *same* cookie.
pub fn connect(host: String, cookie: &[u8; COOKIE_LEN]) -> Option<Protocol> {
    match Protocol::new_tcp(host) {
        Some(mut protocol) => match send_cookie(&mut protocol, cookie) {
            Ok(()) => Some(protocol),
            Err(e) => {
                eprintln!("failed to send cookie: {:?}", e);
                None
            }
        },
        None => None,
    }
}

fn send_cookie(protocol: &mut Protocol, cookie: &[u8; COOKIE_LEN]) -> std::io::Result<()> {
    protocol.transfer.send(cookie)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_roundtrip_try_from_primitive() {
        let variants = [
            Message::TestStart,
            Message::TestRunning,
            Message::ResultRequest,
            Message::TestEnd,
            Message::StreamBegin,
            Message::StreamRunning,
            Message::StreamEnd,
            Message::AllStreamsEnd,
            Message::ParamExchange,
            Message::CreateStreams,
            Message::ServerTerminate,
            Message::ClientTerminate,
            Message::ExchangeResults,
            Message::DisplayResults,
            Message::IperfStart,
            Message::IperfDone,
            Message::SetDataPort,
            Message::AccessDenied,
            Message::ServerError,
        ];

        for variant in variants {
            let code = variant as i8;
            let roundtripped = Message::try_from(code)
                .unwrap_or_else(|_| panic!("code {} failed to round-trip", code));
            assert_eq!(
                roundtripped as i8, code,
                "variant value {} did not round-trip",
                code
            );
        }
    }

    #[test]
    fn message_try_from_unknown_code_is_err() {
        assert!(Message::try_from(0i8).is_err());
        assert!(Message::try_from(127i8).is_err());
        assert!(Message::try_from(-128i8).is_err());
    }
}