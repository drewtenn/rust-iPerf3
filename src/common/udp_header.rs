//! iperf3-compatible UDP datagram header: 16 bytes, network byte order.
//!
//! Layout:
//! - bytes 0..4  : tv_sec  (u32, BE) — sender wall-clock seconds
//! - bytes 4..8  : tv_usec (u32, BE) — sender wall-clock microseconds
//! - bytes 8..16 : seq     (i64, BE) — monotonic sequence number; negative = end-of-test

use std::io;

pub const UDP_HEADER_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpHeader {
    pub tv_sec: u32,
    pub tv_usec: u32,
    pub seq: i64,
}

impl UdpHeader {
    pub fn encode(self, out: &mut [u8]) -> io::Result<()> {
        if out.len() < UDP_HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer too small for UDP header",
            ));
        }
        out[0..4].copy_from_slice(&self.tv_sec.to_be_bytes());
        out[4..8].copy_from_slice(&self.tv_usec.to_be_bytes());
        out[8..16].copy_from_slice(&self.seq.to_be_bytes());
        Ok(())
    }

    pub fn decode(buf: &[u8]) -> io::Result<Self> {
        if buf.len() < UDP_HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "datagram shorter than 16-byte UDP header",
            ));
        }
        let tv_sec = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        let tv_usec = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        let seq = i64::from_be_bytes(buf[8..16].try_into().unwrap());
        Ok(Self { tv_sec, tv_usec, seq })
    }

    pub fn is_sentinel(&self) -> bool {
        self.seq < 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let h = UdpHeader { tv_sec: 0x11223344, tv_usec: 0x55667788, seq: 0x0A0B_0C0D_1234_5678 };
        let mut buf = [0u8; 16];
        h.encode(&mut buf).unwrap();
        let back = UdpHeader::decode(&buf).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn encode_layout_is_big_endian() {
        let h = UdpHeader { tv_sec: 1, tv_usec: 2, seq: 3 };
        let mut buf = [0u8; 16];
        h.encode(&mut buf).unwrap();
        assert_eq!(&buf[0..4], &[0, 0, 0, 1]);
        assert_eq!(&buf[4..8], &[0, 0, 0, 2]);
        assert_eq!(&buf[8..16], &[0, 0, 0, 0, 0, 0, 0, 3]);
    }

    #[test]
    fn decode_rejects_short_buffer() {
        let short = [0u8; 8];
        let err = UdpHeader::decode(&short).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn encode_rejects_short_buffer() {
        let h = UdpHeader { tv_sec: 0, tv_usec: 0, seq: 0 };
        let mut tiny = [0u8; 4];
        let err = h.encode(&mut tiny).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn sentinel_is_negative_seq() {
        let h = UdpHeader { tv_sec: 0, tv_usec: 0, seq: -1 };
        assert!(h.is_sentinel());
        let not = UdpHeader { tv_sec: 0, tv_usec: 0, seq: 0 };
        assert!(!not.is_sentinel());
    }

    #[test]
    fn decode_negative_seq_roundtrips() {
        let h = UdpHeader { tv_sec: 10, tv_usec: 20, seq: -42 };
        let mut buf = [0u8; 16];
        h.encode(&mut buf).unwrap();
        let back = UdpHeader::decode(&buf).unwrap();
        assert_eq!(back.seq, -42);
        assert!(back.is_sentinel());
    }
}
