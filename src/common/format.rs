//! Human-readable formatting helpers matching iPerf3's output style:
//! bytes rendered in binary units (KBytes/MBytes/GBytes, base 1024),
//! bitrates rendered in SI units (Kbits/Mbits/Gbits/sec, base 1000).

/// Render a byte count the way iperf3 does:
/// `500 Bytes`, `1.50 KBytes`, `128 MBytes`, `15.9 GBytes`, `2.10 TBytes`.
pub fn bytes(n: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    const TIB: u64 = GIB * 1024;

    if n >= TIB {
        format!("{:.2} TBytes", n as f64 / TIB as f64)
    } else if n >= GIB {
        format!("{:.2} GBytes", n as f64 / GIB as f64)
    } else if n >= MIB {
        format!("{:.2} MBytes", n as f64 / MIB as f64)
    } else if n >= KIB {
        format!("{:.2} KBytes", n as f64 / KIB as f64)
    } else {
        format!("{} Bytes", n)
    }
}

/// Render a bitrate given bits per second, base 1000.
/// `800.00 bits/sec`, `500.00 Kbits/sec`, `137.50 Mbits/sec`, `12.40 Gbits/sec`.
pub fn bitrate_bps(bits_per_sec: f64) -> String {
    const K: f64 = 1_000.0;
    const M: f64 = K * 1_000.0;
    const G: f64 = M * 1_000.0;
    const T: f64 = G * 1_000.0;

    if bits_per_sec >= T {
        format!("{:.2} Tbits/sec", bits_per_sec / T)
    } else if bits_per_sec >= G {
        format!("{:.2} Gbits/sec", bits_per_sec / G)
    } else if bits_per_sec >= M {
        format!("{:.2} Mbits/sec", bits_per_sec / M)
    } else if bits_per_sec >= K {
        format!("{:.2} Kbits/sec", bits_per_sec / K)
    } else {
        format!("{:.2} bits/sec", bits_per_sec)
    }
}

/// Render a throughput given bytes and a duration in seconds, as
/// `<bitrate>`. Guards against zero-duration by treating it as a
/// vanishingly small non-zero value.
pub fn bitrate(bytes_count: u64, duration_secs: f64) -> String {
    let secs = duration_secs.max(0.000_001);
    bitrate_bps((bytes_count as f64 * 8.0) / secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_under_kib_renders_as_bytes() {
        assert_eq!(bytes(0), "0 Bytes");
        assert_eq!(bytes(1023), "1023 Bytes");
    }

    #[test]
    fn bytes_kib_renders_with_two_decimals() {
        assert_eq!(bytes(1024), "1.00 KBytes");
        assert_eq!(bytes(2048), "2.00 KBytes");
        assert_eq!(bytes(1536), "1.50 KBytes");
    }

    #[test]
    fn bytes_mib_renders_with_two_decimals() {
        assert_eq!(bytes(1024 * 1024), "1.00 MBytes");
        assert_eq!(bytes(128 * 1024 * 1024), "128.00 MBytes");
    }

    #[test]
    fn bytes_gib_renders_with_two_decimals() {
        // iperf3's "15.9 GBytes" for ~17 GB input.
        let n = 17_013_866_288u64;
        let out = bytes(n);
        assert!(out.ends_with(" GBytes"), "unexpected: {}", out);
        // 15.85 GiB rounds to 15.85.
        assert!(out.starts_with("15.8"), "unexpected: {}", out);
    }

    #[test]
    fn bytes_tib_renders_in_tbytes() {
        let n = 2u64 * 1024u64 * 1024 * 1024 * 1024;
        assert_eq!(bytes(n), "2.00 TBytes");
    }

    #[test]
    fn bitrate_bps_scales_by_1000() {
        assert_eq!(bitrate_bps(500.0), "500.00 bits/sec");
        assert_eq!(bitrate_bps(1_000.0), "1.00 Kbits/sec");
        assert_eq!(bitrate_bps(1_500_000.0), "1.50 Mbits/sec");
        assert_eq!(bitrate_bps(137_500_000_000.0), "137.50 Gbits/sec");
    }

    #[test]
    fn bitrate_from_bytes_over_seconds() {
        // 125_000 bytes per second = 1 Mbit/sec.
        assert_eq!(bitrate(125_000, 1.0), "1.00 Mbits/sec");
    }

    #[test]
    fn bitrate_handles_zero_duration_without_panic() {
        let out = bitrate(1_000, 0.0);
        assert!(out.ends_with("bits/sec"));
    }
}
