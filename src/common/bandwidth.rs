//! Parse iperf3-style bandwidth strings for `-b`.
//! Accepts integer bits-per-second with optional K/M/G suffix (case-
//! insensitive). Returns bps. "0" (or "") means unlimited.

/// Parse a size string with optional K/M/G suffix using binary (1024-based)
/// multipliers.  Used for buffer sizes (-w) and byte counts (-n).
///
/// Examples: "256K" → 262144, "1M" → 1048576, "1G" → 1073741824, "4096" → 4096.
pub fn parse_size(s: &str) -> Result<u64, String> {
    if s.is_empty() {
        return Ok(0);
    }
    let (num_part, mult): (&str, u64) = match s.as_bytes().last() {
        Some(b'k') | Some(b'K') => (&s[..s.len() - 1], 1_024),
        Some(b'm') | Some(b'M') => (&s[..s.len() - 1], 1_024 * 1_024),
        Some(b'g') | Some(b'G') => (&s[..s.len() - 1], 1_024 * 1_024 * 1_024),
        _ => (s, 1),
    };
    let n: u64 = num_part
        .parse()
        .map_err(|e| format!("invalid size '{}': {}", s, e))?;
    n.checked_mul(mult)
        .ok_or_else(|| format!("size '{}' overflows u64", s))
}

/// Parse a TOS value from a string.  Accepts:
/// - Decimal: "16"
/// - Hex with 0x prefix: "0x10"
/// - Octal with 0 prefix: "020"
pub fn parse_tos(s: &str) -> Result<u8, String> {
    let val: u32 = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).map_err(|e| format!("invalid TOS hex '{}': {}", s, e))?
    } else if s.starts_with('0') && s.len() > 1 {
        u32::from_str_radix(&s[1..], 8).map_err(|e| format!("invalid TOS octal '{}': {}", s, e))?
    } else {
        s.parse::<u32>().map_err(|e| format!("invalid TOS '{}': {}", s, e))?
    };
    if val > 255 {
        return Err(format!("TOS value {} out of range (0-255)", val));
    }
    Ok(val as u8)
}

pub fn parse(s: &str) -> Result<u64, String> {
    if s.is_empty() {
        return Ok(0);
    }
    let (num_part, mult): (&str, u64) = match s.as_bytes().last() {
        Some(b'k') | Some(b'K') => (&s[..s.len() - 1], 1_000),
        Some(b'm') | Some(b'M') => (&s[..s.len() - 1], 1_000_000),
        Some(b'g') | Some(b'G') => (&s[..s.len() - 1], 1_000_000_000),
        _ => (s, 1),
    };
    let n: u64 = num_part
        .parse()
        .map_err(|e| format!("invalid bandwidth '{}': {}", s, e))?;
    n.checked_mul(mult)
        .ok_or_else(|| format!("bandwidth '{}' overflows u64", s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_unlimited() {
        assert_eq!(parse("0").unwrap(), 0);
        assert_eq!(parse("").unwrap(), 0);
    }

    #[test]
    fn integer_bps_passthrough() {
        assert_eq!(parse("1000").unwrap(), 1_000);
    }

    #[test]
    fn k_suffix_is_thousand_bits() {
        assert_eq!(parse("1k").unwrap(), 1_000);
        assert_eq!(parse("250K").unwrap(), 250_000);
    }

    #[test]
    fn m_suffix_is_million_bits() {
        assert_eq!(parse("1M").unwrap(), 1_000_000);
        assert_eq!(parse("100m").unwrap(), 100_000_000);
    }

    #[test]
    fn g_suffix_is_billion_bits() {
        assert_eq!(parse("2G").unwrap(), 2_000_000_000);
    }

    #[test]
    fn invalid_input_errors() {
        assert!(parse("abc").is_err());
        assert!(parse("1.5M").is_err());
        assert!(parse("M").is_err());
    }

    #[test]
    fn overflow_errors() {
        assert!(parse("99999999999G").is_err());
    }
}
