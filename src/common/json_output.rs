//! Minimal iperf3-compatible JSON output for end-of-test summaries.
//!
//! The shape approximates iperf3's `-J` output closely enough for
//! automation to parse `bytes` and `bits_per_second` from `end.sum_sent`
//! and `end.sum_received`. Interval streaming and per-stream detail are
//! noted as follow-ups in the roadmap.

use serde::Serialize;

#[derive(Serialize)]
pub struct JsonOutput {
    pub start: JsonStart,
    pub end: JsonEnd,
}

#[derive(Serialize)]
pub struct JsonStart {
    pub connecting_to: Option<JsonConnectingTo>,
    pub test_start: JsonTestStart,
}

#[derive(Serialize)]
pub struct JsonConnectingTo {
    pub host: String,
    pub port: u16,
}

#[derive(Serialize)]
pub struct JsonTestStart {
    pub protocol: String,
    pub num_streams: u32,
    pub blksize: u32,
    pub duration: u32,
    pub reverse: u32,
    pub bidir: u32,
}

#[derive(Serialize)]
pub struct JsonEnd {
    pub sum_sent: JsonSum,
    pub sum_received: JsonSum,
}

#[derive(Serialize)]
pub struct JsonSum {
    pub bytes: u64,
    pub seconds: f64,
    pub bits_per_second: f64,
}

impl JsonSum {
    pub fn new(bytes: u64, seconds: f64) -> Self {
        let s = seconds.max(0.000_001);
        Self {
            bytes,
            seconds,
            bits_per_second: (bytes as f64 * 8.0) / s,
        }
    }
}

pub fn render(output: &JsonOutput) -> String {
    serde_json::to_string_pretty(output).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_shape_is_parseable() {
        let j = JsonOutput {
            start: JsonStart {
                connecting_to: Some(JsonConnectingTo {
                    host: "127.0.0.1".into(),
                    port: 5201,
                }),
                test_start: JsonTestStart {
                    protocol: "TCP".into(),
                    num_streams: 1,
                    blksize: 131072,
                    duration: 1,
                    reverse: 0,
                    bidir: 0,
                },
            },
            end: JsonEnd {
                sum_sent: JsonSum::new(1_000_000, 1.0),
                sum_received: JsonSum::new(1_000_000, 1.0),
            },
        };
        let s = render(&j);
        assert!(s.contains("\"bytes\": 1000000"));
        assert!(s.contains("\"protocol\": \"TCP\""));
    }

    #[test]
    fn json_sum_computes_bitrate() {
        let sum = JsonSum::new(1_000_000, 1.0);
        assert!((sum.bits_per_second - 8_000_000.0).abs() < 1.0);
    }

    #[test]
    fn json_sum_avoids_divide_by_zero() {
        let sum = JsonSum::new(100, 0.0);
        assert!(sum.bits_per_second.is_finite());
        assert!(sum.bits_per_second > 0.0);
    }
}
