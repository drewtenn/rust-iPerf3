//! Token-bucket sender pacing for UDP/TCP bandwidth limits.
//!
//! Tracks bytes-sent vs. expected-bytes-at-this-time and returns a
//! `Duration` to sleep when the sender is ahead of schedule. `rate_bps`
//! is bits per second, matching iperf3's `-b` flag. A rate of 0 disables
//! pacing (unlimited).

use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub struct TokenBucket {
    pub rate_bps: u64,
    pub bytes_sent: u64,
    pub start: Instant,
}

impl TokenBucket {
    pub fn new(rate_bps: u64, start: Instant) -> Self {
        Self { rate_bps, bytes_sent: 0, start }
    }

    pub fn record(&mut self, n: u64) {
        self.bytes_sent = self.bytes_sent.saturating_add(n);
    }

    pub fn wait(&self, now: Instant) -> Option<Duration> {
        if self.rate_bps == 0 {
            return None;
        }
        let elapsed = now.duration_since(self.start).as_secs_f64();
        let expected_bytes = (self.rate_bps as f64 / 8.0) * elapsed;
        let ahead = self.bytes_sent as f64 - expected_bytes;
        if ahead <= 0.0 {
            return None;
        }
        let seconds_to_wait = ahead / (self.rate_bps as f64 / 8.0);
        Some(Duration::from_secs_f64(seconds_to_wait))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlimited_rate_never_waits() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(0, start);
        bucket.record(10_000_000);
        assert!(bucket.wait(start).is_none());
        assert!(bucket.wait(start + Duration::from_secs(60)).is_none());
    }

    #[test]
    fn no_wait_when_exactly_on_schedule() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(1_000_000, start);
        bucket.record(125_000);
        assert!(bucket.wait(start + Duration::from_secs(1)).is_none());
    }

    #[test]
    fn wait_proportional_when_ahead() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(1_000_000, start);
        bucket.record(250_000);
        let d = bucket.wait(start + Duration::from_secs(1)).expect("should wait");
        let ms = d.as_millis() as i64;
        assert!((950..=1_050).contains(&ms), "unexpected wait: {} ms", ms);
    }

    #[test]
    fn no_wait_when_behind_schedule() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(1_000_000, start);
        bucket.record(1_000);
        assert!(bucket.wait(start + Duration::from_secs(1)).is_none());
    }

    #[test]
    fn record_is_saturating() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(1_000_000, start);
        bucket.bytes_sent = u64::MAX - 10;
        bucket.record(1_000_000);
        assert_eq!(bucket.bytes_sent, u64::MAX);
    }
}
