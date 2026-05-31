//! Per-second (configurable) interval reporting.
//!
//! Both the client's send loop and the server's receive loop feed
//! byte-count deltas through an `IntervalReporter`. The reporter holds
//! a running total and a boundary clock; every time a recv/send
//! crosses the next boundary, it returns an `IntervalSnapshot` that
//! the caller prints. Keeping this pure (no I/O) makes it unit-testable
//! without a real test run, and keeps the hot loops branch-free in the
//! common case.

use std::time::{Duration, Instant};

/// A single emitted interval: [start_sec, end_sec) since the first byte
/// was observed on this stream, plus the byte count accumulated within
/// that window.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IntervalSnapshot {
    pub stream_id: u32,
    pub start_sec: f64,
    pub end_sec: f64,
    pub bytes: u64,
}

impl IntervalSnapshot {
    /// Duration of this interval in seconds, floored to a tiny positive
    /// value to avoid divide-by-zero in the throughput helpers.
    pub fn duration_secs(&self) -> f64 {
        (self.end_sec - self.start_sec).max(0.000_001)
    }

    /// Throughput during this interval in Mbits/sec.
    pub fn mbits_per_sec(&self) -> f64 {
        self.bits_per_sec() / 1_000_000.0
    }

    /// Throughput during this interval in bits/sec (for the
    /// `format::bitrate_bps` helper).
    pub fn bits_per_sec(&self) -> f64 {
        (self.bytes as f64 * 8.0) / self.duration_secs()
    }
}

/// Rolling accumulator that emits snapshots at `interval` boundaries.
pub struct IntervalReporter {
    stream_id: u32,
    interval: Duration,
    origin: Option<Instant>,
    next_boundary: Option<Instant>,
    bytes_in_interval: u64,
}

impl IntervalReporter {
    pub fn new(stream_id: u32, interval: Duration) -> Self {
        Self {
            stream_id,
            interval,
            origin: None,
            next_boundary: None,
            bytes_in_interval: 0,
        }
    }

    /// Record `n` bytes observed at `now`. Returns the interval
    /// snapshot if this tick closes one (possibly more than one, but
    /// we emit at most one per call — callers can call again with
    /// n=0 to drain remaining boundaries if that matters; for our
    /// purposes one per byte-delivery is enough).
    pub fn on_bytes(&mut self, n: u64, now: Instant) -> Option<IntervalSnapshot> {
        if self.origin.is_none() {
            self.origin = Some(now);
            self.next_boundary = Some(now + self.interval);
        }

        self.bytes_in_interval += n;

        let origin = self.origin.expect("origin set");
        let boundary = self.next_boundary.expect("boundary set");

        if now >= boundary {
            let start_sec = (boundary - self.interval).duration_since(origin).as_secs_f64();
            let end_sec = boundary.duration_since(origin).as_secs_f64();
            let snap = IntervalSnapshot {
                stream_id: self.stream_id,
                start_sec,
                end_sec,
                bytes: self.bytes_in_interval,
            };
            // Advance boundary; reset byte counter.
            self.bytes_in_interval = 0;
            self.next_boundary = Some(boundary + self.interval);
            return Some(snap);
        }
        None
    }

    /// Emit whatever is still in the bucket as a final snapshot (may
    /// cover less than a full interval). Returns `None` if no bytes
    /// have ever been seen.
    pub fn flush(&mut self, now: Instant) -> Option<IntervalSnapshot> {
        let origin = self.origin?;
        if self.bytes_in_interval == 0 && self.next_boundary.is_none_or(|b| now < b - self.interval) {
            return None;
        }
        let boundary = self.next_boundary.unwrap_or(now);
        let start_sec = (boundary - self.interval).duration_since(origin).as_secs_f64();
        let end_sec = now.duration_since(origin).as_secs_f64().max(start_sec);
        let snap = IntervalSnapshot {
            stream_id: self.stream_id,
            start_sec,
            end_sec,
            bytes: self.bytes_in_interval,
        };
        self.bytes_in_interval = 0;
        Some(snap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_without_crossing_boundary_return_none() {
        let mut rep = IntervalReporter::new(1, Duration::from_secs(1));
        let t0 = Instant::now();
        assert!(rep.on_bytes(100, t0).is_none());
        assert!(rep.on_bytes(200, t0 + Duration::from_millis(500)).is_none());
    }

    #[test]
    fn crossing_boundary_emits_snapshot_with_accumulated_bytes() {
        let mut rep = IntervalReporter::new(1, Duration::from_secs(1));
        let t0 = Instant::now();
        assert!(rep.on_bytes(1_000, t0).is_none());
        let snap = rep
            .on_bytes(2_000, t0 + Duration::from_millis(1_000))
            .expect("snapshot at boundary");

        assert_eq!(snap.stream_id, 1);
        assert!((snap.start_sec - 0.0).abs() < 1e-9);
        assert!((snap.end_sec - 1.0).abs() < 1e-9);
        assert_eq!(snap.bytes, 3_000);
    }

    #[test]
    fn subsequent_boundaries_reset_counter() {
        let mut rep = IntervalReporter::new(7, Duration::from_secs(1));
        let t0 = Instant::now();
        rep.on_bytes(500, t0);
        let snap1 = rep
            .on_bytes(500, t0 + Duration::from_millis(1_000))
            .expect("snap1");
        assert_eq!(snap1.bytes, 1_000);

        let snap2 = rep
            .on_bytes(2_000, t0 + Duration::from_millis(2_050))
            .expect("snap2");
        assert_eq!(snap2.stream_id, 7);
        // Second interval reports bytes seen since the first boundary.
        assert_eq!(snap2.bytes, 2_000);
        assert!((snap2.start_sec - 1.0).abs() < 1e-9);
        assert!((snap2.end_sec - 2.0).abs() < 1e-9);
    }

    #[test]
    fn mbits_per_sec_matches_bytes_over_duration() {
        let snap = IntervalSnapshot {
            stream_id: 1,
            start_sec: 0.0,
            end_sec: 1.0,
            bytes: 125_000, // 1 Mbit
        };
        assert!((snap.mbits_per_sec() - 1.0).abs() < 1e-6);
    }

    #[test]
    fn flush_emits_remaining_partial_interval() {
        let mut rep = IntervalReporter::new(3, Duration::from_secs(1));
        let t0 = Instant::now();
        rep.on_bytes(500, t0);
        let snap = rep.flush(t0 + Duration::from_millis(250)).expect("flush");
        assert_eq!(snap.stream_id, 3);
        assert_eq!(snap.bytes, 500);
        assert!(snap.start_sec <= snap.end_sec);
    }

    #[test]
    fn flush_returns_none_when_nothing_observed() {
        let mut rep = IntervalReporter::new(1, Duration::from_secs(1));
        assert!(rep.flush(Instant::now()).is_none());
    }
}
