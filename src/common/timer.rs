use std::time::{Duration, Instant};

/// Monotonic stopwatch used by the stream loop to decide when to stop
/// sending. Wraps `std::time::Instant` so callers have a small, testable
/// surface.
#[derive(Debug, Clone, Copy)]
pub struct Timer {
    start: Instant,
}

impl Timer {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    pub fn is_elapsed(&self, duration: Duration) -> bool {
        self.elapsed() >= duration
    }
}

impl Default for Timer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn elapsed_is_non_decreasing() {
        let timer = Timer::new();
        let a = timer.elapsed();
        sleep(Duration::from_millis(5));
        let b = timer.elapsed();
        assert!(b >= a, "elapsed went backwards: {:?} -> {:?}", a, b);
    }

    #[test]
    fn is_elapsed_false_for_large_duration() {
        let timer = Timer::new();
        assert!(!timer.is_elapsed(Duration::from_secs(60)));
    }

    #[test]
    fn is_elapsed_true_after_wait() {
        let timer = Timer::new();
        sleep(Duration::from_millis(20));
        assert!(timer.is_elapsed(Duration::from_millis(5)));
    }
}
