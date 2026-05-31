//! RFC 1889 jitter EWMA. Pure function so callers own all state.
//!
//! For each packet after the first, compute
//!     D = (R_j - R_i) - (S_j - S_i)
//! where R is local receive time and S is sender-stamped send time (both
//! in the same unit, e.g. milliseconds). Then update:
//!     J = J + (|D| - J) / 16

pub fn update(prev_jitter: f64, d: f64) -> f64 {
    prev_jitter + (d.abs() - prev_jitter) / 16.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_d_leaves_jitter_unchanged() {
        assert_eq!(update(5.0, 0.0), 5.0 - 5.0 / 16.0);
    }

    #[test]
    fn converges_to_d_under_constant_input() {
        let mut j = 0.0;
        for _ in 0..200 {
            j = update(j, 10.0);
        }
        assert!((j - 10.0).abs() < 0.01, "did not converge: {}", j);
    }

    #[test]
    fn absolute_value_is_used() {
        let pos = update(1.0, 5.0);
        let neg = update(1.0, -5.0);
        assert_eq!(pos, neg);
    }

    #[test]
    fn starting_from_zero_moves_toward_d() {
        let j = update(0.0, 16.0);
        assert_eq!(j, 1.0);
    }
}
