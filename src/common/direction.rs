//! Data-path direction for a test. Control channel is always client-initiated.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Direction {
    #[default]
    Forward,
    Reverse,
    Bidirectional,
}

impl Direction {
    pub fn is_reverse(self) -> bool {
        matches!(self, Self::Reverse)
    }
    pub fn is_bidirectional(self) -> bool {
        matches!(self, Self::Bidirectional)
    }
    pub fn client_sends(self) -> bool {
        matches!(self, Self::Forward | Self::Bidirectional)
    }
    pub fn client_receives(self) -> bool {
        matches!(self, Self::Reverse | Self::Bidirectional)
    }
    pub fn server_sends(self) -> bool {
        matches!(self, Self::Reverse | Self::Bidirectional)
    }
    pub fn server_receives(self) -> bool {
        matches!(self, Self::Forward | Self::Bidirectional)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_forward() {
        assert_eq!(Direction::default(), Direction::Forward);
    }

    #[test]
    fn forward_client_sends_server_receives() {
        assert!(Direction::Forward.client_sends());
        assert!(!Direction::Forward.client_receives());
        assert!(!Direction::Forward.server_sends());
        assert!(Direction::Forward.server_receives());
    }

    #[test]
    fn reverse_swaps_roles() {
        assert!(!Direction::Reverse.client_sends());
        assert!(Direction::Reverse.client_receives());
        assert!(Direction::Reverse.server_sends());
        assert!(!Direction::Reverse.server_receives());
    }

    #[test]
    fn bidirectional_both_sides_send_and_receive() {
        assert!(Direction::Bidirectional.client_sends());
        assert!(Direction::Bidirectional.client_receives());
        assert!(Direction::Bidirectional.server_sends());
        assert!(Direction::Bidirectional.server_receives());
    }
}
