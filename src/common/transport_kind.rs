//! Which transport a rPerf3 test uses for its data streams. Control
//! channel is always TCP.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportKind {
    #[default]
    Tcp,
    Udp,
}

impl TransportKind {
    pub fn is_udp(self) -> bool {
        matches!(self, Self::Udp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_tcp() {
        assert_eq!(TransportKind::default(), TransportKind::Tcp);
    }

    #[test]
    fn is_udp_true_only_for_udp() {
        assert!(!TransportKind::Tcp.is_udp());
        assert!(TransportKind::Udp.is_udp());
    }
}
