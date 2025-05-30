use rand::{rng, Rng};
use std::ops::Range;
use std::time::{Duration, Instant};

#[derive(Debug, PartialEq, Eq)]
pub enum PacketDecision {
    Allow,
    Drop,
}

pub struct KeepaliveDropper {
    drop_left: u8,
    min: u8,
    max: u8,
    pending_until: Option<Instant>,
    delay_range: Range<u64>,
    last_data_time: Instant,
}

impl KeepaliveDropper {
    pub fn new(min: u8, max: u8) -> Self {
        Self {
            drop_left: 0,
            min: min.max(1),
            max: max.max(min.max(1)),
            pending_until: None,
            delay_range: 3000..10000,
            last_data_time: Instant::now(),
        }
    }

    pub fn filter_packet(&mut self, packet: &[u8]) -> PacketDecision {
        let now = Instant::now();

        if !is_keepalive(packet) {
            self.last_data_time = now;
            self.pending_until = None;
            self.reset();
            return PacketDecision::Allow;
        }

        if self.drop_left > 0 {
            self.drop_left -= 1;
            return PacketDecision::Drop;
        }

        if self.pending_until.is_none() {
            let delay = rng().random_range(self.delay_range.clone());
            self.pending_until = Some(now + Duration::from_millis(delay));
            self.drop_left = rng().random_range(self.min..=self.max);
            return PacketDecision::Drop;
        }

        if let Some(when) = self.pending_until {
            if now >= when {
                self.pending_until = None;
                return PacketDecision::Allow;
            }
        }

        PacketDecision::Drop
    }

    pub fn reset(&mut self) {
        self.drop_left = 0;
    }
}

#[inline]
pub fn is_keepalive(packet: &[u8]) -> bool {
    !packet.is_empty() && packet.len() <= 32 && packet[0] == 0x04
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_keepalive_true() {
        let pkt = [0x04, 0, 0, 0];
        assert!(is_keepalive(&pkt));
        let pkt = [0x04];
        assert!(is_keepalive(&pkt));
        let pkt = [0x04; 32];
        assert!(is_keepalive(&pkt));
    }

    #[test]
    fn test_is_keepalive_false() {
        let pkt = [0x01, 0, 0, 0];
        assert!(!is_keepalive(&pkt));
        let pkt = [0x04; 33];
        assert!(!is_keepalive(&pkt));
        let pkt: [u8; 0] = [];
        assert!(!is_keepalive(&pkt));
    }

    #[test]
    fn test_dropper_allows_non_keepalive() {
        let mut dropper = KeepaliveDropper::new(1, 2);
        let pkt = [0x01, 0, 0, 0];
        assert_eq!(dropper.filter_packet(&pkt), PacketDecision::Allow);
    }

    #[test]
    fn test_dropper_resets_on_non_keepalive() {
        let mut dropper = KeepaliveDropper::new(1, 2);
        let keepalive = [0x04, 0, 0, 0];

        dropper.drop_left = 2;
        dropper.filter_packet(&keepalive);
        let non_keepalive = [0x01, 0, 0, 0];
        assert_eq!(dropper.filter_packet(&non_keepalive), PacketDecision::Allow);
        assert_eq!(dropper.drop_left, 0);
    }

    #[test]
    fn test_dropper_drop_and_allow() {
        let mut dropper = KeepaliveDropper::new(1, 1);
        let keepalive = [0x04, 0, 0, 0];

        let res1 = dropper.filter_packet(&keepalive);
        assert_eq!(res1, PacketDecision::Drop);

        let res2 = dropper.filter_packet(&keepalive);

        assert!(matches!(res2, PacketDecision::Drop | PacketDecision::Allow));
    }
}
