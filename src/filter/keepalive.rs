use rand::{rngs::SmallRng, Rng};
use std::time::{Duration, Instant};

#[derive(Debug, PartialEq, Eq)]
pub enum PacketDecision {
    Allow,
    Drop,
}

/// Drops keepalive packets with a given probability, but always drops them if there was data in the last 30 seconds.
pub struct KeepaliveDropper {
    last_data_time: Instant,
    drop_percent: u8, // 0..=100
}

impl KeepaliveDropper {
    pub fn new(drop_percent: u8) -> Self {
        Self { last_data_time: Instant::now(), drop_percent: drop_percent.min(100) }
    }

    /// Returns Allow for data packets, and Drop/Allow for keepalive packets according to policy.
    /// If there was data in the last 30 seconds, always drops keepalive.
    /// Otherwise, drops keepalive with probability `drop_percent`.
    pub fn filter_packet(&mut self, packet: &u8, len: usize, rng: &mut SmallRng) -> PacketDecision {
        let now = Instant::now();

        if len > 32 || *packet != 0x04 {
            self.last_data_time = now;
            return PacketDecision::Allow;
        }

        if now.duration_since(self.last_data_time) < Duration::from_secs(30) {
            return PacketDecision::Drop;
        }

        if rng.random_range(0..100) < self.drop_percent as u32 {
            PacketDecision::Drop
        } else {
            PacketDecision::Allow
        }
    }
}
