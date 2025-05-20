use rand::rngs::SmallRng;
use rand::{RngCore, SeedableRng};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn create_secure_rng() -> SmallRng {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    let pid = std::process::id() as u64;
    let noise = fastrand::u64(..);

    let seed = now ^ pid.rotate_left(13) ^ noise.rotate_right(7);

    SmallRng::seed_from_u64(seed)
}

#[inline(always)]
pub fn fill_nonce(nonce: &mut [u8; 12], rng: &mut impl RngCore) {
    rng.fill_bytes(nonce);
}

#[inline(always)]
pub fn fill_ballast(buf: &mut [u8], rng: &mut impl RngCore) {
    rng.fill_bytes(buf);
}
