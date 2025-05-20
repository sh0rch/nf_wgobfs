use crate::cipher::randomiser::fill_ballast;
use crate::cipher::{randomiser, CipherImpl};
use crate::config::FilterConfig;
use crate::filter::keepalive::{KeepaliveDropper, PacketDecision};
use crate::netutils::{ipv4, ipv6};
use rand::rngs::SmallRng;
use rand::Rng;

const NONCE_LEN: usize = 12;
const MAC2_LEN: usize = 16;
const BALLAST_LEN_MAX: usize = 65;

pub fn obfuscate_wg_packet(
    buf: &mut [u8],
    len: usize,
    config: &FilterConfig,
    dropper: &mut KeepaliveDropper,
    rng: &mut SmallRng,
) -> Option<usize> {
    if len < 1 || len > config.mtu {
        return Some(len);
    }

    let ip_version = buf[0] >> 4;
    let wg_start = match ip_version {
        4 => ((buf[0] & 0x0F) as usize) * 4 + 8,
        6 => 48,
        _ => return Some(len),
    };

    if len < wg_start + 32 {
        println!(
            "Packet too small for obfuscation : len={} < wg_start({}) + 32",
            len, wg_start
        );
        return Some(len);
    }

    let wg_payload = &buf[wg_start..len];
    if matches!(dropper.filter_packet(wg_payload), PacketDecision::Drop) {
        return None;
    }

    let max_insert = config.mtu.saturating_sub(len);
    let max_ballast = max_insert
        .saturating_sub(1 + NONCE_LEN)
        .min(BALLAST_LEN_MAX);
    let ballast_len = if max_ballast >= 3 {
        rng.random_range(3..=max_ballast)
    } else {
        0
    };

    let new_len = len + 1 + ballast_len + NONCE_LEN;
    if new_len > buf.len() {
        return None;
    }

    let mut nonce = [0u8; NONCE_LEN];
    randomiser::fill_nonce(&mut nonce, rng);

    // Prepare block for encryption
    let mut block = [0u8; 33];
    block[..16].copy_from_slice(&buf[wg_start..wg_start + 16]);
    block[16] = ballast_len as u8;
    block[17..].copy_from_slice(&buf[len - MAC2_LEN..len]);

    let mut cipher = CipherImpl::new(&config.key, &nonce, &config.cipher_mode);
    cipher.xor(&mut block);

    buf[wg_start..wg_start + 16].copy_from_slice(&block[..16]);

    // Place ballast after MAC2
    let mut offset = len - MAC2_LEN;
    fill_ballast(&mut buf[offset..offset + ballast_len], rng);
    offset += ballast_len;

    // Place ballast length and encrypted MAC2
    buf[offset] = block[16];
    offset += 1;
    buf[offset..offset + MAC2_LEN].copy_from_slice(&block[17..]);
    offset += MAC2_LEN;

    // Place nonce at the end
    buf[offset..offset + NONCE_LEN].copy_from_slice(&nonce);
    offset += NONCE_LEN;

    if new_len != offset {
        return None;
    }

    match ip_version {
        4 => {
            ipv4::clear_diffserv(&mut buf[..new_len]);
            ipv4::fix_udp_headers(&mut buf[..new_len]);
        }
        6 => ipv6::fix_udp_headers(&mut buf[..new_len]),
        _ => {}
    }

    Some(new_len)
}

#[inline(always)]
pub fn deobfuscate_wg_packet(buf: &mut [u8], config: &FilterConfig) -> Option<usize> {
    let len = buf.len();
    if len < 1 {
        return Some(len);
    }

    let ip_version = buf[0] >> 4;
    let wg_start = match ip_version {
        4 => ((buf[0] & 0x0F) as usize) * 4 + 8,
        6 => 48,
        _ => return Some(len),
    };
    if len <= wg_start + 45 {
        return Some(len);
    }

    // Extract nonce from the end
    let nonce_offset = len - NONCE_LEN;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&buf[nonce_offset..len]);
    let mut cipher = CipherImpl::new(&config.key, &nonce, &config.cipher_mode);

    // Prepare block for decryption
    let offset = len - 1 - NONCE_LEN - MAC2_LEN;
    let mut block = [0u8; 33];
    block[..16].copy_from_slice(&buf[wg_start..wg_start + 16]);
    block[16..].copy_from_slice(&buf[offset..len - NONCE_LEN]);

    cipher.xor(&mut block);

    buf[wg_start..wg_start + 16].copy_from_slice(&block[..16]);
    let ballast_len = block[16] as usize;

    let min_len = ballast_len + 45;
    if len < min_len {
        return Some(len);
    }

    let new_len = len - 1 - ballast_len - NONCE_LEN;
    buf[new_len - MAC2_LEN..new_len].copy_from_slice(&block[17..]);

    match ip_version {
        4 => ipv4::fix_udp_headers(&mut buf[..new_len]),
        6 => ipv6::fix_udp_headers(&mut buf[..new_len]),
        _ => {}
    }

    Some(new_len)
}

#[cfg(test)]
mod tests {
    use crate::config::{ascii_to_key, CipherMode, Direction, FilterConfig};

    use super::*;
    use rand::rngs::SmallRng;
    use rand::SeedableRng;

    #[test]
    fn test_obfuscate_and_deobfuscate() {
        // Provided input data
        let before: [u8; 156] = [
            0x45, 0x00, 0x00, 0x9c, 0x5e, 0x1c, 0x00, 0x00, 0x40, 0x11, 0x51, 0xf0, 0xd5, 0xa5,
            0x54, 0x5d, 0x59, 0xdf, 0x46, 0x63, 0xca, 0x6c, 0xca, 0x6c, 0x00, 0x88, 0x50, 0x44,
            0x04, 0x00, 0x00, 0x00, 0x99, 0x65, 0x38, 0xec, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x61, 0x05, 0x7b, 0x7f, 0x1f, 0xc8, 0x19, 0x2b, 0x8e, 0xa2, 0xd7, 0x7a,
            0xd0, 0x74, 0xfa, 0x2d, 0x0f, 0x8d, 0x1b, 0xf7, 0x30, 0x0d, 0xef, 0xfa, 0xa5, 0x9d,
            0x0a, 0xc4, 0x8b, 0xf4, 0x00, 0xec, 0x28, 0xff, 0x83, 0x64, 0x75, 0xad, 0x54, 0xc8,
            0x1c, 0x3f, 0x16, 0xc7, 0xcf, 0x8c, 0xbb, 0x7e, 0x27, 0xcd, 0x65, 0x66, 0x08, 0x3f,
            0x2b, 0x65, 0xda, 0xb3, 0x67, 0xaa, 0x7c, 0xde, 0xc9, 0xf7, 0x53, 0x3e, 0x37, 0xa2,
            0x58, 0x6d, 0x97, 0x59, 0x56, 0xfe, 0xfb, 0xa9, 0x95, 0x60, 0x00, 0x80, 0x10, 0x2f,
            0xb1, 0x94, 0xf0, 0xc1, 0x5d, 0x2b, 0xfd, 0x84, 0x0f, 0xf9, 0x99, 0x7f, 0x27, 0xb7,
            0x51, 0x1d, 0xe1, 0xe7, 0x00, 0x95, 0x4c, 0xe4, 0x27, 0xd9, 0x46, 0x2c, 0xdf, 0xda,
            0xff, 0x35,
        ];

        // Dummy config and dropper
        let mut config = FilterConfig {
            mtu: 256,
            key: [0u8; 32],
            cipher_mode: CipherMode::Auto,
            queue_num: 0,
            direction: Direction::Out,
            name: String::new(),
        };
        let mut dropper = KeepaliveDropper::new(0, 9);
        let mut rng = SmallRng::from_seed([0u8; 32]);

        // Copy input to a buffer with extra space
        let mut buf = [0u8; 256];
        buf[..before.len()].copy_from_slice(&before);
        config.direction = Direction::Out;
        config.cipher_mode = CipherMode::Auto;
        config.key = ascii_to_key("secretkey");
        // Obfuscate
        let obf_len = obfuscate_wg_packet(&mut buf, before.len(), &config, &mut dropper, &mut rng)
            .expect("obfuscation failed");

        // Deobfuscate;
        config.direction = Direction::In;
        config.cipher_mode = CipherMode::Auto;
        let deobf_len =
            deobfuscate_wg_packet(&mut buf[..obf_len], &config).expect("deobfuscation failed");

        // Check roundtrip
        assert_eq!(&buf[..deobf_len], &before[..], "deobfuscated != original");
    }
}
