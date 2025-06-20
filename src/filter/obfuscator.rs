/*
 * Copyright (c) 2025 sh0rch <sh0rch@iwl.dev>
 *
 * MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*!
 * # Obfuscator module for WireGuard packets
 *
 * This module provides functions to obfuscate and deobfuscate WireGuard packets
 * by encrypting selected fields and adding random ballast (padding), making traffic analysis
 * and fingerprinting more difficult.
 *
 * ## Main Functions
 * - [`obfuscate_wg_packet`]: Obfuscates a WireGuard packet in-place by encrypting selected fields,
 *   adding random ballast, and appending a nonce.
 * - [`deobfuscate_wg_packet`]: Reverses the obfuscation process, restoring the original packet.
 *
 * ## Usage
 * Use these functions to protect WireGuard packets from fingerprinting and traffic analysis
 * by making their structure less predictable.
 */

use crate::config::FilterConfig;
use crate::filter::keepalive::{KeepaliveDropper, PacketDecision};
use crate::netutils::{ipv4, ipv6};
use crate::randomiser::fill_random;
use fast_chacha::FastChaCha20;
use rand::rngs::SmallRng;
use rand::Rng;

const NONCE_LEN: usize = 12;
//const MAC2_LEN: usize = 16;
//const BALLAST_LEN_MAX: usize = 65;

/// Obfuscates a WireGuard packet in-place.
///
/// This function encrypts selected fields of the WireGuard packet, adds random
/// ballast (padding), and appends a nonce. It also updates UDP and IP headers as needed.
///
/// # Arguments
/// * `buf` - Mutable buffer containing the packet data.
/// * `len` - Length of the valid data in the buffer.
/// * `config` - Filter configuration, including the obfuscation key and MTU.
/// * `dropper` - KeepaliveDropper instance for filtering keepalive packets.
/// * `rng` - Random number generator.
///
/// # Returns
/// * `Some(new_len)` - The new length of the obfuscated packet.
/// * `None` - If the packet should be dropped or an error occurred.
///
/// # Details
/// - Encrypts the first 16 bytes of the WireGuard payload and the MAC2 field using ChaCha20.
/// - Inserts random ballast (padding) to make packet sizes less predictable.
/// - Appends a nonce for encryption.
/// - Updates UDP and IP headers to reflect the new packet size.
pub fn obfuscate_wg_packet(
    buf: &mut [u8],
    len: usize,
    config: &FilterConfig,
    dropper: &mut KeepaliveDropper,
    rng: &mut SmallRng,
) -> Option<usize> {
    // if len < 45 {
    //     return None;
    // }
    // if len > config.mtu {
    //     return None;
    // }

    // Determine IP version and calculate start of WireGuard payload
    let ip_version = buf[0] >> 4;
    let wg_start = match ip_version {
        4 => ((buf[0] & 0x0F) as usize) * 4 + 8,
        6 => 48,
        _ => return None,
    };

    if matches!(dropper.filter_packet(&buf[wg_start], len - wg_start, rng), PacketDecision::Drop) {
        // Drop keepalive packet
        return None;
    }

    // Calculate how much random ballast can be inserted
    let max_insert = config.mtu - len - 13;
    // if max_insert > 255
    let max_ballast = if max_insert < 255 { max_insert } else { 255 };
    let ballast_len = if max_insert >= 1 { rng.random_range(1..max_ballast) } else { 0 };

    let new_len = len + NONCE_LEN + ballast_len + 1;
    if new_len > buf.len() {
        return None;
    }

    // Generate random nonce

    // Prepare block for encryption: first 16 bytes of payload, ballast length, MAC2
    let mut offset = len + ballast_len;
    fill_random(&mut buf[len..new_len], rng);

    // let mut nonce = [0u8; NONCE_LEN];
    // fill_random(&mut nonce, rng);

    buf[offset] = ballast_len as u8;
    offset += 1;

    // Encrypt block with ChaCha20
    let mut cipher = FastChaCha20::new(
        &config.key,
        (&buf[offset..new_len]).try_into().expect("nonce slice has incorrect length"),
    );
    let crypt = if offset - wg_start > 192 { wg_start + 192 } else { offset };
    cipher.apply_keystream(&mut buf[wg_start..crypt]);
    //buf[offset..new_len].copy_from_slice(&nonce);

    //cipher.apply_keystream(&mut buf[wg_start..len]);
    //buf[len..new_len].copy_from_slice(&nonce);
    // Fix headers to reflect new packet size
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

/// Deobfuscates a previously obfuscated WireGuard packet in-place.
///
/// This function reverses the obfuscation process, decrypting the selected fields,
/// removing the ballast and nonce, and restoring the original packet structure.
///
/// # Arguments
/// * `buf` - Mutable buffer containing the obfuscated packet data.
/// * `config` - Filter configuration, including the obfuscation key.
///
/// # Returns
/// * `Some(new_len)` - The new length of the deobfuscated packet.
/// * `None` - If an error occurred.
///
/// # Details
/// - Extracts and decrypts the encrypted fields using the nonce and key.
/// - Removes the random ballast and nonce.
/// - Restores the original MAC2 field and packet structure.
/// - Fixes UDP and IP headers to match the restored packet.
#[inline(always)]
pub fn deobfuscate_wg_packet(buf: &mut [u8], len: usize, config: &FilterConfig) -> Option<usize> {
    if len < 1 {
        return None;
    }

    // Determine IP version and calculate start of WireGuard payload
    let ip_version = buf[0] >> 4;
    let wg_start = match ip_version {
        4 => ((buf[0] & 0x0F) as usize) * 4 + 8,
        6 => 48,
        _ => return None,
    };
    // Ensure packet is large enough for deobfuscation
    // if len <= wg_start + 32 {
    //     return None;
    // }

    // Extract nonce from the end of the packet
    let mut offset = len - NONCE_LEN;
    let mut cipher = FastChaCha20::new(
        &config.key,
        (&buf[offset..len]).try_into().expect("nonce slice has incorrect length"),
    );

    // Decrypt block
    let crypt = if offset - wg_start > 192 { wg_start + 192 } else { offset };
    cipher.apply_keystream(&mut buf[wg_start..crypt]);

    offset -= 1;
    let ballast_len = buf[offset] as usize;
    offset -= ballast_len; // Remove ballast bytes

    // Fix UDP and IP headers as needed

    match ip_version {
        4 => ipv4::fix_udp_headers(&mut buf[..offset]),
        6 => ipv6::fix_udp_headers(&mut buf[..offset]),
        _ => return None,
    }

    Some(offset)
}

#[cfg(test)]
mod tests {
    //use std::vec;

    use crate::config::{ascii_to_key, FilterConfig};

    use super::*;
    use rand::rngs::SmallRng;
    use rand::SeedableRng;

    /// Tests obfuscation and deobfuscation round-trip for a sample packet.
    ///
    /// This test ensures that after obfuscating and then deobfuscating a packet,
    /// the result matches the original input.
    #[test]
    fn test_obfuscate_and_deobfuscate() {
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

        let mut config =
            FilterConfig { mtu: 256, key: [0u8; 32], queue_num: 0, queue_len: Some(1024) };
        let mut dropper = KeepaliveDropper::new(80);
        let mut rng = SmallRng::from_seed([0u8; 32]);

        let mut buf = [0u8; 256];
        buf[..before.len()].copy_from_slice(&before);

        // Obfuscate the packet
        config.key = ascii_to_key("secretkey");
        let obf_len =
            obfuscate_wg_packet(&mut buf, before.len(), &config, &mut dropper, &mut rng).unwrap();
        //buf.truncate(obf_len);
        assert!(obf_len > before.len(), "obfuscated packet length should be greater than original");
        assert!(obf_len <= buf.len(), "obfuscated packet length should not exceed buffer size");
        let deobf_len = deobfuscate_wg_packet(&mut buf, obf_len, &config).unwrap();

        println!(
            "obfuscated length: {}, deobfuscated length: {}, original length: {}",
            obf_len,
            deobf_len,
            before.len()
        );
        assert!(
            deobf_len <= obf_len,
            "deobfuscated packet length should not exceed original length"
        );
        assert!(
            deobf_len >= before.len() - 1,
            "deobfuscated packet length should be at least original length minus nonce"
        );

        assert_eq!(&buf[..deobf_len], &before, "deobfuscated != original");
    }
}
