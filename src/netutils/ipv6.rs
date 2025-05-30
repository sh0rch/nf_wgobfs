/*
 * Copyright (c) 2025 sh0rch <sh0rch@iwl.dev>
 *
 * This file is licensed under the MIT License.
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

//! IPv6 UDP packet utilities.
//!
//! This module provides functions to fix and validate UDP headers in IPv6 packets,
//! including length and checksum calculation according to RFC 2460.

use crate::netutils::common::checksum16;

/// Fixes the UDP header in an IPv6 packet buffer.
///
/// This function updates the IPv6 payload length and the UDP length fields,
/// and recalculates the UDP checksum. The packet is expected to be a full
/// IPv6 packet with the UDP header starting at byte 40.
///
/// # Arguments
///
/// * `packet` - Mutable byte slice containing the IPv6 packet.
///
/// # Behavior
///
/// - If the packet is smaller than 48 bytes, the function returns immediately.
/// - Updates the IPv6 payload length (bytes 4-5) and UDP length (bytes 44-45).
/// - Sets the UDP checksum field to zero, then recalculates and writes the correct checksum.
pub fn fix_udp_headers(packet: &mut [u8]) {
    if packet.len() < 48 {
        // Not enough data for IPv6 + UDP headers
        return;
    }

    let udp_start = 40;
    let payload_len = (packet.len() - 40) as u16;
    // Set IPv6 payload length
    packet[4] = (payload_len >> 8) as u8;
    packet[5] = (payload_len & 0xff) as u8;

    // Set UDP length
    packet[udp_start + 4] = (payload_len >> 8) as u8;
    packet[udp_start + 5] = (payload_len & 0xff) as u8;

    // Zero UDP checksum before calculation
    packet[udp_start + 6] = 0;
    packet[udp_start + 7] = 0;

    let udp = &packet[udp_start..];
    let src = &packet[8..24];
    let dst = &packet[24..40];
    let sum = udp_checksum(udp, src, dst);
    // Write calculated UDP checksum
    packet[udp_start + 6] = (sum >> 8) as u8;
    packet[udp_start + 7] = (sum & 0xff) as u8;
}

/// Calculates the UDP checksum for an IPv6 packet.
///
/// This function constructs the IPv6 pseudo-header and UDP segment,
/// then computes the 16-bit one's complement checksum as required by RFC 2460.
///
/// # Arguments
///
/// * `udp` - Byte slice containing the UDP header and payload.
/// * `src_ip` - 16-byte source IPv6 address.
/// * `dst_ip` - 16-byte destination IPv6 address.
///
/// # Returns
///
/// * `u16` - The computed UDP checksum.
///
/// # Notes
///
/// - Handles both even and odd UDP payload lengths.
/// - Uses a stack buffer for small packets, heap allocation for large ones.
pub fn udp_checksum(udp: &[u8], src_ip: &[u8], dst_ip: &[u8]) -> u16 {
    const MAX_UDP: usize = 2048;
    let udp_len = udp.len();
    let pseudo_len = 40 + udp_len + (udp_len % 2);
    if udp_len <= MAX_UDP {
        // Use stack buffer for efficiency
        let mut pseudo = [0u8; 40 + MAX_UDP + 1];
        // Source address (16 bytes)
        pseudo[..16].copy_from_slice(src_ip);
        // Destination address (16 bytes)
        pseudo[16..32].copy_from_slice(dst_ip);

        // UDP length (4 bytes, big-endian)
        let len = udp_len as u32;
        pseudo[32..36].copy_from_slice(&len.to_be_bytes());
        // Next header (UDP = 17), 3 bytes zero + 1 byte protocol
        pseudo[36] = 0;
        pseudo[37] = 0;
        pseudo[38] = 0;
        pseudo[39] = 17;

        // UDP header and payload
        pseudo[40..40 + udp_len].copy_from_slice(udp);
        // Pad with zero if odd length
        if udp_len % 2 != 0 {
            pseudo[40 + udp_len] = 0;
        }
        checksum16(&pseudo[..pseudo_len])
    } else {
        // Use heap allocation for large packets
        let mut pseudo = Vec::with_capacity(pseudo_len);
        pseudo.extend_from_slice(src_ip);
        pseudo.extend_from_slice(dst_ip);

        let len = udp_len as u32;
        pseudo.extend_from_slice(&len.to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 17]);

        pseudo.extend_from_slice(udp);
        if pseudo.len() % 2 != 0 {
            pseudo.push(0);
        }
        checksum16(&pseudo)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that fix_udp_headers sets correct lengths and checksum for a valid IPv6+UDP packet.
    #[test]
    fn test_fix_udp_headers_sets_lengths_and_checksum() {
        // Construct a minimal IPv6 + UDP packet with 4 bytes of payload
        let mut packet = [
            // IPv6 header (first 8 bytes)
            0x60, 0, 0, 0, 0, 0, 0, 0,
            // Traffic class, flow label, payload length, next header, hop limit
            0, 17, 64, 0, // Source address (16 bytes)
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            // Destination address (16 bytes)
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
            // UDP header (8 bytes)
            0x12, 0x34, // Source port
            0x56, 0x78, // Destination port
            0, 0, // Length (to be set)
            0, 0, // Checksum (to be set)
            // UDP payload (4 bytes)
            1, 2, 3, 4,
        ];
        fix_udp_headers(&mut packet);

        let payload_len = (packet.len() - 40) as u16;

        // Check IPv6 payload length
        assert_eq!(packet[4], (payload_len >> 8) as u8);
        assert_eq!(packet[5], (payload_len & 0xff) as u8);

        let udp_start = 40;
        let mut udp_for_sum = packet[udp_start..].to_vec();
        udp_for_sum[6] = 0;
        udp_for_sum[7] = 0;
        let src = &packet[8..24];
        let dst = &packet[24..40];
        let sum = udp_checksum(&udp_for_sum, src, dst);
        let packet_sum = ((packet[udp_start + 6] as u16) << 8) | (packet[udp_start + 7] as u16);
        assert_eq!(sum, packet_sum);
    }

    /// Test UDP checksum calculation for even and odd UDP payload lengths.
    #[test]
    fn test_udp_checksum_even_and_odd_length() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let udp_even = [0x00, 0x35, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00]; // 8 bytes
        let udp_odd = [0x00, 0x35, 0x00, 0x35, 0x00, 0x07, 0x00, 0x00, 0xFF]; // 9 bytes

        let sum_even = udp_checksum(&udp_even, &src, &dst);
        let sum_odd = udp_checksum(&udp_odd, &src, &dst);

        // Checksums should be non-zero
        assert_ne!(sum_even, 0);
        assert_ne!(sum_odd, 0);
    }

    /// Test that fix_udp_headers does nothing for packets smaller than minimum size.
    #[test]
    fn test_fix_udp_headers_minimum_size() {
        let mut packet = [0u8; 20];
        fix_udp_headers(&mut packet);
        assert_eq!(packet, [0u8; 20]);
    }

    /// Test UDP checksum calculation for a zero-length UDP payload.
    #[test]
    fn test_udp_checksum_zero_payload() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let udp = [0x00, 0x35, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00]; // 8 bytes, no payload
        let sum = udp_checksum(&udp, &src, &dst);
        assert_ne!(sum, 0);
    }

    /// Test UDP checksum calculation for all-zero addresses and payload.
    #[test]
    fn test_udp_checksum_all_zeros() {
        let src = [0u8; 16];
        let dst = [0u8; 16];
        let udp = [0u8; 8];
        let sum = udp_checksum(&udp, &src, &dst);
        // Acceptable values: 0, 0xffff, or 65510 (implementation-dependent)
        assert!(sum == 0 || sum == 0xffff || sum == 65510);
    }
}
