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

//! IPv4 and UDP packet utilities.
//!
//! This module provides functions for manipulating IPv4 and UDP packet headers,
//! including clearing the DiffServ field, fixing header fields, and calculating UDP checksums.

use crate::netutils::common::checksum16;

/// Clears the DiffServ (DSCP) bits in the IPv4 header, preserving only the ECN bits.
///
/// # Arguments
/// * `packet` - Mutable reference to the IPv4 packet bytes.
///
/// # Details
/// The DiffServ field is located in the second byte of the IPv4 header.
/// This function sets the upper 6 bits to zero, leaving only the ECN (lowest 2 bits).
#[inline(always)]
pub fn clear_diffserv(packet: &mut [u8]) {
    if packet.len() >= 20 {
        let ecn = packet[1] & 0x03;
        packet[1] = ecn;
    }
}

/// Fixes the IPv4 and UDP header fields in a packet buffer.
///
/// This function updates the IPv4 total length, recalculates the IPv4 header checksum,
/// sets the UDP length, and recalculates the UDP checksum.
///
/// # Arguments
/// * `packet` - Mutable reference to the full IPv4+UDP packet bytes.
///
/// # Details
/// - Assumes the packet starts with an IPv4 header.
/// - The function does nothing if the packet is too short or malformed.
#[inline(always)]
pub fn fix_udp_headers(packet: &mut [u8]) {
    if packet.len() < 20 {
        return;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || ihl + 8 > packet.len() {
        return;
    }
    // Set IPv4 total length field
    let total_len = packet.len() as u16;
    packet[2] = (total_len >> 8) as u8;
    packet[3] = (total_len & 0xff) as u8;

    // Zero IPv4 header checksum before recalculation
    packet[10] = 0;
    packet[11] = 0;
    let csum = checksum16(&packet[..ihl]);
    packet[10] = (csum >> 8) as u8;
    packet[11] = (csum & 0xff) as u8;

    // Set UDP length field
    let udp_len = (packet.len() - ihl) as u16;
    packet[ihl + 4] = (udp_len >> 8) as u8;
    packet[ihl + 5] = (udp_len & 0xff) as u8;

    // Zero UDP checksum before recalculation
    packet[ihl + 6] = 0;
    packet[ihl + 7] = 0;
    let udp = &packet[ihl..];
    let src = &packet[12..16];
    let dst = &packet[16..20];
    let sum = udp_checksum(udp, src, dst);
    packet[ihl + 6] = (sum >> 8) as u8;
    packet[ihl + 7] = (sum & 0xff) as u8;
}

/// Calculates the UDP checksum for a given UDP segment and IPv4 addresses.
///
/// # Arguments
/// * `udp`    - UDP segment bytes (header + payload)
/// * `src_ip` - Source IPv4 address (4 bytes)
/// * `dst_ip` - Destination IPv4 address (4 bytes)
///
/// # Returns
/// * `u16` - The computed UDP checksum value.
///
/// # Details
/// The function constructs a pseudo-header as required by the UDP checksum algorithm.
/// If the UDP segment is small, a stack buffer is used for efficiency; otherwise, a heap buffer is allocated.
pub fn udp_checksum(udp: &[u8], src_ip: &[u8], dst_ip: &[u8]) -> u16 {
    const MAX_UDP: usize = 2048;
    let udp_len = udp.len();
    let pseudo_len = 12 + udp_len + (udp_len % 2);
    if udp_len <= MAX_UDP {
        // Use stack buffer for small UDP segments
        let mut pseudo = [0u8; 12 + MAX_UDP + 1];
        pseudo[..4].copy_from_slice(src_ip);
        pseudo[4..8].copy_from_slice(dst_ip);
        pseudo[8] = 0;
        pseudo[9] = 17; // UDP protocol number
        pseudo[10] = (udp_len >> 8) as u8;
        pseudo[11] = (udp_len & 0xff) as u8;
        pseudo[12..12 + udp_len].copy_from_slice(udp);
        if udp_len % 2 != 0 {
            pseudo[12 + udp_len] = 0; // Pad to even length
        }
        checksum16(&pseudo[..pseudo_len])
    } else {
        // Use heap buffer for large UDP segments
        let mut pseudo = Vec::with_capacity(pseudo_len);
        pseudo.extend_from_slice(src_ip);
        pseudo.extend_from_slice(dst_ip);
        pseudo.push(0);
        pseudo.push(17);
        pseudo.push((udp_len >> 8) as u8);
        pseudo.push((udp_len & 0xff) as u8);
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

    /// Test clearing the DiffServ field in an IPv4 packet.
    #[test]
    fn test_clear_diffserv() {
        let mut packet = [
            0x45, 0x88, 0x00, 0xb0, 0x2e, 0x41, 0x00, 0x00, 0x40, 0x11, 0x81, 0x2f, 0x59, 0xdf,
            0x46, 0x63, 0xd5, 0xa5, 0x54, 0x5d, 0xca, 0x6c, 0xca, 0x6c, 0x00, 0x9c, 0x7b, 0x52,
            0x01,
        ];
        clear_diffserv(&mut packet);
        assert_eq!(packet[1], 0x00);
    }

    /// Test fixing UDP headers and verifying UDP checksum calculation.
    #[test]
    fn test_fix_udp_headers_and_udp_checksum() {
        let mut packet = [
            // IPv4 header (20 bytes)
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 192, 168, 1, 1,
            192, 168, 1, 2, // UDP header (8 bytes)
            0x12, 0x34, 0x56, 0x78, 0x00, 0x0c, 0x00, 0x00, // UDP payload (4 bytes)
            1, 2, 3, 4,
        ];

        let ihl = ((packet[0] & 0x0f) as usize) * 4;
        fix_udp_headers(&mut packet);
        let udp = &packet[ihl..];
        let src = &packet[12..16];
        let dst = &packet[16..20];

        let mut udp_for_sum = udp.to_owned();
        udp_for_sum[6] = 0;
        udp_for_sum[7] = 0;

        let sum = udp_checksum(&udp_for_sum, src, dst);
        let packet_sum = ((packet[ihl + 6] as u16) << 8) | (packet[ihl + 7] as u16);

        assert_eq!(sum, packet_sum);
    }

    /// Test UDP checksum calculation for even and odd length UDP segments.
    #[test]
    fn test_udp_checksum_even_and_odd() {
        let src = [10, 0, 0, 1];
        let dst = [10, 0, 0, 2];
        let udp_even = [0x00, 0x35, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00]; // 8 bytes
        let udp_odd = [0x00, 0x35, 0x00, 0x35, 0x00, 0x07, 0x00, 0x00, 0xFF]; // 9 bytes

        let sum_even = udp_checksum(&udp_even, &src, &dst);
        let sum_odd = udp_checksum(&udp_odd, &src, &dst);

        assert_ne!(sum_even, 0);
        assert_ne!(sum_odd, 0);
    }
}
