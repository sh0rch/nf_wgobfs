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

//! Common network utility functions.
//!
//! This module provides utility functions for network programming,
//! including a function to compute the 16-bit one's complement checksum,
//! commonly used in network protocols such as IP, TCP, and UDP.

/// Computes the 16-bit one's complement checksum for the given data slice.
///
/// This function processes the input byte slice in 16-bit words (big-endian order),
/// summing them up and folding any overflow bits back into the sum.
/// If the input has an odd number of bytes, the last byte is padded with zero
/// in the least significant position. The final result is the one's complement
/// of the accumulated sum. If the result is zero, 0xffff is returned instead,
/// as per common network protocol conventions.
///
/// # Arguments
///
/// * `data` - A byte slice containing the data to checksum.
///
/// # Returns
///
/// * `u16` - The computed 16-bit one's complement checksum.
///
/// # Examples
///
/// ```
/// let data = [0x01u8, 0x02, 0x03, 0x04];
/// let checksum = checksum16(&data);
/// ```
#[inline(always)]
pub fn checksum16(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let len = data.len();
    let mut i = 0;
    // Process all 16-bit words
    while i + 1 < len {
        // Combine two bytes into a 16-bit word (big-endian)
        let word = u16::from_be_bytes([data[i], data[i + 1]]);
        sum += word as u32;
        i += 2;
    }
    // If there's a leftover byte, pad with zero and add
    if i < len {
        sum += (data[i] as u32) << 8;
    }
    // Fold any carries from the upper 16 bits into the lower 16 bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    // One's complement and handle special case for zero result
    let result = !(sum as u16);
    if result == 0 {
        0xffff
    } else {
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test checksum16 with an even number of bytes.
    #[test]
    fn test_checksum16_even_bytes() {
        let data = [0x01u8, 0x02, 0x03, 0x04];
        assert_eq!(checksum16(&data), 0xfbf9);
    }

    /// Test checksum16 with an odd number of bytes.
    #[test]
    fn test_checksum16_odd_bytes() {
        let data = [0x01u8, 0x02, 0x03];
        assert_eq!(checksum16(&data), 0xfbfd);
    }

    /// Test checksum16 with an empty slice.
    #[test]
    fn test_checksum16_empty() {
        let data: [u8; 0] = [];
        assert_eq!(checksum16(&data), 0xffff);
    }

    /// Test checksum16 with all zero bytes.
    #[test]
    fn test_checksum16_all_zeros() {
        let data = [0u8; 8];
        assert_eq!(checksum16(&data), 0xffff);
    }

    /// Test that checksum16 produces consistent results for the same input.
    #[test]
    fn test_checksum16_big_endian_consistency() {
        let data = [0x12u8, 0x34, 0x56, 0x78];
        assert_eq!(checksum16(&data), checksum16(&data));
    }
}
