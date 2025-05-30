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

//! Randomiser module for generating pseudo-random numbers and filling buffers with random data.
//!
//! This module provides utility functions for creating a seeded random number generator
//! and filling byte buffers with random data. The seeding process combines system time,
//! process ID, and additional entropy to improve unpredictability.

use rand::rngs::SmallRng;
use rand::{RngCore, SeedableRng};
use std::time::{SystemTime, UNIX_EPOCH};

/// Creates a new instance of `SmallRng` seeded with a combination of system time,
/// process ID, and additional random noise.
///
/// # Returns
/// A `SmallRng` random number generator seeded for improved unpredictability.
///
/// # Example
/// ```
/// let mut rng = create_secure_rng();
/// ```
pub fn create_secure_rng() -> SmallRng {
    // Get the current time in microseconds since UNIX_EPOCH.
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_micros() as u64;

    // Get the current process ID.
    let pid = std::process::id() as u64;

    // Generate additional random noise using fastrand.
    let noise = fastrand::u64(..);

    // Combine all entropy sources using bitwise operations to form the seed.
    let seed = now ^ pid.rotate_left(13) ^ noise.rotate_right(7);
    SmallRng::seed_from_u64(seed)
}

/// Fills the given buffer with random bytes using the provided random number generator.
///
/// # Arguments
/// * `buf` - The mutable byte slice to fill with random data.
/// * `rng` - A mutable reference to an object implementing `RngCore`.
///
/// # Example
/// ```
/// let mut buf = [0u8; 16];
/// let mut rng = create_secure_rng();
/// fill_random(&mut buf, &mut rng);
/// ```
#[inline(always)]
pub fn fill_random(buf: &mut [u8], rng: &mut impl RngCore) {
    rng.fill_bytes(buf);
}
