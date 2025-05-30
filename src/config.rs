/*
 * Copyright (c) 2025 sh0rch <sh0rch@iwl.dev>
 * SPDX-License-Identifier: MIT
 *
 * This module provides configuration parsing and management for the nf_wgobfs application.
 * It defines the configuration structures, parsing logic, and utility functions for
 * handling filter rules, including queue numbers, directions, interface names, keys, and MTU.
 */

use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::BufRead;

/// Represents the direction of the filter rule (incoming or outgoing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    In,
    Out,
}

/// Holds the configuration for a single filter rule.
#[derive(Clone)]
pub struct FilterConfig {
    /// Netfilter queue number.
    pub queue_num: u16,
    /// Direction of the filter (inbound or outbound).
    pub direction: Direction,
    /// 32-byte key derived from ASCII input.
    pub key: [u8; 32],
    /// Maximum Transmission Unit for this rule.
    pub mtu: usize,
}

/// Checks if the current process is running as root by reading /proc/self/status.
/// Returns true if UID is 0, false otherwise.
fn is_root() -> bool {
    match fs::read_to_string("/proc/self/status") {
        Ok(status) => status
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .map(|uid| uid == "0")
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// Converts an ASCII string to a 32-byte key using SHA-256 hash.
/// Returns the resulting 32-byte array.
pub fn ascii_to_key(s: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Loads the filter configuration from the default path or from the NF_WGOBFS_CONF environment variable.
/// Exits the process if not run as root. Returns a vector of FilterConfig on success.
pub(crate) fn load_config() -> std::io::Result<Vec<FilterConfig>> {
    if !is_root() {
        eprintln!("This program must be run as root.");
        std::process::exit(1);
    }
    let default_path = "/etc/nf_wgobfs/config";
    let config_path = match std::path::Path::new(default_path).exists() {
        true => default_path.to_string(),
        false => env::var("NF_WGOBFS_CONF").map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Config not found: {} and NF_WGOBFS_CONF not set.", default_path),
            )
        })?,
    };

    let file = fs::File::open(&config_path)?;
    let reader = std::io::BufReader::new(file);
    let lines = reader
        .lines()
        .map_while(Result::ok)
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect::<Vec<_>>();
    parse_config(&lines)
}

/// Parses a list of configuration lines into a vector of FilterConfig.
/// Each line should be in the format: queue_num:direction:name:key\[:mtu\]
/// Returns an error if the format is invalid or if there are duplicate queue numbers.
pub fn parse_config(input: &[String]) -> std::io::Result<Vec<FilterConfig>> {
    let mut configs = Vec::with_capacity(input.len());
    let mut seen_queues = HashSet::with_capacity(input.len());
    for line in input {
        let mut parts = line.split(':');
        let queue_num = parts
            .next()
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or(std::io::ErrorKind::InvalidData)?;
        if !seen_queues.insert(queue_num) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Duplicate queue number",
            ));
        }
        let direction = match parts.next().map(|s| s.to_lowercase()) {
            Some(ref s) if s == "in" => Direction::In,
            Some(_) => Direction::Out,
            None => return Err(std::io::ErrorKind::InvalidData.into()),
        };
        let _name = parts.next().map(str::to_string).ok_or(std::io::ErrorKind::InvalidData)?;
        let key_ascii = parts.next().ok_or(std::io::ErrorKind::InvalidData)?;
        let key = ascii_to_key(key_ascii.trim());

        // MTU: if there is another field and it is a number, use it; otherwise, default to 1500
        let mtu = parts.next_back().and_then(|s| s.parse::<u16>().ok()).unwrap_or(1500) as usize;

        configs.push(FilterConfig { queue_num, direction, key, mtu });
    }
    Ok(configs)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests that ascii_to_key produces consistent results for the same input.
    #[test]
    fn test_ascii_to_key_consistency() {
        let key1 = ascii_to_key("testkey");
        let key2 = ascii_to_key("testkey");
        assert_eq!(key1, key2);
    }

    /// Tests that ascii_to_key produces different results for different inputs.
    #[test]
    fn test_ascii_to_key_differs() {
        let key1 = ascii_to_key("testkey1");
        let key2 = ascii_to_key("testkey2");
        assert_ne!(key1, key2);
    }

    /// Tests parsing a full config line with all fields present.
    #[test]
    fn test_parse_config_line_full() {
        let line = ["1:in:wg_in:abcdef0123456789abcdef0123456789:F:1350"];
        let line: Vec<String> = line.iter().map(|s| s.to_string()).collect();
        if let Ok(config) = parse_config(&line) {
            assert_eq!(config[0].queue_num, 1);
            assert_eq!(config[0].direction, Direction::In);
            assert_eq!(config[0].key, ascii_to_key("abcdef0123456789abcdef0123456789"));
            assert_eq!(config[0].mtu, 1350);
        } else {
            panic!("Failed to parse config line");
        }
    }

    /// Tests parsing multiple config lines, including default MTU handling.
    #[test]
    fn test_parse_config_line_full_and_defaults() {
        let lines = [
            "0:out:wg_out:abcdef6760123456789abcdef0123456789:1350",
            "1:in:wg_in:fjklabcdef0123456789abcdef0123456789",
            "2:in:wg_in:mnopf0123456789abcdef0123456789",
            "3:in:wg_in:mnopf0123456789abcdef0123456789",
        ];
        let lines: Vec<String> = lines.iter().map(|s| s.to_string()).collect();
        if let Ok(configs) = parse_config(&lines) {
            assert_eq!(configs[0].queue_num, 0);
            assert_eq!(configs[0].direction, Direction::Out);
            assert_eq!(configs[0].key, ascii_to_key("abcdef6760123456789abcdef0123456789"));
            assert_eq!(configs[0].mtu, 1350);

            assert_eq!(configs[1].queue_num, 1);
            assert_eq!(configs[1].direction, Direction::In);
            assert_eq!(configs[1].key, ascii_to_key("fjklabcdef0123456789abcdef0123456789"));
            assert_eq!(configs[1].mtu, 1500); // Default MTU
            assert_eq!(configs[2].queue_num, 2);
            assert_eq!(configs[2].direction, Direction::In);
            assert_eq!(configs[2].key, ascii_to_key("mnopf0123456789abcdef0123456789"));
            assert_eq!(configs[2].mtu, 1500); // Default MTU
        } else {
            panic!("Failed to parse config lines");
        }
    }

    /// Tests that duplicate queue numbers in the config cause an error.
    #[test]
    fn test_parse_config_duplicate_queue_num() {
        let lines = [
            "1:in:wg_in:abcdef0123456789abcdef0123456789:1350",
            "1:out:wg_out:abcdef0123456789abcdef0123456789:1400", // duplicate queue_num
        ];
        let lines: Vec<String> = lines.iter().map(|s| s.to_string()).collect();
        let result = parse_config(&lines);
        assert!(result.is_err(), "Duplicate queue numbers should cause an error");
    }
}
