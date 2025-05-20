use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::io::{self, BufRead};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    In,
    Out,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherMode {
    Auto,
    Fast,
    Standard,
}

#[derive(Debug, Clone)]
pub struct FilterConfig {
    pub queue_num: u16,
    pub direction: Direction,
    pub name: String,
    pub key: [u8; 32],
    pub mtu: usize,
    pub cipher_mode: CipherMode,
}

fn is_root() -> bool {
    match fs::read_to_string("/proc/self/status") {
        Ok(status) => status
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(1)) // first number = real UID
            .map(|uid| uid == "0")
            .unwrap_or(false),
        Err(_) => false,
    }
}

pub fn ascii_to_key(s: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

fn load_config_lines() -> io::Result<Vec<String>> {
    if !is_root() {
        eprintln!("This program must be run as root.");
        std::process::exit(1);
    }
    let default_path = "/etc/nf_wgobfs/config";
    let config_path = if std::path::Path::new(default_path).exists() {
        default_path.to_string()
    } else if let Ok(env_path) = env::var("NF_WGOBFS_CONF") {
        if std::path::Path::new(&env_path).exists() {
            env_path
        } else {
            eprintln!(
                "Config not found: neither {} nor {}",
                default_path, env_path
            );
            std::process::exit(1);
        }
    } else {
        eprintln!(
            "Config not found: {} and NF_WGOBFS_CONF not set.",
            default_path
        );
        std::process::exit(1);
    };

    let file = fs::File::open(&config_path)?;
    let reader = io::BufReader::new(file);
    let lines = reader
        .lines()
        .filter_map(Result::ok)
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    Ok(lines)
}

pub fn parse_config() -> std::io::Result<Vec<FilterConfig>> {
    let mut configs = Vec::new();
    let lines = load_config_lines()?;
    for line in lines {
        let mut parts = line.splitn(7, ':');
        let queue_num = parts
            .next()
            .unwrap()
            .parse::<u16>()
            .map_err(|_| std::io::ErrorKind::InvalidData)?;
        let direction = match parts.next().unwrap_or("out").to_lowercase().as_str() {
            "in" => Direction::In,
            _ => Direction::Out,
        };
        let name = parts
            .next()
            .ok_or(std::io::ErrorKind::InvalidData)?
            .to_string();
        let key_ascii = parts.next().ok_or(std::io::ErrorKind::InvalidData)?;
        let key = ascii_to_key(key_ascii.trim());
        let next = parts.next();
        let (cipher_mode, mtu) = match next {
            Some("F") | Some("f") => {
                let mtu = parts
                    .next()
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(1500);
                (CipherMode::Fast, mtu)
            }
            Some("S") | Some("s") => {
                let mtu = parts
                    .next()
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(1500);
                (CipherMode::Standard, mtu)
            }
            Some(mtu_str) if mtu_str.chars().all(|c| c.is_ascii_digit()) => {
                (CipherMode::Auto, mtu_str.parse::<usize>().unwrap_or(1500))
            }
            None => (CipherMode::Auto, 1500),
            _ => (CipherMode::Auto, 1500),
        };
        configs.push(FilterConfig {
            queue_num,
            direction,
            name,
            key,
            mtu,
            cipher_mode,
        });
    }
    Ok(configs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ascii_to_key_consistency() {
        let key1 = ascii_to_key("testkey");
        let key2 = ascii_to_key("testkey");
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_ascii_to_key_differs() {
        let key1 = ascii_to_key("testkey1");
        let key2 = ascii_to_key("testkey2");
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_parse_config_line_full() {
        // queue:direction:name:key:mode:mtu
        let line = "1:in:wg_in:abcdef0123456789abcdef0123456789:F:1350";
        let mut parts = line.splitn(7, ':');
        let queue_num = parts.next().unwrap().parse::<u16>().unwrap();
        let direction = match parts.next().unwrap_or("out").to_lowercase().as_str() {
            "in" => Direction::In,
            _ => Direction::Out,
        };
        let name = parts.next().unwrap().to_string();
        let key_ascii = parts.next().unwrap();
        let key = ascii_to_key(key_ascii.trim());
        let next = parts.next();
        let (cipher_mode, mtu) = match next {
            Some("F") | Some("f") => (CipherMode::Fast, 1350),
            Some("S") | Some("s") => (CipherMode::Standard, 1350),
            Some(mtu_str) if mtu_str.chars().all(|c| c.is_ascii_digit()) => {
                (CipherMode::Auto, mtu_str.parse::<usize>().unwrap_or(1500))
            }
            None => (CipherMode::Auto, 1500),
            _ => (CipherMode::Auto, 1500),
        };
        assert_eq!(queue_num, 1);
        assert_eq!(direction, Direction::In);
        assert_eq!(name, "wg_in");
        assert_eq!(key, ascii_to_key("abcdef0123456789abcdef0123456789"));
        assert_eq!(cipher_mode, CipherMode::Fast);
        assert_eq!(mtu, 1350);
    }

    #[test]
    fn test_parse_config_line_full_and_defaults() {
        // queue:direction:name:key:mode:mtu
        let line_full = "1:in:wg_in:abcdef0123456789abcdef0123456789:F:1350";
        let line_no_mtu = "1:in:wg_in:abcdef0123456789abcdef0123456789:F";
        let line_no_mode_mtu = "1:in:wg_in:abcdef0123456789abcdef0123456789";

        for (line, exp_mode, exp_mtu) in [
            (line_full, CipherMode::Fast, 1350),
            (line_no_mtu, CipherMode::Fast, 1500),
            (line_no_mode_mtu, CipherMode::Auto, 1500),
        ] {
            let mut parts = line.splitn(7, ':');
            let queue_num = parts.next().unwrap().parse::<u16>().unwrap();
            let direction = match parts.next().unwrap_or("out").to_lowercase().as_str() {
                "in" => Direction::In,
                _ => Direction::Out,
            };
            let name = parts.next().unwrap().to_string();
            let key_ascii = parts.next().unwrap();
            let key = ascii_to_key(key_ascii.trim());
            let mode = parts.next();
            let mtu = parts.next();
            let (cipher_mode, mtu) = match (mode, mtu) {
                (Some("F") | Some("f"), Some(mtu_str)) => {
                    (CipherMode::Fast, mtu_str.parse::<usize>().unwrap_or(1500))
                }
                (Some("F") | Some("f"), None) => (CipherMode::Fast, 1500),
                (Some("S") | Some("s"), Some(mtu_str)) => (
                    CipherMode::Standard,
                    mtu_str.parse::<usize>().unwrap_or(1500),
                ),
                (Some("S") | Some("s"), None) => (CipherMode::Standard, 1500),
                (Some(mtu_str), None) if mtu_str.chars().all(|c| c.is_ascii_digit()) => {
                    (CipherMode::Auto, mtu_str.parse::<usize>().unwrap_or(1500))
                }
                (None, _) => (CipherMode::Auto, 1500),
                _ => (CipherMode::Auto, 1500),
            };
            assert_eq!(queue_num, 1);
            assert_eq!(direction, Direction::In);
            assert_eq!(name, "wg_in");
            assert_eq!(key, ascii_to_key("abcdef0123456789abcdef0123456789"));
            assert_eq!(cipher_mode, exp_mode);
            assert_eq!(mtu, exp_mtu);
        }
    }
}
