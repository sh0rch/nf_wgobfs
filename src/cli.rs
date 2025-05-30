/*
 * Copyright (c) 2025 sh0rch <sh0rch@iwl.dev>
 *
 * This file is part of nf_wgobfs.
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

//! CLI module for nf_wgobfs.
//!
//! This module provides command-line argument parsing and systemd unit file generation
//! for the nf_wgobfs application. It defines the supported CLI commands, parses
//! arguments, and generates systemd unit files for each configured filter.
//!
//! # Features
//! - Command-line argument parsing for different application modes.
//! - Systemd unit file generation for each filter configuration.
//! - Helper functions for integration with systemd service management.

use crate::config;
use std::fs;

/// Enum representing supported CLI commands for the application.
///
/// Each variant corresponds to a specific mode of operation:
/// - `Start(u16)`: Start the application for a specific queue number.
/// - `RunAll`: Run all configured filters.
/// - `GenerateUnits`: Generate systemd unit files for all configured filters.
/// - `Version`: Print version information.
#[derive(Debug)]
pub enum Command {
    /// Start the application for a specific queue number.
    Start(u16),
    /// Run all configured filters.
    RunAll,
    /// Generate systemd unit files for all configured filters.
    GenerateUnits,
    /// Print version information.
    Version,
}

/// Parses command-line arguments and returns the corresponding [`Command`].
///
/// # Returns
/// * [`Command`] - The parsed command to execute.
///
/// # Behavior
/// - `--generate-units`: Generates systemd unit files.
/// - `--version` or `-V`: Prints version information.
/// - `queue <num>`: Starts the application for the specified queue number.
/// - No arguments or unknown arguments: Runs all configured filters.
///
/// # Example
/// ```
/// let cmd = parse_args();
/// match cmd {
///     Command::Start(q) => { /* start for queue q */ }
///     Command::RunAll => { /* run all filters */ }
///     Command::GenerateUnits => { /* generate systemd units */ }
///     Command::Version => { /* print version */ }
/// }
/// ```
pub fn parse_args() -> Command {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        match args[1].as_str() {
            "--generate-units" => Command::GenerateUnits,
            "--version" | "-V" => Command::Version,
            "queue" if args.len() > 2 => Command::Start(args[2].parse().unwrap_or(0)),
            _ => Command::RunAll,
        }
    } else {
        Command::RunAll
    }
}

/// Generates systemd unit files for each filter configuration and a target unit.
///
/// This function creates a directory `/tmp/nf_wgobfs/` and writes a systemd
/// service unit file for each filter configuration. It also generates a target
/// unit that depends on all generated service units. After generation, it prints
/// instructions for installing and activating the units.
///
/// # Arguments
/// * `configs` - A slice of [`config::FilterConfig`] containing filter configurations.
///
/// # Returns
/// * `std::io::Result<()>` - Result indicating success or failure.
///
/// # Side Effects
/// - Writes unit files to `/tmp/nf_wgobfs/`.
/// - Prints instructions for installing and activating the generated units.
///
/// # Example
/// ```
/// generate_systemd_units(&configs)?;
/// ```
pub fn generate_systemd_units(configs: &[config::FilterConfig]) -> std::io::Result<()> {
    let out_dir = "/tmp/nf_wgobfs";
    fs::create_dir_all(out_dir)?;
    let mut unit_names = Vec::new();
    for filter in configs {
        // Generate a systemd service unit for each queue
        let unit = format!(
            r#"[Unit]
Description=NFQUEUE WireGuard Obfuscator queue {queue}
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/nf_wgobfs queue {queue}
Restart=on-failure

[Install]
WantedBy=multi-user.target
"#,
            queue = filter.queue_num
        );
        let filename = format!("{}/nf_wgobfs@{}.service", out_dir, filter.queue_num);
        fs::write(&filename, unit)?;
        println!("Generated {}", filename);
        unit_names.push(format!("nf_wgobfs@{}.service", filter.queue_num));
    }

    // Generate a target unit that wants all generated service units
    let wants = unit_names.join(" ");
    let target = format!(
        r#"[Unit]
Description=NFQUEUE WireGuard Obfuscator (all queues)
Requires=multi-user.target
Wants={wants}

[Install]
WantedBy=multi-user.target
"#,
        wants = wants
    );
    let target_filename = format!("{}/nf_wgobfs.target", out_dir);
    fs::write(&target_filename, target)?;
    println!("Generated {}", target_filename);

    // Print instructions for installing and activating the units
    println!("\nTo install and activate these units, run:");
    println!("  sudo cp /tmp/nf_wgobfs/nf_wgobfs@*.service /etc/systemd/system/");
    println!("  sudo cp /tmp/nf_wgobfs/nf_wgobfs.target /etc/systemd/system/");
    println!("  sudo systemctl daemon-reload");
    println!("  sudo systemctl enable nf_wgobfs.target");
    println!("  sudo systemctl start nf_wgobfs.target");
    Ok(())
}
