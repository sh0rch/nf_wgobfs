/*
 * Copyright (c) 2025 sh0rch <sh0rch@iwl.dev>
 *
 * This file is part of nf_wgobfs.
 *
 * Licensed under the MIT License. See LICENSE file in the project root for full license information.
 */

//! Main entry point for the nf_wgobfs application.
//!
//! This module handles command-line argument parsing, configuration loading,
//! and dispatches execution to the appropriate submodules based on user input.

mod cli;
mod config;
mod filter;
mod netutils;
mod randomiser;

use std::thread;

/// Application entry point.
///
/// Loads configuration, parses command-line arguments, and executes the selected command.
/// Returns a `std::io::Result<()>` indicating success or failure.
fn main() -> std::io::Result<()> {
    // Load configuration from file.
    let configs = match config::load_config() {
        Ok(configs) => {
            if configs.is_empty() {
                // No valid configurations found.
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "No valid configurations found in the config file",
                ));
            }
            configs
        }
        Err(_) => {
            // Configuration file not found or invalid.
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Configuration file not found or invalid",
            ));
        }
    };

    // Parse command-line arguments and execute the corresponding command.
    match cli::parse_args() {
        cli::Command::GenerateUnits => {
            // Generate systemd unit files for all configurations.
            if cli::generate_systemd_units(&configs).is_err() {
                return Err(std::io::Error::other("Failed to generate systemd units"));
            }
        }
        cli::Command::Start(queue_num) => {
            // Start the filter for the specified queue number.
            let q = configs.iter().find(|f| f.queue_num == queue_num).unwrap();
            filter::queue::run_nfqueue_filter(q.clone())?;
        }
        cli::Command::Version => {
            // Print application version.
            println!("nf_wgobfs version {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        cli::Command::RunAll => {
            // Start filters for all configurations in separate threads.
            let mut handles = Vec::new();
            for filter in configs {
                handles.push(thread::spawn(move || {
                    filter::queue::run_nfqueue_filter(filter).unwrap();
                }));
            }
            // Wait for all threads to finish.
            for handle in handles {
                handle.join().unwrap();
            }
        }
    }
    Ok(())
}
