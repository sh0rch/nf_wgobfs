/*
 * Copyright (c) 2025 sh0rch <sh0rch@iwl.dev>
 *
 * This file is part of nf_wgobfs.
 *
 * Licensed under the MIT License. See LICENSE file in the project root for full license information.
 */

//! # NFQUEUE-based WireGuard Packet Filter
//!
//! This module implements a packet filter using Linux NFQUEUE for obfuscating and deobfuscating
//! WireGuard packets. It provides an event loop that binds to a specified NFQUEUE, processes
//! packets according to the configured direction (inbound or outbound), and sets the appropriate
//! verdict (accept or drop) for each packet.
//!
//! ## Features
//! - Binds to a user-specified NFQUEUE number.
//! - Receives packets from the kernel, applies obfuscation or deobfuscation, and sets verdicts.
//! - Handles panics and errors gracefully, automatically restarting the handler as needed.
//! - Supports configurable MTU and direction for flexible deployment.
//!
//! ## Usage
//! Use [`run_nfqueue_filter`] to start the event loop with a given [`FilterConfig`].
//!
//! ## Safety
//! Panics are caught and logged; the handler is automatically restarted to ensure robustness.

use crate::config::{Direction, FilterConfig};
use crate::filter::keepalive::KeepaliveDropper;
use crate::filter::obfuscator::{deobfuscate_wg_packet, obfuscate_wg_packet};
use crate::randomiser;
use nfq::{Queue, Verdict};
use std::panic;
use std::thread;
use std::time::Duration;

/// Runs the NFQUEUE filter event loop.
///
/// This function binds to the specified NFQUEUE and enters a loop where it receives packets,
/// applies obfuscation or deobfuscation depending on the direction, and sets the verdict
/// (accept or drop) for each packet. If an error or panic occurs, the handler is restarted
/// after a short delay to ensure continuous operation.
///
/// # Arguments
/// * `filter` - The filter configuration, including queue number, direction, MTU, etc.
///
/// # Returns
/// * `std::io::Result<()>` - Returns `Ok(())` on success, or an error if the handler fails to start.
///
/// # Panics
/// Panics are caught and logged; the handler is restarted automatically.
///
/// # Example
/// ```no_run
/// use crate::config::FilterConfig;
/// run_nfqueue_filter(FilterConfig::default()).unwrap();
/// ```
pub fn run_nfqueue_filter(filter: FilterConfig) -> std::io::Result<()> {
    loop {
        // Catch panics to allow automatic restart of the handler
        let result: Result<std::io::Result<()>, Box<dyn std::any::Any + Send>> =
            panic::catch_unwind(|| {
                // Open the NFQUEUE socket for packet interception
                let mut q =
                    Queue::open().map_err(|e| panic!("Failed to open NFQUEUE: {e}")).unwrap();

                // Bind to the specified queue number
                q.bind(filter.queue_num)
                    .map_err(|e| {
                        panic!(
                            "Failed to bind NFQUEUE {}: {}. \
                    Probably, the queue is already occupied by another process. \
                    Try selecting another queue through the NF_WGOBFS_QUEUE environment variable.",
                            filter.queue_num, e
                        );
                    })
                    .unwrap();

                #[cfg(debug_assertions)]
                {
                    println!(
                        "User-space filter started (NFQUEUE{}), direction {:?}, mtu {}",
                        filter.queue_num, filter.direction, filter.mtu
                    );
                }

                // Allocate buffer for packet processing
                let buf_size = filter.mtu + 80;
                let mut buf = vec![0u8; buf_size];
                let mut rng = randomiser::create_secure_rng();
                let mut keepalive_dropper = KeepaliveDropper::new(0, 9);

                // Main packet processing loop
                loop {
                    // Receive a packet from the queue
                    let mut msg = q.recv().expect("Failed to receive from NFQUEUE");
                    let pkt = msg.get_payload();
                    let len = pkt.len();
                    buf[..len].copy_from_slice(pkt);

                    #[cfg(debug_assertions)]
                    println!(
                        "New packet in NFQUEUE {}: len={}, verdict={:?}",
                        filter.queue_num,
                        len,
                        msg.get_verdict()
                    );

                    #[cfg(debug_assertions)]
                    println!(
                        "NFQUEUE {}: direction {:?}, payload_len={}",
                        filter.queue_num, filter.direction, len
                    );

                    // Process packet based on direction
                    match filter.direction {
                        Direction::Out => {
                            #[cfg(debug_assertions)]
                            println!("Before obfuscation ({}): {:02x?}", len, &buf[..len]);

                            // Attempt to obfuscate the packet
                            if let Some(new_len) = obfuscate_wg_packet(
                                &mut buf,
                                len,
                                &filter,
                                &mut keepalive_dropper,
                                &mut rng,
                            ) {
                                #[cfg(debug_assertions)]
                                {
                                    println!(
                                        "After obfuscation ({}): {:02x?}",
                                        new_len,
                                        &buf[..new_len]
                                    );
                                }
                                msg.set_payload(&buf[..new_len]);
                                msg.set_verdict(Verdict::Accept);
                            } else {
                                #[cfg(debug_assertions)]
                                {
                                    println!("Obfuscation skipped");
                                }
                                msg.set_verdict(Verdict::Drop);
                            }
                        }
                        Direction::In => {
                            #[cfg(debug_assertions)]
                            {
                                println!("Deobfuscating packet ({}): {:02x?}", len, &buf[..len]);
                            }

                            // Attempt to deobfuscate the packet
                            if let Some(new_len) = deobfuscate_wg_packet(&mut buf[..len], &filter) {
                                #[cfg(debug_assertions)]
                                {
                                    println!(
                                        "Deobfuscated packet ({}): {:02x?}",
                                        new_len,
                                        &buf[..new_len]
                                    );
                                }
                                msg.set_payload(&buf[..new_len]);
                                msg.set_verdict(Verdict::Accept);
                            } else {
                                #[cfg(debug_assertions)]
                                {
                                    println!("Deobfuscation skipped");
                                }
                                msg.set_verdict(Verdict::Drop);
                            }
                        }
                    }

                    #[cfg(debug_assertions)]
                    {
                        println!(
                            "NFQUEUE {}: verdict={:?}, payload_len={}",
                            filter.queue_num,
                            msg.get_verdict(),
                            msg.get_payload().len()
                        );
                    }
                    // Send verdict back to the queue
                    q.verdict(msg)?;
                }
            });

        // Handle errors and panics, restart the handler if needed
        match result {
            Ok(Ok(())) => break,
            Ok(Err(e)) => {
                eprintln!("NFQUEUE error: {e:?}");
                thread::sleep(Duration::from_secs(1));
                eprintln!("Restarting NFQUEUE handler...");
            }
            Err(e) => {
                if let Some(msg) = e.downcast_ref::<&str>() {
                    eprintln!("NFQUEUE panic: {msg}");
                } else if let Some(msg) = e.downcast_ref::<String>() {
                    eprintln!("NFQUEUE panic: {msg}");
                } else {
                    eprintln!("NFQUEUE panic: unknown error");
                }
                thread::sleep(Duration::from_secs(1));
                eprintln!("Restarting NFQUEUE handler after panic...");
            }
        }
    }
    Ok(())
}
