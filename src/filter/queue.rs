/*
 * Copyright (c) 2025 sh0rch <sh0rch@iwl.dev>
 * SPDX-License-Identifier: MIT
 *
 * This module implements a Netfilter queue (NFQUEUE) based packet filter for WireGuard obfuscation.
 * It provides a main entry point to run the filter, handling panics and automatic restarts,
 * and a child loop that processes packets from the queue, applying obfuscation or deobfuscation
 * depending on the Netfilter hook.
 */

use crate::config::FilterConfig;
use crate::filter::keepalive::KeepaliveDropper;
use crate::filter::obfuscator::{deobfuscate_wg_packet, obfuscate_wg_packet};
use crate::nfqueue::{self, Hook, NfqQueue};
use crate::randomiser;
use std::{panic, thread, time::Duration};

/// Runs the NFQUEUE-based filter in a loop, automatically restarting on panic.
///
/// # Arguments
/// * `filter` - The filter configuration specifying queue number, length, MTU, etc.
///
/// # Returns
/// * `std::io::Result<()>` - Returns Ok(()) on success, or an error if the filter fails to start.
///
/// This function catches panics in the child process, logs the error, waits for a second,
/// and then restarts the NFQUEUE filter. This ensures robustness against unexpected failures.
pub fn run_nfqueue_filter(filter: FilterConfig) -> std::io::Result<()> {
    loop {
        let result = panic::catch_unwind(|| {
            let qlen: u32 = filter.queue_len.unwrap_or(1024);
            let qnum = filter.queue_num;
            let mtu = filter.mtu;
            let _pid = NfqQueue::spawn(qnum, qlen, mtu, move |q| child_loop(q, &filter))
                .map_err(|e| panic!("NFQUEUE spawn: errno {e}"))
                .unwrap();

            #[cfg(debug_assertions)]
            println!("NFQUEUE{} child PID {}, backlog {}, mtu {}", qnum, _pid, qlen, mtu);

            nfqueue::wait_forever_until_signal();
        });

        match result {
            Ok(()) => break,
            Err(e) => {
                if let Some(msg) = e.downcast_ref::<&str>() {
                    eprintln!("NFQUEUE panic: {msg}");
                } else if let Some(msg) = e.downcast_ref::<String>() {
                    eprintln!("NFQUEUE panic: {msg}");
                } else {
                    eprintln!("NFQUEUE panic: unknown");
                }
                thread::sleep(Duration::from_secs(1));
                eprintln!("Restarting NFQUEUE after panic...");
            }
        }
    }
    Ok(())
}

/// The main loop for processing packets from the NFQUEUE.
///
/// # Arguments
/// * `q` - Mutable reference to the NfqQueue instance.
/// * `filter` - Reference to the filter configuration.
///
/// # Behavior
/// This function runs indefinitely, receiving packets from the queue and processing them
/// according to the Netfilter hook:
/// - For outgoing packets (LocalOut, PostRouting), it applies obfuscation.
/// - For incoming packets (LocalIn, Ingress, PreRouting), it applies deobfuscation.
/// - For unknown hooks, the packet is dropped.
///
/// Debug output is printed if compiled in debug mode.
fn child_loop(q: &mut NfqQueue, filter: &FilterConfig) -> ! {
    let mut rng = randomiser::create_secure_rng();
    let mut dropper = KeepaliveDropper::new(80);
    loop {
        let pkt = match q.recv() {
            Ok(p) => p,
            Err(-2) => continue,
            Err(errno) => {
                eprintln!("NFQUEUE recv errno {errno}, retry...");
                continue;
            }
        };

        let len = pkt.payload_len;
        let payload = unsafe { q.payload_mut() };
        #[cfg(debug_assertions)]
        println!("NFQUEUE{}: hook={:?}, payload_len={}", filter.queue_num, pkt.hook, len);

        match pkt.hook {
            Hook::LocalOut | Hook::PostRouting => {
                #[cfg(debug_assertions)]
                println!("Before obfuscation ({}): {:02x?}", len, &payload[..len]);

                if let Some(new_len) =
                    obfuscate_wg_packet(payload, len, filter, &mut dropper, &mut rng)
                {
                    #[cfg(debug_assertions)]
                    println!("After obfuscation ({}): {:02x?}", new_len, &payload[..new_len]);
                    q.accept_pkt(new_len).unwrap();
                } else {
                    #[cfg(debug_assertions)]
                    println!("Obfuscation skipped");
                    q.drop_pkt().unwrap();
                }
            }
            Hook::LocalIn | Hook::Ingress | Hook::PreRouting => {
                #[cfg(debug_assertions)]
                println!("De-obfuscating packet ({}): {:02x?}", len, &payload[..len]);

                if let Some(new_len) = deobfuscate_wg_packet(payload, len, filter) {
                    #[cfg(debug_assertions)]
                    println!("De-obfuscated ({}): {:02x?}", new_len, &payload[..new_len]);
                    q.accept_pkt(new_len).unwrap();
                } else {
                    #[cfg(debug_assertions)]
                    println!("Failed de-obfuscation → DROP");
                    q.drop_pkt().unwrap();
                }
            }
            _ => {
                #[cfg(debug_assertions)]
                println!("Unknown hook {:?} → DROP", pkt.hook);
                q.drop_pkt().unwrap();
            }
        }
    }
}
