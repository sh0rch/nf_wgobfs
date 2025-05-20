use crate::cipher::randomiser;
use crate::config::{Direction, FilterConfig};
use crate::filter::keepalive::KeepaliveDropper;
use crate::filter::obfuscator::{deobfuscate_wg_packet, obfuscate_wg_packet};
use nfq::{Queue, Verdict};
use std::panic;
use std::thread;
use std::time::Duration;

pub fn run_nfqueue_filter(filter: FilterConfig) -> std::io::Result<()> {
    loop {
        let result: Result<std::io::Result<()>, Box<dyn std::any::Any + Send>> =
            panic::catch_unwind(|| {
                let mut q = Queue::open().map_err(|e| {
                    eprintln!("Failed to open NFQUEUE: {e}");
                    std::io::Error::other(e)
                })?;

                q.bind(filter.queue_num).map_err(|e| {
                    eprintln!(
                        "Failed to bind NFQUEUE {}: {}. \
                    Probably, the queue is already occupied by another process. \
                    Try selecting another queue through the NF_WGOBFS_QUEUE environment variable.",
                        filter.queue_num, e
                    );
                    std::io::Error::other(e)
                })?;

                println!(
                    "User-space filter started (NFQUEUE{} for {}), direction {:?}, mtu {}",
                    filter.queue_num, filter.name, filter.direction, filter.mtu
                );
                let buf_size = filter.mtu + 80;
                let mut buf = vec![0u8; buf_size];
                let mut rng = randomiser::create_secure_rng();
                let mut keepalive_dropper = KeepaliveDropper::new(0, 9);

                loop {
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

                    match filter.direction {
                        Direction::Out => {
                            #[cfg(debug_assertions)]
                            println!("Before obfuscation ({}): {:02x?}", len, &buf[..len]);

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
                    q.verdict(msg)?;
                }
            });

        match result {
            Ok(Ok(())) => break, // завершение без ошибок
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
