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

//! UDP Echo utility module.
//!
//! This module provides a simple UDP echo server and client for testing UDP connectivity.
//! The server listens for UDP packets and echoes them back to the sender.
//! The client sends a UDP packet to the server and waits for the echoed response.
//!
//! Usage:
//! - As a server: `cargo run -- [bind_addr] [port]`
//! - As a client: `cargo run -- --client [server_ip] [port] [message]`

use std::env;
use std::io::{self, Write};
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

/// Prints the contents of a UDP packet in both hexadecimal and ASCII representations.
///
/// # Arguments
/// * `label` - A label to prefix the output (e.g., "\[client\] sent").
/// * `buf` - The byte buffer containing the packet data.
fn print_packet(label: &str, buf: &[u8]) {
    print!("{label} [hex]: ");
    for b in buf {
        print!("{:02x} ", b);
    }
    println!();
    print!("{label} [ascii]: ");
    for b in buf {
        if b.is_ascii_graphic() || *b == b' ' {
            print!("{}", *b as char);
        } else {
            print!(".");
        }
    }
    println!();
}

/// Runs the UDP echo client.
///
/// Binds to a random local UDP port, sends a message to the specified server,
/// and waits for the echoed response. Repeats on each Enter key press.
///
/// # Arguments
/// * `ip` - The server IP address to send packets to.
/// * `port` - The server UDP port.
/// * `message` - The message to send as a byte slice.
fn run_client(ip: &str, port: u16, message: &[u8]) {
    let sock = UdpSocket::bind("0.0.0.0:0").expect("bind failed");
    let dest = format!("{}:{}", ip, port);

    println!(
        "[client] Ready to send to {}. Press Enter to send (message: {:?}), Ctrl+C to exit.",
        dest,
        String::from_utf8_lossy(message)
    );

    let mut buf = [0u8; 1500];
    loop {
        print!("[client] Press Enter to send: ");
        io::stdout().flush().ok();
        let _ = io::stdin().read_line(&mut String::new());

        sock.send_to(message, &dest).expect("send_to failed");
        println!("[client] sent {} bytes", message.len());
        print_packet("[client] sent", message);

        match sock.recv_from(&mut buf) {
            Ok((len, src)) => {
                println!("[client] got {} bytes from {}", len, src);
                print_packet("[client] recv", &buf[..len]);
            }
            Err(e) => {
                eprintln!("[client] recv_from failed: {}", e);
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

/// Runs the UDP echo server.
///
/// Binds to the specified address and port, receives UDP packets,
/// and echoes them back to the sender.
///
/// # Arguments
/// * `bind_addr` - The local address to bind to (e.g., "0.0.0.0").
/// * `port` - The UDP port to listen on.
fn run_server(bind_addr: &str, port: u16) {
    let addr = format!("{}:{}", bind_addr, port);
    let sock = UdpSocket::bind(&addr).expect("bind failed");
    println!("[server] listening on {}", addr);

    let mut buf = [0u8; 1500];
    loop {
        match sock.recv_from(&mut buf) {
            Ok((len, src)) => {
                println!("[server] got {} bytes from {}", len, src);
                print_packet("[server] recv", &buf[..len]);
                if let Err(e) = sock.send_to(&buf[..len], src) {
                    eprintln!("[server] failed to send response: {}", e);
                } else {
                    print_packet("[server] sent", &buf[..len]);
                }
            }
            Err(e) => {
                eprintln!("[server] recv_from failed: {}", e);
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

/// Entry point for the UDP echo utility.
///
/// Parses command-line arguments to determine whether to run as a server or client.
/// - As a server: `cargo run -- [bind_addr] [port]`
/// - As a client: `cargo run -- --client [server_ip] [port] [message]`
fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() > 1 && args[1] == "--client" {
        let ip = args.get(2).map(|s| s.as_str()).unwrap_or("127.0.0.1");
        let port: u16 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(51820);
        let message = args.get(4).map(|s| s.as_bytes()).unwrap_or(b"test-packet");
        run_client(ip, port, message);
    } else {
        let bind_addr = args.get(1).map(|s| s.as_str()).unwrap_or("0.0.0.0");
        let port: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(51820);
        run_server(bind_addr, port);
    }
}
