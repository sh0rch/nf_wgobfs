use std::env;
use std::io::{self, Write};
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

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
