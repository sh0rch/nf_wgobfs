mod cipher;
mod cli;
mod config;
mod filter;
mod netutils;

use std::thread;

fn main() -> std::io::Result<()> {
    match cli::parse_args() {
        cli::Command::CheckCipher => {
            let avx2 = cipher::fast_available();
            println!(
                "Cipher auto-detection: {}",
                if avx2 {
                    "FAST (ChaCha20, AVX2/SIMD/NEON supported)"
                } else {
                    "STANDARD (ChaCha6, AVX2/SIMD/NEON not supported)"
                }
            );
            return Ok(());
        }
        cli::Command::GenerateUnits => {
            let configs = config::parse_config()?;
            cli::generate_systemd_units(&configs)?;
        }
        cli::Command::Start(queue_num) => {
            let configs = config::parse_config()?;
            let filter = configs
                .into_iter()
                .find(|f| f.queue_num == queue_num)
                .unwrap();
            filter::queue::run_nfqueue_filter(filter)?;
        }
        cli::Command::Version => {
            println!("nf_wgobfs version {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        cli::Command::RunAll => {
            let configs = config::parse_config()?;
            let mut handles = Vec::new();
            for filter in configs {
                handles.push(thread::spawn(move || {
                    filter::queue::run_nfqueue_filter(filter).unwrap();
                }));
            }
            for handle in handles {
                handle.join().unwrap();
            }
        }
    }
    Ok(())
}
