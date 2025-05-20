use crate::config;
use std::fs;

#[derive(Debug)]
pub enum Command {
    CheckCipher,
    Start(u16),
    RunAll,
    GenerateUnits,
    Version,
}

pub fn parse_args() -> Command {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        match args[1].as_str() {
            "--check-cipher" => Command::CheckCipher,
            "--generate-units" => Command::GenerateUnits,
            "--version" | "-V" => Command::Version,
            "queue" if args.len() > 2 => Command::Start(args[2].parse().unwrap_or(0)),
            _ => Command::RunAll,
        }
    } else {
        Command::RunAll
    }
}

pub fn generate_systemd_units(configs: &[config::FilterConfig]) -> std::io::Result<()> {
    let out_dir = "/tmp/nf_wgobfs";
    fs::create_dir_all(out_dir)?;
    let mut unit_names = Vec::new();
    for filter in configs {
        let unit = format!(
            r#"[Unit]
Description=NFQUEUE WireGuard Obfuscator queue {queue}
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/nf_wgobfs start {queue}
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

    // Генерируем общий target unit
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

    println!("\nTo install and activate these units, run:");
    println!("  sudo cp /tmp/nf_wgobfs/nf_wgobfs@*.service /etc/systemd/system/");
    println!("  sudo cp /tmp/nf_wgobfs/nf_wgobfs.target /etc/systemd/system/");
    println!("  sudo systemctl daemon-reload");
    println!("  sudo systemctl enable nf_wgobfs.target");
    println!("  sudo systemctl start nf_wgobfs.target");
    Ok(())
}
