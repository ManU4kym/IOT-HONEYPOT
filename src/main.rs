use clap::Parser;
use colored::*;
use std::sync::Arc;
use tokio::sync::Mutex;

mod logger;
mod services;

use logger::HoneypotLogger;
use services::{
    run_ftp_honeypot, run_http_honeypot, run_rtsp_honeypot, run_ssh_honeypot, run_telnet_honeypot,
};

#[derive(Parser, Debug)]
#[command(name = "iot-honeypot")]
#[command(about = "Local IoT Honeypot - Detect and log network probes on your network", long_about = None)]
struct Args {
    /// Bind address
    #[arg(short, long, default_value = "0.0.0.0")]
    bind: String,

    /// Log output file (JSON)
    #[arg(short, long, default_value = "honeypot.log")]
    output: String,

    /// Disable HTTP honeypot (port 80/8080)
    #[arg(long)]
    no_http: bool,

    /// Disable Telnet honeypot (port 23)
    #[arg(long)]
    no_telnet: bool,

    /// Disable RTSP honeypot (port 554) - simulates IP camera
    #[arg(long)]
    no_rtsp: bool,

    /// Disable SSH honeypot (port 2222)
    #[arg(long)]
    no_ssh: bool,

    /// Disable FTP honeypot (port 21)
    #[arg(long)]
    no_ftp: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    print_banner();

    let logger = Arc::new(Mutex::new(
        HoneypotLogger::new(&args.output).expect("Failed to initialize logger"),
    ));

    println!("{}", "Starting honeypot services...".bright_yellow());
    println!("{}", format!("Logging to: {}", args.output).dimmed());
    println!();

    let bind = args.bind.clone();
    let mut handles = vec![];

    if !args.no_http {
        let logger_clone = Arc::clone(&logger);
        let bind_clone = bind.clone();
        handles.push(tokio::spawn(async move {
            run_http_honeypot(&bind_clone, 80, logger_clone.clone()).await;
        }));
        let logger_clone = Arc::clone(&logger);
        let bind_clone = bind.clone();
        handles.push(tokio::spawn(async move {
            run_http_honeypot(&bind_clone, 8080, logger_clone).await;
        }));
        println!("  {} HTTP honeypot on ports 80, 8080", "✓".bright_green());
    }

    if !args.no_telnet {
        let logger_clone = Arc::clone(&logger);
        let bind_clone = bind.clone();
        handles.push(tokio::spawn(async move {
            run_telnet_honeypot(&bind_clone, 23, logger_clone).await;
        }));
        println!("  {} Telnet honeypot on port 23", "✓".bright_green());
    }

    if !args.no_rtsp {
        let logger_clone = Arc::clone(&logger);
        let bind_clone = bind.clone();
        handles.push(tokio::spawn(async move {
            run_rtsp_honeypot(&bind_clone, 554, logger_clone).await;
        }));
        println!(
            "  {} RTSP honeypot on port 554 (IP Camera sim)",
            "✓".bright_green()
        );
    }

    if !args.no_ssh {
        let logger_clone = Arc::clone(&logger);
        let bind_clone = bind.clone();
        handles.push(tokio::spawn(async move {
            run_ssh_honeypot(&bind_clone, 2222, logger_clone).await;
        }));
        println!("  {} SSH honeypot on port 2222", "✓".bright_green());
    }

    if !args.no_ftp {
        let logger_clone = Arc::clone(&logger);
        let bind_clone = bind.clone();
        handles.push(tokio::spawn(async move {
            run_ftp_honeypot(&bind_clone, 21, logger_clone).await;
        }));
        println!("  {} FTP honeypot on port 21", "✓".bright_green());
    }

    println!();
    println!(
        "{}",
        "Honeypot active. Listening for probes...".bright_cyan()
    );
    println!("{}", "Press Ctrl+C to stop.".dimmed());
    println!();

    // Wait for all tasks
    for handle in handles {
        let _ = handle.await;
    }
}

fn print_banner() {
    println!(
        "{}",
        r#"
  ___     _____   _   _                                   _
 |_ _|_____|_   _| | | | ___  _ __   ___ _   _ _ __   ___ | |_
  | |/ _ \  | |   | |_| |/ _ \| '_ \ / _ \ | | | '_ \ / _ \| __|
  | | (_) | | |   |  _  | (_) | | | |  __/ |_| | |_) | (_) | |_
 |___\___/  |_|   |_| |_|\___/|_| |_|\___|\__, | .__/ \___/ \__|
                                           |___/|_|
"#
        .bright_red()
    );
    println!(
        "{}",
        "  Local IoT Honeypot — Defensive Security Tool".bright_white()
    );
    println!(
        "{}",
        "  Simulates vulnerable IoT devices to detect network probes".dimmed()
    );
    println!(
        "{}",
        "  All captured data is stored locally. For use on your own network only.".yellow()
    );
    println!();
}
