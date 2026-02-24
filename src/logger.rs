use chrono::Utc;
use colored::*;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{self, Write};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HoneypotEvent {
    pub timestamp: String,
    pub service: String,
    pub port: u16,
    pub remote_addr: String,
    pub event_type: EventType,
    pub details: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    Connection,
    LoginAttempt,
    Command,
    Scan,
    Disconnect,
    Data,
}

pub struct HoneypotLogger {
    log_file: String,
    event_count: u64,
}

impl HoneypotLogger {
    pub fn new(log_file: &str) -> io::Result<Self> {
        // Ensure file is writable / create it
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file)?;
        Ok(Self {
            log_file: log_file.to_string(),
            event_count: 0,
        })
    }

    pub fn log(&mut self, event: HoneypotEvent) {
        self.event_count += 1;
        let count = self.event_count;

        // Console output
        let timestamp = &event.timestamp[..19]; // trim to seconds
        let service_label = format!("[{}:{}]", event.service, event.port).bright_blue();
        let addr = event.remote_addr.yellow();

        let event_str = match &event.event_type {
            EventType::Connection => format!("{} connected", addr).bright_white().to_string(),
            EventType::LoginAttempt => {
                let user = event
                    .details
                    .get("username")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let pass = event
                    .details
                    .get("password")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                format!("{} tried login: {}:{}", addr, user.cyan(), pass.red())
            }
            EventType::Command => {
                let cmd = event
                    .details
                    .get("command")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                format!("{} sent command: {}", addr, cmd.magenta())
            }
            EventType::Scan => format!("{} scan/probe detected", addr)
                .bright_yellow()
                .to_string(),
            EventType::Disconnect => format!("{} disconnected", addr).dimmed().to_string(),
            EventType::Data => {
                let data = event
                    .details
                    .get("raw")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                format!("{} sent data: {}", addr, &data[..data.len().min(60)])
            }
        };

        println!(
            "{} {} {} {}",
            format!("#{}", count).dimmed(),
            timestamp.dimmed(),
            service_label,
            event_str
        );

        // Write JSON to file
        if let Ok(mut file) = OpenOptions::new().append(true).open(&self.log_file) {
            if let Ok(json) = serde_json::to_string(&event) {
                let _ = writeln!(file, "{}", json);
            }
        }
    }

    pub fn log_event(
        &mut self,
        service: &str,
        port: u16,
        remote_addr: &str,
        event_type: EventType,
        details: serde_json::Value,
    ) {
        let event = HoneypotEvent {
            timestamp: Utc::now().to_rfc3339(),
            service: service.to_string(),
            port,
            remote_addr: remote_addr.to_string(),
            event_type,
            details,
        };
        self.log(event);
    }
}
