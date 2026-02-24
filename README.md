```
  ___     _____   _   _                                   _
 |_ _|_____|_   _| | | | ___  _ __   ___ _   _ _ __   ___ | |_
  | |/ _ \  | |   | |_| |/ _ \| '_ \ / _ \ | | | '_ \ / _ \| __|
  | | (_) | | |   |  _  | (_) | | | |  __/ |_| | |_) | (_) | |_
 |___\___/  |_|   |_| |_|\___/|_| |_|\___|\__, | .__/ \___/ \__|
                                           |___/|_|

  Local IoT Honeypot — Defensive Security Tool
  Simulates vulnerable IoT devices to detect network probes
  All captured data is stored locally. For use on your own network only.
```

---

# IoT Honeypot 🍯

A local honeypot written in Rust that simulates common IoT devices to detect and log unauthorized probes on your network.

> ⚠️ **For use on your own network only.** This tool is for defensive security research.

---

## ✨ Features

- Multi-service honeypot: HTTP (80/8080), Telnet (23), RTSP (554), SSH (2222), FTP (21)
- Structured JSONL logging for easy parsing and SIEM ingestion
- Human-friendly colored console output for live monitoring
- Lightweight Rust binary using `tokio` for async concurrency
- Modular services (enable/disable with CLI flags)

---

## What It Simulates

| Service | Port(s) | Simulates |
|---------|---------|-----------|
| HTTP    | 80, 8080 | IP camera web login panel |
| Telnet  | 23       | BusyBox router shell (like Mirai targets) |
| RTSP    | 554      | IP camera RTSP stream endpoint |
| SSH     | 2222     | OpenSSH banner (captures client fingerprints) |
| FTP     | 21       | vsFTPd (captures login credentials) |

---

## Setup

### Prerequisites

- Rust + Cargo: <https://rustup.rs>

### Quick Start

Linux / macOS (preferred):

```bash
cd iot-honeypot
cargo build --release
sudo ./target/release/iot-honeypot --bind 0.0.0.0 --output /var/log/honeypot.log
```

Windows (PowerShell):

```powershell
cd iot-honeypot
cargo build --release
.\target\release\iot-honeypot.exe --bind 0.0.0.0 --output honeypot.log
```

Custom options example (enable/disable services):

```bash
sudo ./target/release/iot-honeypot --bind 0.0.0.0 --no-ssh --no-ftp
```

> `sudo` is required for ports below 1024 (80, 21, 23, 554). Alternatively,
> use `setcap cap_net_bind_service=+ep ./target/release/iot-honeypot`.

---

## Output

**Console** — color-coded live feed:

```
#1 2024-01-15T10:23:01 [HTTP:80]   192.168.1.42 connected
#2 2024-01-15T10:23:01 [HTTP:80]   192.168.1.42 tried login: admin:admin
#3 2024-01-15T10:23:02 [Telnet:23] 192.168.1.55 connected
#4 2024-01-15T10:23:04 [Telnet:23] 192.168.1.55 tried login: root:xc3511
```

**Log file** (`honeypot.log`) — one JSON event per line (JSONL), easy to parse:

```json
{"timestamp":"2024-01-15T10:23:01Z","service":"HTTP","port":80,"remote_addr":"192.168.1.42:54321","event_type":"login_attempt","details":{"username":"admin","password":"admin"}}
```

### Analyzing the log

```bash
# All login attempts
grep '"login_attempt"' honeypot.log | jq .

# Top attacking IPs
grep '"connection"' honeypot.log | jq -r '.remote_addr' | cut -d: -f1 | sort | uniq -c | sort -rn

# All credentials tried
grep '"login_attempt"' honeypot.log | jq -r '[.details.username, .details.password] | @csv'

# Commands entered in fake shell
grep '"command"' honeypot.log | jq -r '.details.command'
```

---

## Architecture

```
src/
├── main.rs       — CLI args, banner, spawns all services
├── logger.rs     — Shared async logger (console + JSONL file)
└── services.rs   — All honeypot service implementations
    ├── run_http_honeypot()    — fake camera login page, captures POST creds
    ├── run_telnet_honeypot()  — BusyBox shell sim, logs all commands
    ├── run_rtsp_honeypot()    — RTSP 401 challenge to capture auth headers
    ├── run_ssh_honeypot()     — SSH banner + client data capture
    └── run_ftp_honeypot()     — FTP USER/PASS capture
```

All services run as concurrent `tokio::spawn` tasks sharing a `Arc<Mutex<HoneypotLogger>>`.

---

## Extending

To add a new service, implement a new `run_*_honeypot()` async function in `services.rs` following the same pattern:

1. Bind a `TcpListener`
2. Accept connections in a loop
3. `tokio::spawn` each connection handler
4. Log events with `logger.log_event()`

---

## Legal & Ethics

- Only deploy on networks you own or have explicit written permission to monitor
- Do not expose to the public internet without understanding the implications
- Captured data may include sensitive information — store and handle responsibly
