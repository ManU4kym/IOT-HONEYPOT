# 🍯 IoT Honeypot

___     _____   _   _                                   _
 |__|_____|_   _| | | | ___  _ __   ___ _   _ _ __   ___ | |_
  | |/_ \  | |   | |_| |/ _ \| '_ \ / _\ | | | '_ \ / _\| __|
  | | (_) | | |   |  _  | (_) | | | |  __/ |_| | |_) | (_) | |_
 |___\___/  |_|   |_| |_|\___/|_| |_|\___|\__, | .__/ \___/ \__|
                                           |___/|_|

  Local IoT Honeypot — Defensive Security Tool
  Simulates vulnerable IoT devices to detect network probes
  All captured data is stored locally. For use on your own network only.

A sophisticated local honeypot written in Rust that simulates vulnerable IoT devices to detect, log, and analyze unauthorized network probes and intrusion attempts on your network.

> 🛡️ __Defensive Security Only__ — Deploy this on networks you own or have explicit written permission to monitor. This tool is designed for security research and threat analysis.

---

## 🎯 Simulated Services

This honeypot emulates the following vulnerable IoT device interfaces to attract and log attacker behavior:

| Service | Port(s) | Simulates | Target |
|---------|---------|-----------|--------|
| __HTTP__ | 80, 8080 | IP camera web login panel | Web-based credential theft |
| __Telnet__ | 23 | BusyBox router shell | Mirai botnet and legacy IoT exploits |
| __RTSP__ | 554 | IP camera stream endpoint | Unauthorized stream access |
| __SSH__ | 2222 | OpenSSH server | Client fingerprint & config capture |
| __FTP__ | 21 | vsFTPd file server | FTP credential harvesting |

---

## 🚀 Getting Started

### Prerequisites

You'll need the following tools installed on your system:

- __Rust & Cargo__ ([install here](https://rustup.rs)) — the Rust toolchain and package manager
- __Linux/macOS or WSL__ (on Windows) — required for binding to ports < 1024
- __Administrator/sudo access__ — needed to run privileged network listeners

### Installation & Execution

#### 1. Build the Project

```bash
cd iot-honeypot
cargo build --release
```

#### 2. Run the Honeypot

__Default settings__ (all services enabled on 0.0.0.0):

```bash
sudo ./target/release/iot-honeypot
```

__Custom configuration__:

```bash
sudo ./target/release/iot-honeypot \
  --bind 0.0.0.0 \
  --output /var/log/honeypot.log \
  --no-ssh        # disable specific services
```

__View all options__:

```bash
./target/release/iot-honeypot --help
```

> __Privilege Note__: `sudo` is required for ports below 1024 (80, 21, 23, 554).  
> Alternatively, grant capabilities: `setcap cap_net_bind_service=+ep ./target/release/iot-honeypot`

---

## 📊 Output & Logging

The honeypot generates real-time logs in two formats for maximum visibility and flexibility.

### Console Output

Color-coded, streaming feed of all events as they occur:

```
#1 2024-01-15T10:23:01 [HTTP:80]   192.168.1.42 connected
#2 2024-01-15T10:23:01 [HTTP:80]   192.168.1.42 tried login: admin:admin
#3 2024-01-15T10:23:02 [Telnet:23] 192.168.1.55 connected
#4 2024-01-15T10:23:04 [Telnet:23] 192.168.1.55 tried login: root:xc3511
```

### JSON Log File (JSONL)

Structured log file output — one event per line, machine-readable and easy to parse. Default location: `honeypot.log`

```json
{"timestamp":"2024-01-15T10:23:01Z","service":"HTTP","port":80,"remote_addr":"192.168.1.42:54321","event_type":"login_attempt","details":{"username":"admin","password":"admin"}}
{"timestamp":"2024-01-15T10:23:02Z","service":"Telnet","port":23,"remote_addr":"192.168.1.55:43210","event_type":"connection","details":{}}
```

### Analyzing Logs

Use these commands to extract useful threat intelligence from your logs:

```bash
# 🔍 View all login attempts
grep '"login_attempt"' honeypot.log | jq .

# 📈 Top attacking IPs (by frequency)
grep '"connection"' honeypot.log | jq -r '.remote_addr' | cut -d: -f1 | sort | uniq -c | sort -rn

# 🔐 All credentials attempted
grep '"login_attempt"' honeypot.log | jq -r '[.details.username, .details.password] | @csv'

# ⌨️ Commands executed in fake shell
grep '"command"' honeypot.log | jq -r '.details.command'
```

## 🧪 Example Run (demo)

Here is a short capture from a local demo run (console-style and raw JSONL lines taken from `honeypot.log`). Use this as a reference to show what the honeypot produces in real-world testing.

### Console (human-readable) — sample

```
#1 2026-02-24T14:39:21 [HTTP:80]  127.0.0.1:21326 connected
#2 2026-02-24T14:39:21 [HTTP:80]  127.0.0.1:21326 scan: GET /
#3 2026-02-24T14:40:36 [HTTP:80]  127.0.0.1:21352 tried login: admin:admin
#4 2026-02-24T14:43:59 [SSH:2222]  127.0.0.1:21413 data: SSH-2.0-OpenSSH_for_Windows_8.1
#5 2026-02-24T14:45:05 [FTP:21]   127.0.0.1:21446 tried login: U:S
```

### JSONL (raw) — sample entries from `honeypot.log`

```json
{"timestamp":"2026-02-24T14:39:21.254219100+00:00","service":"HTTP","port":80,"remote_addr":"127.0.0.1:21326","event_type":"connection","details":{}}
{"timestamp":"2026-02-24T14:40:36.525203100+00:00","service":"HTTP","port":80,"remote_addr":"127.0.0.1:21352","event_type":"login_attempt","details":{"password":"admin","path":"POST / HTTP/1.1","username":"admin"}}
{"timestamp":"2026-02-24T14:43:59.295155300+00:00","service":"SSH","port":2222,"remote_addr":"127.0.0.1:21413","event_type":"data","details":{"banner_response":true,"raw":"SSH-2.0-OpenSSH_for_Windows_8.1"}}
{"timestamp":"2026-02-24T14:45:05.957879300+00:00","service":"FTP","port":21,"remote_addr":"127.0.0.1:21446","event_type":"login_attempt","details":{"password":"S","username":"U"}}
```

Notes:

- The console output is a human-friendly rendering of the JSONL events; timestamps, service labels, and event descriptions are derived from the underlying JSON.
- Use the JSONL file for automated analysis (jq, Python, SIEM ingestion).

---

## 🏗️ Architecture

The project is organized into three main modules:

```
src/
├── main.rs       → Entry point: CLI argument parsing, banner, service orchestration
├── logger.rs     → Shared async logger: writes to both console and JSONL file
└── services.rs   → All honeypot implementations
    ├── run_http_honeypot()    — Fake IP camera login interface, captures POST credentials
    ├── run_telnet_honeypot()  — BusyBox shell emulation, logs all commands and attempts
    ├── run_rtsp_honeypot()    — RTSP 401 authentication challenge to capture headers
    ├── run_ssh_honeypot()     — SSH banner + client fingerprint capture
    └── run_ftp_honeypot()     — FTP USER/PASS credential capture
```

__Key Design Patterns__:

- __Concurrent Execution__: All services run as independent `tokio::spawn` tasks
- __Shared Logger__: Uses `Arc<Mutex<HoneypotLogger>>` for thread-safe logging
- __Async I/O__: Built on `tokio` runtime for high-performance connection handling
- __Modular Services__: Each honeypot is self-contained and can be independently enabled/disabled

---

## 🔧 Extending the Honeypot

To add a new service, implement a new `run_*_honeypot()` async function in `services.rs` following this pattern:

```rust
pub async fn run_new_honeypot(logger: Arc<Mutex<HoneypotLogger>>) {
    let listener = TcpListener::bind("0.0.0.0:PORT").await.unwrap();
    
    loop {
        let (socket, addr) = listener.accept().await.unwrap();
        let logger = Arc::clone(&logger);
        
        tokio::spawn(async move {
            // Handle the connection
            logger.lock().unwrap().log_event(/* ... */);
        });
    }
}
```

__Steps__:

1. Create a `TcpListener` on your target port
2. Accept connections in an infinite loop
3. Spawn each connection as a separate tokio task
4. Log events using `logger.log_event()`
5. Register your service in `main()`

---

## ⚖️ Legal & Responsible Use

Please deploy this tool responsibly:

- ✅ __Deploy on networks you own__ or have __explicit written permission__ from the network owner
- ✅ __Do not expose__ to the public internet without understanding legal implications
- ✅ __Handle captured data securely__ — credentials and behavioral data may be sensitive
- ✅ __Comply with local laws__ regarding monitoring and data retention
- ❌ __Do not use__ for unauthorized network intrusion or surveillance
- ❌ __Do not share__ captured data without proper anonymization and consent

This tool is intended for __defensive security research and threat analysis only__.
