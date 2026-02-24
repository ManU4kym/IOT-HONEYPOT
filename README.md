# 🍯 IoT Honeypot

A sophisticated local honeypot written in Rust that simulates vulnerable IoT devices to detect, log, and analyze unauthorized network probes and intrusion attempts on your network.

> 🛡️ **Defensive Security Only** — Deploy this on networks you own or have explicit written permission to monitor. This tool is designed for security research and threat analysis.

---

## 🎯 Simulated Services

This honeypot emulates the following vulnerable IoT device interfaces to attract and log attacker behavior:

| Service | Port(s) | Simulates | Target |
|---------|---------|-----------|--------|
| **HTTP** | 80, 8080 | IP camera web login panel | Web-based credential theft |
| **Telnet** | 23 | BusyBox router shell | Mirai botnet and legacy IoT exploits |
| **RTSP** | 554 | IP camera stream endpoint | Unauthorized stream access |
| **SSH** | 2222 | OpenSSH server | Client fingerprint & config capture |
| **FTP** | 21 | vsFTPd file server | FTP credential harvesting |

---

## 🚀 Getting Started

### Prerequisites

You'll need the following tools installed on your system:

- **Rust & Cargo** ([install here](https://rustup.rs)) — the Rust toolchain and package manager
- **Linux/macOS or WSL** (on Windows) — required for binding to ports < 1024
- **Administrator/sudo access** — needed to run privileged network listeners

### Installation & Execution

#### 1. Build the Project

```bash
cd iot-honeypot
cargo build --release
```

#### 2. Run the Honeypot

**Default settings** (all services enabled on 0.0.0.0):

```bash
sudo ./target/release/iot-honeypot
```

**Custom configuration**:

```bash
sudo ./target/release/iot-honeypot \
  --bind 0.0.0.0 \
  --output /var/log/honeypot.log \
  --no-ssh        # disable specific services
```

**View all options**:

```bash
./target/release/iot-honeypot --help
```

> **Privilege Note**: `sudo` is required for ports below 1024 (80, 21, 23, 554).  
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

**Key Design Patterns**:

- **Concurrent Execution**: All services run as independent `tokio::spawn` tasks
- **Shared Logger**: Uses `Arc<Mutex<HoneypotLogger>>` for thread-safe logging
- **Async I/O**: Built on `tokio` runtime for high-performance connection handling
- **Modular Services**: Each honeypot is self-contained and can be independently enabled/disabled

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

**Steps**:

1. Create a `TcpListener` on your target port
2. Accept connections in an infinite loop
3. Spawn each connection as a separate tokio task
4. Log events using `logger.log_event()`
5. Register your service in `main()`

---

## ⚖️ Legal & Responsible Use

Please deploy this tool responsibly:

- ✅ **Deploy on networks you own** or have **explicit written permission** from the network owner
- ✅ **Do not expose** to the public internet without understanding legal implications
- ✅ **Handle captured data securely** — credentials and behavioral data may be sensitive
- ✅ **Comply with local laws** regarding monitoring and data retention
- ❌ **Do not use** for unauthorized network intrusion or surveillance
- ❌ **Do not share** captured data without proper anonymization and consent

This tool is intended for **defensive security research and threat analysis only**.
