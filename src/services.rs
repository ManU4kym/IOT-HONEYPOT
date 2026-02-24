use crate::logger::{EventType, HoneypotLogger};
use serde_json::json;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

type SharedLogger = Arc<Mutex<HoneypotLogger>>;

// ─── HTTP Honeypot ────────────────────────────────────────────────────────────
// Simulates a web interface for an IP camera / router admin panel

pub async fn run_http_honeypot(bind: &str, port: u16, logger: SharedLogger) {
    let addr = format!("{}:{}", bind, port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("HTTP honeypot failed to bind {}:{} — {}", bind, port, e);
            return;
        }
    };

    loop {
        if let Ok((mut socket, peer)) = listener.accept().await {
            let logger = Arc::clone(&logger);
            let remote = peer.to_string();
            let port_copy = port;

            tokio::spawn(async move {
                logger.lock().await.log_event(
                    "HTTP",
                    port_copy,
                    &remote,
                    EventType::Connection,
                    json!({}),
                );

                let mut buf = vec![0u8; 4096];
                let n = match socket.read(&mut buf).await {
                    Ok(n) => n,
                    Err(_) => return,
                };
                let request = String::from_utf8_lossy(&buf[..n]);
                let first_line = request.lines().next().unwrap_or("").to_string();

                // Check for login attempts in POST bodies
                if request.contains("POST") {
                    let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
                    let (user, pass) = parse_form_creds(body);
                    logger.lock().await.log_event(
                        "HTTP",
                        port_copy,
                        &remote,
                        EventType::LoginAttempt,
                        json!({ "username": user, "password": pass, "path": first_line }),
                    );
                } else {
                    logger.lock().await.log_event(
                        "HTTP",
                        port_copy,
                        &remote,
                        EventType::Scan,
                        json!({ "request": first_line }),
                    );
                }

                // Serve a fake camera login page
                let html = fake_camera_login_page(port_copy);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nServer: mini_httpd/1.19 19dec2003\r\nX-Powered-By: IP-Camera/2.4\r\n\r\n{}",
                    html.len(),
                    html
                );
                let _ = socket.write_all(response.as_bytes()).await;

                logger.lock().await.log_event(
                    "HTTP",
                    port_copy,
                    &remote,
                    EventType::Disconnect,
                    json!({}),
                );
            });
        }
    }
}

fn parse_form_creds(body: &str) -> (String, String) {
    let mut user = String::from("(unknown)");
    let mut pass = String::from("(unknown)");
    for part in body.split('&') {
        if let Some((k, v)) = part.split_once('=') {
            let k = k.to_lowercase();
            let v = v.replace('+', " ");
            if k.contains("user") || k == "login" || k == "name" {
                user = v;
            } else if k.contains("pass") || k == "pwd" {
                pass = v;
            }
        }
    }
    (user, pass)
}

fn fake_camera_login_page(port: u16) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>IP Camera Login</title>
<style>
  body {{ background:#1a1a2e; color:#eee; font-family:Arial; display:flex; justify-content:center; align-items:center; height:100vh; margin:0; }}
  .box {{ background:#16213e; padding:40px; border-radius:8px; box-shadow:0 0 20px #0f3460; width:320px; }}
  h2 {{ color:#e94560; text-align:center; }}
  input {{ width:100%; padding:10px; margin:8px 0; background:#0f3460; border:none; color:#fff; border-radius:4px; box-sizing:border-box; }}
  button {{ width:100%; padding:10px; background:#e94560; border:none; color:#fff; border-radius:4px; cursor:pointer; }}
  .brand {{ text-align:center; color:#aaa; font-size:12px; margin-top:10px; }}
</style>
</head>
<body>
<div class="box">
  <h2>📷 IP Camera</h2>
  <form method="POST" action="/">
    <input type="text" name="username" placeholder="Username" /><br/>
    <input type="password" name="password" placeholder="Password" /><br/>
    <button type="submit">Login</button>
  </form>
  <div class="brand">NetCam Pro v2.4 — Port {}</div>
</div>
</body>
</html>"#,
        port
    )
}

// ─── Telnet Honeypot ──────────────────────────────────────────────────────────
// Simulates a classic IoT device Telnet shell (like Mirai targets)

pub async fn run_telnet_honeypot(bind: &str, port: u16, logger: SharedLogger) {
    let addr = format!("{}:{}", bind, port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Telnet honeypot failed to bind {}:{} — {}", bind, port, e);
            return;
        }
    };

    loop {
        if let Ok((socket, peer)) = listener.accept().await {
            let logger = Arc::clone(&logger);
            let remote = peer.to_string();
            let port_copy = port;

            tokio::spawn(async move {
                logger.lock().await.log_event(
                    "Telnet",
                    port_copy,
                    &remote,
                    EventType::Connection,
                    json!({}),
                );

                let (reader, mut writer) = socket.into_split();
                let mut reader = BufReader::new(reader);

                // Send fake login prompt
                let _ = writer
                    .write_all(
                        b"\r\nBusyBox v1.19.4 (2014-03-27 23:20:41 CST) built-in shell (ash)\r\n",
                    )
                    .await;
                let _ = writer
                    .write_all(b"Enter 'help' for a list of built-in commands.\r\n\r\n")
                    .await;
                let _ = writer.write_all(b"Login: ").await;

                let mut line = String::new();
                let mut username = String::new();
                let mut stage = 0u8; // 0=user, 1=pass, 2=shell

                loop {
                    line.clear();
                    match reader.read_line(&mut line).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                    let input = line.trim().to_string();

                    match stage {
                        0 => {
                            username = input.clone();
                            let _ = writer.write_all(b"Password: ").await;
                            stage = 1;
                        }
                        1 => {
                            logger.lock().await.log_event(
                                "Telnet",
                                port_copy,
                                &remote,
                                EventType::LoginAttempt,
                                json!({ "username": username, "password": input }),
                            );
                            // Always "succeed" to capture commands
                            let _ = writer.write_all(b"\r\n# ").await;
                            stage = 2;
                        }
                        2 => {
                            if input.is_empty() {
                                let _ = writer.write_all(b"# ").await;
                                continue;
                            }
                            logger.lock().await.log_event(
                                "Telnet",
                                port_copy,
                                &remote,
                                EventType::Command,
                                json!({ "command": input }),
                            );
                            // Fake responses for common commands
                            let response = fake_shell_response(&input);
                            let _ = writer.write_all(response.as_bytes()).await;
                            let _ = writer.write_all(b"# ").await;
                        }
                        _ => {}
                    }
                }

                logger.lock().await.log_event(
                    "Telnet",
                    port_copy,
                    &remote,
                    EventType::Disconnect,
                    json!({}),
                );
            });
        }
    }
}

fn fake_shell_response(cmd: &str) -> String {
    let cmd_lower = cmd.to_lowercase();
    let base = cmd_lower.split_whitespace().next().unwrap_or("");
    match base {
        "ls" => "bin  dev  etc  home  proc  tmp  usr  var\r\n".to_string(),
        "pwd" => "/root\r\n".to_string(),
        "whoami" => "root\r\n".to_string(),
        "id" => "uid=0(root) gid=0(root)\r\n".to_string(),
        "cat" => "cat: permission denied\r\n".to_string(),
        "uname" => "Linux router 2.6.36 #1 SMP PREEMPT Fri Mar 14 11:26:04 CST 2014 mips unknown\r\n".to_string(),
        "ifconfig" | "ip" => "eth0      Link encap:Ethernet  HWaddr 00:1A:2B:3C:4D:5E\r\n          inet addr:192.168.1.1  Bcast:192.168.1.255  Mask:255.255.255.0\r\n".to_string(),
        "ps" => "  PID USER       VSZ STAT COMMAND\r\n    1 root      1236 S    /sbin/init\r\n    2 root         0 SW   [kthreadd]\r\n  142 root      2056 S    httpd\r\n  199 root      1872 S    telnetd\r\n".to_string(),
        "exit" | "logout" | "quit" => "\r\n".to_string(),
        "wget" | "curl" => "Download failed: connection refused\r\n".to_string(),
        "help" => "Available commands: ls pwd whoami id uname ifconfig ps cat wget curl\r\n".to_string(),
        _ => format!("{}: command not found\r\n", base),
    }
}

// ─── RTSP Honeypot ────────────────────────────────────────────────────────────
// Simulates an IP camera RTSP stream endpoint

pub async fn run_rtsp_honeypot(bind: &str, port: u16, logger: SharedLogger) {
    let addr = format!("{}:{}", bind, port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("RTSP honeypot failed to bind {}:{} — {}", bind, port, e);
            return;
        }
    };

    loop {
        if let Ok((mut socket, peer)) = listener.accept().await {
            let logger = Arc::clone(&logger);
            let remote = peer.to_string();
            let port_copy = port;

            tokio::spawn(async move {
                logger.lock().await.log_event(
                    "RTSP",
                    port_copy,
                    &remote,
                    EventType::Connection,
                    json!({}),
                );

                let mut buf = vec![0u8; 2048];
                let n = match socket.read(&mut buf).await {
                    Ok(n) => n,
                    Err(_) => return,
                };
                let request = String::from_utf8_lossy(&buf[..n]);
                let first_line = request.lines().next().unwrap_or("").to_string();

                // Check for credentials in Authorization header
                let auth = request
                    .lines()
                    .find(|l| l.to_lowercase().starts_with("authorization:"))
                    .unwrap_or("")
                    .to_string();

                if !auth.is_empty() {
                    logger.lock().await.log_event(
                        "RTSP",
                        port_copy,
                        &remote,
                        EventType::LoginAttempt,
                        json!({ "authorization": auth, "request": first_line }),
                    );
                } else {
                    logger.lock().await.log_event(
                        "RTSP",
                        port_copy,
                        &remote,
                        EventType::Scan,
                        json!({ "request": first_line }),
                    );
                }

                // Respond with 401 to prompt credential submission
                let response = "RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Basic realm=\"IPCamera\"\r\nServer: HiIPCamera/V100R003\r\n\r\n";
                let _ = socket.write_all(response.as_bytes()).await;

                logger.lock().await.log_event(
                    "RTSP",
                    port_copy,
                    &remote,
                    EventType::Disconnect,
                    json!({}),
                );
            });
        }
    }
}

// ─── SSH Honeypot ─────────────────────────────────────────────────────────────
// Simulates an SSH banner (no real SSH handshake, just banner + logging)

pub async fn run_ssh_honeypot(bind: &str, port: u16, logger: SharedLogger) {
    let addr = format!("{}:{}", bind, port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("SSH honeypot failed to bind {}:{} — {}", bind, port, e);
            return;
        }
    };

    loop {
        if let Ok((mut socket, peer)) = listener.accept().await {
            let logger = Arc::clone(&logger);
            let remote = peer.to_string();
            let port_copy = port;

            tokio::spawn(async move {
                logger.lock().await.log_event(
                    "SSH",
                    port_copy,
                    &remote,
                    EventType::Connection,
                    json!({}),
                );

                // Send SSH version banner
                let _ = socket
                    .write_all(b"SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10\r\n")
                    .await;

                // Read what client sends
                let mut buf = vec![0u8; 256];
                if let Ok(n) = socket.read(&mut buf).await {
                    let data = String::from_utf8_lossy(&buf[..n]);
                    let printable: String = data
                        .chars()
                        .filter(|c| c.is_ascii_graphic() || c.is_whitespace())
                        .collect();
                    logger.lock().await.log_event(
                        "SSH",
                        port_copy,
                        &remote,
                        EventType::Data,
                        json!({ "raw": printable.trim(), "banner_response": true }),
                    );
                }

                logger.lock().await.log_event(
                    "SSH",
                    port_copy,
                    &remote,
                    EventType::Disconnect,
                    json!({}),
                );
            });
        }
    }
}

// ─── FTP Honeypot ─────────────────────────────────────────────────────────────
// Simulates an FTP server login, capturing credentials

pub async fn run_ftp_honeypot(bind: &str, port: u16, logger: SharedLogger) {
    let addr = format!("{}:{}", bind, port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("FTP honeypot failed to bind {}:{} — {}", bind, port, e);
            return;
        }
    };

    loop {
        if let Ok((socket, peer)) = listener.accept().await {
            let logger = Arc::clone(&logger);
            let remote = peer.to_string();
            let port_copy = port;

            tokio::spawn(async move {
                logger.lock().await.log_event(
                    "FTP",
                    port_copy,
                    &remote,
                    EventType::Connection,
                    json!({}),
                );

                let (reader, mut writer) = socket.into_split();
                let mut reader = BufReader::new(reader);

                let _ = writer.write_all(b"220 (vsFTPd 3.0.3)\r\n").await;

                let mut line = String::new();
                let mut username = String::new();

                loop {
                    line.clear();
                    match reader.read_line(&mut line).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                    let input = line.trim();
                    let upper = input.to_uppercase();

                    if upper.starts_with("USER ") {
                        username = input[5..].to_string();
                        let _ = writer
                            .write_all(b"331 Please specify the password.\r\n")
                            .await;
                    } else if upper.starts_with("PASS ") {
                        let password = input[5..].to_string();
                        logger.lock().await.log_event(
                            "FTP",
                            port_copy,
                            &remote,
                            EventType::LoginAttempt,
                            json!({ "username": username, "password": password }),
                        );
                        // Always deny (safer for a honeypot)
                        let _ = writer.write_all(b"530 Login incorrect.\r\n").await;
                        break;
                    } else if upper.starts_with("QUIT") {
                        let _ = writer.write_all(b"221 Goodbye.\r\n").await;
                        break;
                    } else {
                        let _ = writer
                            .write_all(b"530 Please login with USER and PASS.\r\n")
                            .await;
                    }
                }

                logger.lock().await.log_event(
                    "FTP",
                    port_copy,
                    &remote,
                    EventType::Disconnect,
                    json!({}),
                );
            });
        }
    }
}
