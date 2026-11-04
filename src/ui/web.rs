//! Embedded Web UI & Remote Monitoring Daemon.
//!
//! Provides a zero-dependency local web dashboard serving real-time intercepted traffic,
//! protocol statistics, and packet inspections to external browsers, tablets, and phones.

use crate::engine::event::TlsEvent;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub static EMBEDDED_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>NullCA ⚡ Zero-CA Web Cockpit</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --cyan: #58a6ff;
      --green: #3fb950;
      --yellow: #d29922;
      --red: #f85149;
      --text: #c9d1d9;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
    body { background: var(--bg); color: var(--text); padding: 20px; }
    header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 15px; margin-bottom: 20px; }
    h1 { color: var(--cyan); font-size: 1.4rem; }
    .badge { background: #238636; color: white; padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; background: var(--card-bg); border-radius: 6px; overflow: hidden; border: 1px solid var(--border); }
    th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
    th { background: #21262d; color: #8b949e; text-transform: uppercase; font-size: 0.75rem; }
    tr:hover { background: #1f242c; cursor: pointer; }
    .egress { color: var(--green); font-weight: bold; }
    .ingress { color: var(--cyan); font-weight: bold; }
    .hexdump { background: #000; color: #58a6ff; padding: 10px; border-radius: 4px; font-size: 0.8rem; white-space: pre-wrap; margin-top: 10px; }
  </style>
</head>
<body>
  <header>
    <h1>⚡ NullCA Remote Cockpit</h1>
    <div>
      <span class="badge" id="status">LIVE CONNECTED</span>
      <span style="margin-left: 10px; color: #8b949e;" id="count">0 packets captured</span>
    </div>
  </header>
  <main>
    <table id="packets">
      <thead>
        <tr>
          <th>#</th>
          <th>Direction</th>
          <th>Process</th>
          <th>PID</th>
          <th>Protocol</th>
          <th>Length</th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>
    <div id="inspector" style="margin-top: 20px; display: none;">
      <h3 style="color: var(--yellow);">Packet Inspector</h3>
      <div class="hexdump" id="payload"></div>
    </div>
  </main>
  <script>
    async function refresh() {
      try {
        const res = await fetch('/api/events');
        const data = await res.json();
        document.getElementById('count').innerText = `${data.length} packets captured`;
        const tbody = document.querySelector('#packets tbody');
        tbody.innerHTML = '';
        data.forEach((pkt, i) => {
          const tr = document.createElement('tr');
          tr.innerHTML = `
            <td>${i + 1}</td>
            <td class="${pkt.direction.toLowerCase()}">${pkt.direction}</td>
            <td>${pkt.comm}</td>
            <td>${pkt.pid}</td>
            <td>${pkt.protocol}</td>
            <td>${pkt.data_len} B</td>
          `;
          tr.onclick = () => {
            document.getElementById('inspector').style.display = 'block';
            document.getElementById('payload').innerText = atob(pkt.data_b64 || '');
          };
          tbody.appendChild(tr);
        });
      } catch(e) {}
    }
    setInterval(refresh, 1000);
    refresh();
  </script>
</body>
</html>
"#;

pub struct WebServer;

impl WebServer {
    /// Launches the embedded HTTP server on specified port.
    pub async fn start(port: u16, events: Arc<Mutex<Vec<TlsEvent>>>) -> anyhow::Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
        println!("🚀 NullCA Web Cockpit is live at: http://127.0.0.1:{}", port);

        loop {
            let (mut socket, _) = listener.accept().await?;
            let events_clone = Arc::clone(&events);

            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                if let Ok(n) = socket.read(&mut buf).await {
                    let req_str = String::from_utf8_lossy(&buf[..n]);
                    if req_str.starts_with("GET /api/events") {
                        let payload = {
                            let ev_lock = events_clone.lock().unwrap();
                            let json_items: Vec<_> = ev_lock.iter().map(|e| {
                                serde_json::json!({
                                    "pid": e.pid,
                                    "comm": e.comm,
                                    "direction": format!("{:?}", e.direction),
                                    "protocol": format!("{:?}", e.protocol()),
                                    "data_len": e.data.len(),
                                    "data_b64": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &e.data),
                                })
                            }).collect();
                            serde_json::to_string(&json_items).unwrap_or_else(|_| "[]".into())
                        };

                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}",
                            payload.len(),
                            payload
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    } else {
                        // Serve HTML
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
                            EMBEDDED_HTML.len(),
                            EMBEDDED_HTML
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    }
                }
            });
        }
    }
}
