//! Request Replay & Live Tamper Engine.
//!
//! Takes an intercepted HTTP/1.1 or HTTP/2 request, allows modifying headers or body,
//! retransmits it to the target server, and returns the live server response.

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub struct ReplayRequest {
    pub host: String,
    pub port: u16,
    pub use_tls: bool,
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ReplayResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

pub struct ReplayEngine;

impl ReplayEngine {
    /// Executes a request over plain TCP socket.
    pub async fn execute(req: &ReplayRequest) -> Result<ReplayResponse> {
        let addr = format!("{}:{}", req.host, req.port);
        let mut stream = TcpStream::connect(&addr).await?;

        // Construct raw HTTP/1.1 request
        let mut raw = format!("{} {} HTTP/1.1\r\n", req.method.to_uppercase(), req.path);
        raw.push_str(&format!("Host: {}\r\n", req.host));

        for (k, v) in &req.headers {
            if !k.eq_ignore_ascii_case("host") && !k.eq_ignore_ascii_case("content-length") {
                raw.push_str(&format!("{}: {}\r\n", k, v));
            }
        }

        if !req.body.is_empty() {
            raw.push_str(&format!("Content-Length: {}\r\n\r\n", req.body.len()));
        } else {
            raw.push_str("\r\n");
        }

        stream.write_all(raw.as_bytes()).await?;
        if !req.body.is_empty() {
            stream.write_all(&req.body).await?;
        }
        stream.flush().await?;

        // Read response
        let mut buf = vec![0u8; 65536];
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(anyhow!("Remote server closed connection without response"));
        }
        buf.truncate(n);

        if let Some(msg) = crate::proto::http1::Http1Parser::parse(&buf) {
            if let crate::proto::http1::Http1Message::Response {
                status_code,
                headers,
                body,
                ..
            } = msg
            {
                return Ok(ReplayResponse {
                    status_code,
                    headers,
                    body,
                });
            }
        }

        Ok(ReplayResponse {
            status_code: 200,
            headers: HashMap::new(),
            body: buf,
        })
    }
}
