//! Request Replay & Live Tamper Engine.
//!
//! Takes an intercepted HTTP/1.1 request, allows modifying headers or body,
//! retransmits it to the target server, measures sub-millisecond network timings,
//! and returns the live server response.

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::time::Instant;
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

impl ReplayRequest {
    pub fn new(host: String, port: u16, method: String, path: String) -> Self {
        Self {
            host,
            port,
            use_tls: port == 443,
            method,
            path,
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }

    /// Parses a raw HTTP/1.1 wire payload into a ReplayRequest.
    pub fn from_raw(host: String, port: u16, raw: &[u8]) -> Option<Self> {
        let (method, path, headers, body) = match crate::proto::http1::Http1Parser::parse(raw)? {
            crate::proto::http1::Http1Message::Request {
                method,
                uri,
                headers,
                body,
                ..
            } => (method, uri, headers, body),
            _ => return None,
        };

        Some(Self {
            host,
            port,
            use_tls: port == 443,
            method,
            path,
            headers,
            body,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ReplayMetrics {
    pub connect_latency_ms: f64,
    pub ttfb_ms: f64,
    pub total_duration_ms: f64,
}

#[derive(Debug, Clone)]
pub struct ReplayResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub metrics: ReplayMetrics,
}

pub struct ReplayEngine;

impl ReplayEngine {
    /// Executes a request over TCP socket with precise latency telemetry.
    pub async fn execute(req: &ReplayRequest) -> Result<ReplayResponse> {
        let addr = format!("{}:{}", req.host, req.port);

        let t0 = Instant::now();
        let mut stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| anyhow!("Failed to connect to {}: {}", addr, e))?;
        let connect_latency_ms = t0.elapsed().as_secs_f64() * 1000.0;

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

        let send_t0 = Instant::now();
        stream.write_all(raw.as_bytes()).await?;
        if !req.body.is_empty() {
            stream.write_all(&req.body).await?;
        }
        stream.flush().await?;

        // Read response
        let mut buf = vec![0u8; 65536];
        let n = stream.read(&mut buf).await?;
        let ttfb_ms = send_t0.elapsed().as_secs_f64() * 1000.0;
        let total_duration_ms = t0.elapsed().as_secs_f64() * 1000.0;

        if n == 0 {
            return Err(anyhow!("Remote server closed connection without response"));
        }
        buf.truncate(n);

        let metrics = ReplayMetrics {
            connect_latency_ms,
            ttfb_ms,
            total_duration_ms,
        };

        if let Some(crate::proto::http1::Http1Message::Response {
            status_code,
            headers,
            body,
            ..
        }) = crate::proto::http1::Http1Parser::parse(&buf)
        {
            return Ok(ReplayResponse {
                status_code,
                headers,
                body,
                metrics,
            });
        }

        Ok(ReplayResponse {
            status_code: 200,
            headers: HashMap::new(),
            body: buf,
            metrics,
        })
    }
}
