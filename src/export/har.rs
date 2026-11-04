//! HTTP Archive (HAR 1.2) Format Exporter.
//!
//! Exports captured plaintext sessions to `.har` files directly readable by
//! Chrome DevTools, Burp Suite, Postman, Insomnia, Charles, and Proxyman.

use crate::engine::event::{Direction, TlsEvent};
use crate::proto::http1::{Http1Message, Http1Parser};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::Path;

#[derive(Serialize, Deserialize, Debug)]
pub struct HarRoot {
    pub log: HarLog,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HarLog {
    pub version: String,
    pub creator: HarCreator,
    pub entries: Vec<HarEntry>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HarCreator {
    pub name: String,
    pub version: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HarEntry {
    #[serde(rename = "startedDateTime")]
    pub started_date_time: String,
    pub time: f64,
    pub request: HarRequest,
    pub response: HarResponse,
    pub cache: serde_json::Value,
    pub timings: HarTimings,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HarRequest {
    pub method: String,
    pub url: String,
    #[serde(rename = "httpVersion")]
    pub http_version: String,
    pub headers: Vec<HarHeader>,
    #[serde(rename = "queryString")]
    pub query_string: Vec<HarQueryParam>,
    #[serde(rename = "postData", skip_serializing_if = "Option::is_none")]
    pub post_data: Option<HarPostData>,
    #[serde(rename = "headersSize")]
    pub headers_size: i64,
    #[serde(rename = "bodySize")]
    pub body_size: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HarResponse {
    pub status: u16,
    #[serde(rename = "statusText")]
    pub status_text: String,
    #[serde(rename = "httpVersion")]
    pub http_version: String,
    pub headers: Vec<HarHeader>,
    pub content: HarContent,
    #[serde(rename = "redirectURL")]
    pub redirect_url: String,
    #[serde(rename = "headersSize")]
    pub headers_size: i64,
    #[serde(rename = "bodySize")]
    pub body_size: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HarHeader {
    pub name: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HarQueryParam {
    pub name: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HarPostData {
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    pub text: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HarContent {
    pub size: i64,
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    pub text: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HarTimings {
    pub send: f64,
    pub wait: f64,
    pub receive: f64,
}

pub struct HarExporter;

impl HarExporter {
    /// Generates a valid HAR 1.2 structure from a collection of captured `TlsEvent`s.
    pub fn export_events(events: &[TlsEvent]) -> HarRoot {
        let mut entries = Vec::new();

        // Pair requests and responses by socket fd
        let mut pending_requests: std::collections::HashMap<i32, (TlsEvent, HarRequest)> =
            std::collections::HashMap::new();

        for event in events {
            if event.direction == Direction::Egress {
                // Outbound request
                if let Some(Http1Message::Request {
                    method,
                    uri,
                    version,
                    headers,
                    body,
                }) = Http1Parser::parse(&event.data)
                {
                    let host = headers.get("host").cloned().unwrap_or_else(|| "localhost".into());
                    let full_url = if uri.starts_with("http") {
                        uri
                    } else {
                        format!("https://{}{}", host, uri)
                    };

                    let har_headers = headers
                        .into_iter()
                        .map(|(k, v)| HarHeader { name: k, value: v })
                        .collect();

                    let post_data = if !body.is_empty() {
                        Some(HarPostData {
                            mime_type: "application/octet-stream".into(),
                            text: String::from_utf8_lossy(&body).to_string(),
                        })
                    } else {
                        None
                    };

                    let body_len = body.len() as i64;
                    let har_req = HarRequest {
                        method,
                        url: full_url,
                        http_version: version,
                        headers: har_headers,
                        query_string: Vec::new(),
                        post_data,
                        headers_size: -1,
                        body_size: body_len,
                    };

                    pending_requests.insert(event.fd, (event.clone(), har_req));
                }
            } else if event.direction == Direction::Ingress {
                // Inbound response
                if let Some((req_ev, har_req)) = pending_requests.remove(&event.fd) {
                    let (status, status_text, resp_headers, body) =
                        if let Some(Http1Message::Response {
                            status_code,
                            reason,
                            headers,
                            body,
                            ..
                        }) = Http1Parser::parse(&event.data)
                        {
                            (status_code, reason, headers, body)
                        } else {
                            (200, "OK".into(), std::collections::HashMap::new(), event.data.clone())
                        };

                    let date = DateTime::<Utc>::from_timestamp(
                        (req_ev.timestamp_ns / 1_000_000_000) as i64,
                        (req_ev.timestamp_ns % 1_000_000_000) as u32,
                    )
                    .unwrap_or_else(Utc::now);

                    let latency_ms = event.latency_us.unwrap_or(1000) as f64 / 1000.0;

                    let har_resp = HarResponse {
                        status,
                        status_text,
                        http_version: "HTTP/1.1".into(),
                        headers: resp_headers
                            .into_iter()
                            .map(|(k, v)| HarHeader { name: k, value: v })
                            .collect(),
                        content: HarContent {
                            size: body.len() as i64,
                            mime_type: "text/plain".into(),
                            text: Some(String::from_utf8_lossy(&body).to_string()),
                        },
                        redirect_url: "".into(),
                        headers_size: -1,
                        body_size: body.len() as i64,
                    };

                    entries.push(HarEntry {
                        started_date_time: date.to_rfc3339(),
                        time: latency_ms,
                        request: har_req,
                        response: har_resp,
                        cache: serde_json::json!({}),
                        timings: HarTimings {
                            send: 0.1,
                            wait: latency_ms * 0.8,
                            receive: latency_ms * 0.2,
                        },
                    });
                }
            }
        }

        HarRoot {
            log: HarLog {
                version: "1.2".into(),
                creator: HarCreator {
                    name: "nullca".into(),
                    version: "0.1.0".into(),
                },
                entries,
            },
        }
    }

    /// Saves HAR object directly to disk.
    pub fn write_to_file<P: AsRef<Path>>(events: &[TlsEvent], path: P) -> std::io::Result<()> {
        let har = Self::export_events(events);
        let serialized = serde_json::to_string_pretty(&har)?;
        let mut file = File::create(path)?;
        file.write_all(serialized.as_bytes())?;
        Ok(())
    }
}
