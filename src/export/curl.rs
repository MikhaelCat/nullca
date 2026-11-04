//! "Copy as cURL" Generator.
//!
//! Generates ready-to-run shell `curl` commands from captured HTTP/1.1 and HTTP/2 requests.

use crate::proto::http1::{Http1Message, Http1Parser};
use crate::proto::http2::Http2Parser;
use std::collections::HashMap;

pub struct CurlExporter;

impl CurlExporter {
    /// Generates a bash-compatible `curl` command string from raw intercepted payload.
    pub fn from_payload(data: &[u8]) -> Option<String> {
        // Try HTTP/1.1 first
        if let Some(Http1Message::Request {
            method,
            uri,
            headers,
            body,
            ..
        }) = Http1Parser::parse(data)
        {
            let host = headers
                .get("host")
                .cloned()
                .unwrap_or_else(|| "127.0.0.1".into());
            let full_url = if uri.starts_with("http://") || uri.starts_with("https://") {
                uri
            } else {
                format!("https://{}{}", host, uri)
            };

            return Some(Self::format_curl(&method, &full_url, &headers, &body));
        }

        // Try HTTP/2 frame stream
        let frames = Http2Parser::parse_frames(data);
        let mut method = "GET".to_string();
        let mut path = "/".to_string();
        let mut authority = "127.0.0.1".to_string();
        let mut scheme = "https".to_string();
        let mut headers = HashMap::new();
        let mut body = Vec::new();
        let mut is_h2_req = false;

        let mut hpack = crate::proto::http2::HpackDecoder::default();

        for frame in frames {
            match frame.frame_type {
                crate::proto::http2::Http2FrameType::Headers => {
                    is_h2_req = true;
                    if let Ok(fields) = hpack.decode(&frame.payload) {
                        for field in fields {
                            match field.name.as_str() {
                                ":method" => method = field.value,
                                ":path" => path = field.value,
                                ":authority" => authority = field.value,
                                ":scheme" => scheme = field.value,
                                other => {
                                    if !other.starts_with(':') {
                                        headers.insert(other.to_string(), field.value);
                                    }
                                }
                            }
                        }
                    }
                }
                crate::proto::http2::Http2FrameType::Data => {
                    body.extend_from_slice(&frame.payload);
                }
                _ => {}
            }
        }

        if is_h2_req {
            let full_url = format!("{}://{}{}", scheme, authority, path);
            return Some(Self::format_curl(&method, &full_url, &headers, &body));
        }

        None
    }

    fn format_curl(
        method: &str,
        url: &str,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> String {
        let mut cmd = format!(
            "curl -X {} '{}'",
            method.to_uppercase(),
            escape_single_quotes(url)
        );

        // Add headers (excluding content-length which curl handles automatically)
        let mut sorted_headers: Vec<(&String, &String)> = headers.iter().collect();
        sorted_headers.sort_by_key(|(k, _)| (*k).clone());

        for (k, v) in sorted_headers {
            if k.eq_ignore_ascii_case("content-length") {
                continue;
            }
            cmd.push_str(&format!(
                " \\\n  -H '{}: {}'",
                escape_single_quotes(k),
                escape_single_quotes(v)
            ));
        }

        if !body.is_empty() {
            if let Ok(body_str) = std::str::from_utf8(body) {
                cmd.push_str(&format!(
                    " \\\n  --data-raw '{}'",
                    escape_single_quotes(body_str)
                ));
            } else {
                cmd.push_str(&format!(
                    " \\\n  --data-binary $'{}'",
                    escape_hex_binary(body)
                ));
            }
        }

        cmd
    }
}

fn escape_single_quotes(input: &str) -> String {
    input.replace('\'', "'\\''")
}

fn escape_hex_binary(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("\\x{:02x}", b))
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_curl_http1() {
        let raw = b"POST /api/v1/auth/login HTTP/1.1\r\nHost: api.internal.corp\r\nAuthorization: Bearer token123\r\nContent-Type: application/json\r\n\r\n{\"user\":\"admin\"}";
        let curl = CurlExporter::from_payload(raw).expect("Should generate cURL command");

        assert!(curl.contains("curl -X POST 'https://api.internal.corp/api/v1/auth/login'"));
        assert!(curl.contains("-H 'authorization: Bearer token123'"));
        assert!(curl.contains("-H 'content-type: application/json'"));
        assert!(curl.contains("--data-raw '{\"user\":\"admin\"}'"));
    }
}
