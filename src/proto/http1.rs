use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Http1Message {
    Request {
        method: String,
        uri: String,
        version: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    },
    Response {
        version: String,
        status_code: u16,
        reason: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    },
}

pub struct Http1Parser;

impl Http1Parser {
    pub fn parse(payload: &[u8]) -> Option<Http1Message> {
        let text = String::from_utf8_lossy(payload);
        let header_end = text.find("\r\n\r\n")?;

        let header_part = &text[..header_end];
        let body_start = header_end + 4;
        let raw_body = if body_start < payload.len() {
            payload[body_start..].to_vec()
        } else {
            Vec::new()
        };

        let mut lines = header_part.lines();
        let start_line = lines.next()?.trim();

        let mut headers = HashMap::new();
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_lowercase(), v.trim().to_string());
            }
        }

        // Check if Response (starts with HTTP/)
        if start_line.starts_with("HTTP/") {
            let parts: Vec<&str> = start_line.split_whitespace().collect();
            if parts.len() >= 2 {
                let version = parts[0].to_string();
                let status_code = parts[1].parse::<u16>().ok()?;
                let reason = if parts.len() > 2 {
                    parts[2..].join(" ")
                } else {
                    String::new()
                };

                let body = Self::process_body(&headers, &raw_body);

                return Some(Http1Message::Response {
                    version,
                    status_code,
                    reason,
                    headers,
                    body,
                });
            }
        } else {
            // Request: Method URI Version
            let parts: Vec<&str> = start_line.split_whitespace().collect();
            if parts.len() >= 3 {
                let method = parts[0].to_string();
                let uri = parts[1].to_string();
                let version = parts[2].to_string();

                let body = Self::process_body(&headers, &raw_body);

                return Some(Http1Message::Request {
                    method,
                    uri,
                    version,
                    headers,
                    body,
                });
            }
        }

        None
    }

    fn process_body(headers: &HashMap<String, String>, raw_body: &[u8]) -> Vec<u8> {
        if let Some(te) = headers.get("transfer-encoding") {
            if te.to_lowercase().contains("chunked") {
                return Self::decode_chunked(raw_body);
            }
        }
        raw_body.to_vec()
    }

    fn decode_chunked(mut data: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();

        while !data.is_empty() {
            // Find CRLF after chunk size
            let mut newline_pos = None;
            for i in 0..data.len().saturating_sub(1) {
                if data[i] == b'\r' && data[i + 1] == b'\n' {
                    newline_pos = Some(i);
                    break;
                }
            }

            let nl = match newline_pos {
                Some(p) => p,
                None => break,
            };

            let size_str = match std::str::from_utf8(&data[..nl]) {
                Ok(s) => s.trim().split(';').next().unwrap_or("0"),
                Err(_) => break,
            };

            let chunk_size = match usize::from_str_radix(size_str, 16) {
                Ok(sz) => sz,
                Err(_) => break,
            };

            if chunk_size == 0 {
                break; // Final 0-chunk
            }

            let chunk_data_start = nl + 2;
            let chunk_data_end = chunk_data_start + chunk_size;

            if chunk_data_end <= data.len() {
                result.extend_from_slice(&data[chunk_data_start..chunk_data_end]);
                // Advance past chunk + trailing CRLF
                let next_start = (chunk_data_end + 2).min(data.len());
                data = &data[next_start..];
            } else {
                // Partial chunk
                result.extend_from_slice(&data[chunk_data_start..]);
                break;
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http1_request() {
        let raw = b"GET /api/v1/users HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\nAccept: application/json\r\n\r\n";
        let parsed = Http1Parser::parse(raw).expect("Failed to parse request");
        if let Http1Message::Request {
            method,
            uri,
            headers,
            ..
        } = parsed
        {
            assert_eq!(method, "GET");
            assert_eq!(uri, "/api/v1/users");
            assert_eq!(headers.get("host").unwrap(), "example.com");
            assert_eq!(headers.get("user-agent").unwrap(), "curl/8.0");
        } else {
            panic!("Expected Request");
        }
    }

    #[test]
    fn test_parse_http1_response_chunked() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n7\r\nMozilla\r\n9\r\nDeveloper\r\n0\r\n\r\n";
        let parsed = Http1Parser::parse(raw).expect("Failed to parse response");
        if let Http1Message::Response {
            status_code, body, ..
        } = parsed
        {
            assert_eq!(status_code, 200);
            assert_eq!(String::from_utf8_lossy(&body), "MozillaDeveloper");
        } else {
            panic!("Expected Response");
        }
    }
}
