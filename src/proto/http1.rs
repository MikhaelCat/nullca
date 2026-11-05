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
        // Zero-allocation byte boundary search to avoid offset drift with non-ASCII headers
        let (header_end, body_start) =
            if let Some(pos) = payload.windows(4).position(|w| w == b"\r\n\r\n") {
                (pos, pos + 4)
            } else {
                let pos = payload.windows(2).position(|w| w == b"\n\n")?;
                (pos, pos + 2)
            };

        let header_part = String::from_utf8_lossy(&payload[..header_end]);
        let raw_body = if body_start < payload.len() {
            &payload[body_start..]
        } else {
            &[]
        };

        let mut lines = header_part.lines();
        let start_line = lines.next()?.trim();

        let mut headers = HashMap::new();
        let mut conflicting_content_length = false;

        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                let key = k.trim().to_lowercase();
                let val = v.trim().to_string();

                if key == "content-length" {
                    // Check for duplicate / conflicting Content-Length headers (CL.CL smuggling)
                    if let Some(existing) = headers.get("content-length") {
                        if existing != &val {
                            conflicting_content_length = true;
                        }
                    }
                    if val.contains(',') {
                        let parts: Vec<&str> = val.split(',').map(|s| s.trim()).collect();
                        if parts.windows(2).any(|w| w[0] != w[1]) {
                            conflicting_content_length = true;
                        }
                    }
                }
                headers.insert(key, val);
            }
        }

        if conflicting_content_length {
            headers.insert(
                "x-nullca-smuggling-risk".to_string(),
                "conflicting-content-length".to_string(),
            );
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

                let body = Self::process_body(&headers, raw_body);

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

                let body = Self::process_body(&headers, raw_body);

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
        if let Some(cl_str) = headers.get("content-length") {
            let clean_cl = cl_str.split(',').next().unwrap_or("").trim();
            if let Ok(cl) = clean_cl.parse::<usize>() {
                if cl < raw_body.len() {
                    return raw_body[..cl].to_vec();
                }
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

    #[test]
    fn test_parse_http1_non_ascii_header_offset_safety() {
        // Contains invalid UTF-8 byte 0xFF inside header, followed by exact body
        let mut raw = Vec::new();
        raw.extend_from_slice(b"POST /upload HTTP/1.1\r\nHost: example.com\r\nX-Custom: ");
        raw.push(0xFF); // Invalid UTF-8 byte
        raw.extend_from_slice(b"\r\nContent-Length: 4\r\n\r\nTEST");

        let parsed = Http1Parser::parse(&raw).expect("Must parse despite non-ascii header");
        if let Http1Message::Request { body, .. } = parsed {
            assert_eq!(
                &body, b"TEST",
                "Body bytes must not be shifted by non-ASCII replacement"
            );
        } else {
            panic!("Expected Request");
        }
    }

    #[test]
    fn test_parse_http1_conflicting_content_length_detection() {
        let raw = b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\n12345";
        let parsed = Http1Parser::parse(raw).expect("Should parse");
        if let Http1Message::Request { headers, .. } = parsed {
            assert_eq!(
                headers.get("x-nullca-smuggling-risk").map(|s| s.as_str()),
                Some("conflicting-content-length")
            );
        } else {
            panic!("Expected Request");
        }
    }
}
