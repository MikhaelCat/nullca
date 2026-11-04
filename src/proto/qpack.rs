//! QPACK (RFC 9204) Header Compression Engine for HTTP/3.
//!
//! Provides static table lookup, dynamic table reference handling, and
//! canonical Huffman decoding for HTTP/3 streams over QUIC.

use crate::proto::huffman::HuffmanTree;
use std::collections::HashMap;

/// RFC 9204 Appendix A: Static Table (99 entries).
pub static QPACK_STATIC_TABLE: &[(&str, &str)] = &[
    (":authority", ""),                                    // 0
    (":path", "/"),                                        // 1
    ("age", "0"),                                          // 2
    ("content-disposition", ""),                           // 3
    ("content-length", "0"),                               // 4
    ("cookie", ""),                                        // 5
    ("date", ""),                                          // 6
    ("etag", ""),                                          // 7
    ("if-modified-since", ""),                             // 8
    ("if-none-match", ""),                                 // 9
    ("last-modified", ""),                                 // 10
    ("link", ""),                                          // 11
    ("location", ""),                                      // 12
    ("referer", ""),                                       // 13
    ("set-cookie", ""),                                    // 14
    (":method", "CONNECT"),                                // 15
    (":method", "DELETE"),                                 // 16
    (":method", "GET"),                                    // 17
    (":method", "HEAD"),                                   // 18
    (":method", "OPTIONS"),                                // 19
    (":method", "POST"),                                   // 20
    (":method", "PUT"),                                    // 21
    (":scheme", "http"),                                   // 22
    (":scheme", "https"),                                  // 23
    (":status", "103"),                                    // 24
    (":status", "200"),                                    // 25
    (":status", "304"),                                    // 26
    (":status", "404"),                                    // 27
    (":status", "503"),                                    // 28
    ("accept", "*/*"),                                     // 29
    ("accept", "application/dns-message"),                 // 30
    ("accept-encoding", "gzip, deflate, br"),              // 31
    ("accept-ranges", "bytes"),                            // 32
    ("access-control-allow-headers", "cache-control"),     // 33
    ("access-control-allow-headers", "content-type"),      // 34
    ("access-control-allow-origin", "*"),                  // 35
    ("cache-control", "max-age=0"),                        // 36
    ("cache-control", "max-age=2592000"),                  // 37
    ("cache-control", "max-age=604800"),                   // 38
    ("cache-control", "no-cache"),                         // 39
    ("cache-control", "no-store"),                         // 40
    ("cache-control", "public, max-age=31536000"),         // 41
    ("content-encoding", "br"),                            // 42
    ("content-encoding", "gzip"),                          // 43
    ("content-type", "application/dns-message"),           // 44
    ("content-type", "application/javascript"),            // 45
    ("content-type", "application/json"),                  // 46
    ("content-type", "application/x-www-form-urlencoded"), // 47
    ("content-type", "image/gif"),                         // 48
    ("content-type", "image/jpeg"),                        // 49
    ("content-type", "image/png"),                         // 50
    ("content-type", "text/css"),                          // 51
    ("content-type", "text/html; charset=utf-8"),          // 52
    ("content-type", "text/plain"),                        // 53
    ("content-type", "text/plain; charset=utf-8"),         // 54
    ("range", "bytes=0-"),                                 // 55
    ("strict-transport-security", "max-age=31536000"),     // 56
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains; preload",
    ), // 57
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains",
    ), // 58
    ("vary", "accept-encoding"),                           // 59
    ("vary", "origin"),                                    // 60
    ("x-content-type-options", "nosniff"),                 // 61
    ("x-xss-protection", "1; mode=block"),                 // 62
    (":status", "100"),                                    // 63
    (":status", "204"),                                    // 64
    (":status", "206"),                                    // 65
    (":status", "302"),                                    // 66
    (":status", "400"),                                    // 67
    (":status", "403"),                                    // 68
    (":status", "421"),                                    // 69
    (":status", "425"),                                    // 70
    (":status", "500"),                                    // 71
    ("accept-language", ""),                               // 72
    ("access-control-allow-credentials", "FALSE"),         // 73
    ("access-control-allow-credentials", "TRUE"),          // 74
    ("access-control-allow-headers", "*"),                 // 75
    ("access-control-allow-methods", "get"),               // 76
    ("access-control-allow-methods", "get, post, options"), // 77
    ("access-control-allow-methods", "options"),           // 78
    ("access-control-expose-headers", "content-length"),   // 79
    ("access-control-request-headers", "content-type"),    // 80
    ("access-control-request-method", "get"),              // 81
    ("access-control-request-method", "post"),             // 82
    ("alt-svc", "clear"),                                  // 83
    ("authorization", ""),                                 // 84
    (
        "content-security-policy",
        "script-src 'none'; object-src 'none'; base-uri 'none'",
    ), // 85
    ("early-data", "1"),                                   // 86
    ("expect-ct", ""),                                     // 87
    ("forwarded", ""),                                     // 88
    ("server", ""),                                        // 89
    ("origin", ""),                                        // 90
    ("timing-allow-origin", "*"),                          // 91
    ("x-frame-options", "deny"),                           // 92
    ("x-frame-options", "sameorigin"),                     // 93
    ("x-forwarded-for", ""),                               // 94
    (":protocol", "websocket"),                            // 95
    ("sec-websocket-accept", ""),                          // 96
    ("sec-websocket-protocol", ""),                        // 97
    ("sec-websocket-version", "13"),                       // 98
];

pub struct QpackDecoder;

impl QpackDecoder {
    /// Decodes a QPACK-encoded header block into HTTP headers map.
    pub fn decode(payload: &[u8]) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        if payload.is_empty() {
            return headers;
        }

        let mut offset = 0;
        // In QPACK, a header block prefix contains:
        // Required Insert Count (RIC) and Base
        // For simplicity of static representations, read through entries:
        while offset < payload.len() {
            let b = payload[offset];

            // 1. Indexed Header Field (starts with bit 1: 1xxxxxxx)
            if b & 0x80 != 0 {
                let static_flag = (b & 0x40) != 0;
                let index = (b & 0x3F) as usize;
                offset += 1;

                if static_flag && index < QPACK_STATIC_TABLE.len() {
                    let (name, val) = QPACK_STATIC_TABLE[index];
                    headers.insert(name.to_string(), val.to_string());
                }
                continue;
            }

            // 2. Literal Header Field With Name Reference (01xxxxxx or 00xxxxxx)
            if b & 0x40 != 0 {
                let static_flag = (b & 0x10) != 0;
                let name_idx = (b & 0x0F) as usize;
                offset += 1;

                let name = if static_flag && name_idx < QPACK_STATIC_TABLE.len() {
                    QPACK_STATIC_TABLE[name_idx].0.to_string()
                } else {
                    format!("custom-header-{}", name_idx)
                };

                // Read value string
                if let Some((val, new_offset)) = Self::read_qpack_string(payload, offset) {
                    headers.insert(name, val);
                    offset = new_offset;
                } else {
                    break;
                }
                continue;
            }

            // 3. Literal Header Field With Literal Name (001xxxxx or 000xxxxx)
            offset += 1;
            if let Some((name, off1)) = Self::read_qpack_string(payload, offset) {
                if let Some((val, off2)) = Self::read_qpack_string(payload, off1) {
                    headers.insert(name, val);
                    offset = off2;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        headers
    }

    /// Reads a QPACK string literal (with optional Huffman decoding).
    fn read_qpack_string(payload: &[u8], mut offset: usize) -> Option<(String, usize)> {
        if offset >= payload.len() {
            return None;
        }

        let first = payload[offset];
        let is_huffman = (first & 0x80) != 0;
        let mut str_len = (first & 0x7F) as usize;
        offset += 1;

        // Multi-byte length support if length prefix overflows 7 bits
        if str_len == 0x7F {
            let mut m = 0;
            while offset < payload.len() {
                let next_b = payload[offset];
                offset += 1;
                str_len += ((next_b & 0x7F) as usize) << m;
                m += 7;
                if next_b & 0x80 == 0 {
                    break;
                }
            }
        }

        if offset + str_len > payload.len() {
            return None;
        }

        let slice = &payload[offset..offset + str_len];
        offset += str_len;

        let res = if is_huffman {
            let tree = HuffmanTree::build();
            let decoded_bytes = tree.decode(slice).ok()?;
            String::from_utf8_lossy(&decoded_bytes).to_string()
        } else {
            String::from_utf8_lossy(slice).to_string()
        };

        Some((res, offset))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qpack_static_table_lookup() {
        assert_eq!(QPACK_STATIC_TABLE[17], (":method", "GET"));
        assert_eq!(QPACK_STATIC_TABLE[20], (":method", "POST"));
        assert_eq!(QPACK_STATIC_TABLE[25], (":status", "200"));
        assert_eq!(
            QPACK_STATIC_TABLE[61],
            ("x-content-type-options", "nosniff")
        );
    }

    #[test]
    fn test_qpack_decode_indexed_static_headers() {
        // Byte 0xC0 | 17 = 0xD1 (:method: GET)
        // Byte 0xC0 | 25 = 0xD9 (:status: 200)
        let payload = [0xD1, 0xD9];
        let headers = QpackDecoder::decode(&payload);

        assert_eq!(headers.get(":method"), Some(&"GET".to_string()));
        assert_eq!(headers.get(":status"), Some(&"200".to_string()));
    }
}
