//! HTTP/3 & QUIC Framing Engine (RFC 9114 & RFC 9000).
//!
//! Parses variable-length integer prefixed HTTP/3 frames (DATA, HEADERS, SETTINGS, GOAWAY)
//! and integrates with the RFC 9204 QPACK decompressor to inspect plaintext HTTP/3 headers.

use crate::proto::qpack::QpackDecoder;

/// RFC 9114 HTTP/3 Frame Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Http3FrameType {
    Data,
    Headers,
    CancelPush,
    Settings,
    PushPromise,
    GoAway,
    MaxPushId,
    Unknown(u64),
}

impl From<u64> for Http3FrameType {
    fn from(val: u64) -> Self {
        match val {
            0x00 => Http3FrameType::Data,
            0x01 => Http3FrameType::Headers,
            0x02 => Http3FrameType::CancelPush,
            0x03 => Http3FrameType::Settings,
            0x04 => Http3FrameType::PushPromise,
            0x07 => Http3FrameType::GoAway,
            0x0D => Http3FrameType::MaxPushId,
            other => Http3FrameType::Unknown(other),
        }
    }
}

/// Decoded RFC 9114 HTTP/3 Frame
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http3Frame {
    pub frame_type: Http3FrameType,
    pub length: u64,
    pub payload: Vec<u8>,
}

/// Decodes RFC 9000 Variable-Length Integer (QUIC varint).
/// Returns `Some((value, bytes_consumed))`.
pub fn decode_quic_varint(data: &[u8]) -> Option<(u64, usize)> {
    if data.is_empty() {
        return None;
    }

    let first = data[0];
    let prefix = (first >> 6) & 0x03;

    match prefix {
        0 => {
            // 1 byte: 6-bit value
            Some(((first & 0x3F) as u64, 1))
        }
        1 => {
            // 2 bytes: 14-bit value
            if data.len() < 2 {
                return None;
            }
            let val = (((first & 0x3F) as u64) << 8) | (data[1] as u64);
            Some((val, 2))
        }
        2 => {
            // 4 bytes: 30-bit value
            if data.len() < 4 {
                return None;
            }
            let val = (((first & 0x3F) as u64) << 24)
                | ((data[1] as u64) << 16)
                | ((data[2] as u64) << 8)
                | (data[3] as u64);
            Some((val, 4))
        }
        3 => {
            // 8 bytes: 62-bit value
            if data.len() < 8 {
                return None;
            }
            let mut val = (first & 0x3F) as u64;
            for &byte in &data[1..8] {
                val = (val << 8) | (byte as u64);
            }
            Some((val, 8))
        }
        _ => unreachable!(),
    }
}

/// Encodes an integer as an RFC 9000 Variable-Length Integer.
pub fn encode_quic_varint(val: u64) -> Vec<u8> {
    if val <= 63 {
        vec![val as u8]
    } else if val <= 16383 {
        let b0 = 0x40 | ((val >> 8) as u8);
        let b1 = (val & 0xFF) as u8;
        vec![b0, b1]
    } else if val <= 1073741823 {
        let b0 = 0x80 | ((val >> 24) as u8);
        let b1 = ((val >> 16) & 0xFF) as u8;
        let b2 = ((val >> 8) & 0xFF) as u8;
        let b3 = (val & 0xFF) as u8;
        vec![b0, b1, b2, b3]
    } else {
        let b0 = 0xC0 | ((val >> 56) as u8);
        let mut out = vec![b0];
        for shift in (0..7).rev() {
            out.push(((val >> (shift * 8)) & 0xFF) as u8);
        }
        out
    }
}

pub struct Http3Parser;

impl Http3Parser {
    /// Parses all complete HTTP/3 frames from raw byte buffer.
    pub fn parse_frames(mut data: &[u8]) -> Vec<Http3Frame> {
        let mut frames = Vec::new();

        while !data.is_empty() {
            let (frame_type_val, type_consumed) = match decode_quic_varint(data) {
                Some(res) => res,
                None => break,
            };
            let rem = &data[type_consumed..];

            let (length, len_consumed) = match decode_quic_varint(rem) {
                Some(res) => res,
                None => break,
            };
            let payload_start = type_consumed + len_consumed;
            let length_usize = match usize::try_from(length) {
                Ok(l) => l,
                Err(_) => break,
            };
            let total_frame_len = match payload_start.checked_add(length_usize) {
                Some(len) => len,
                None => break,
            };

            if data.len() < total_frame_len {
                break; // Incomplete frame
            }

            let payload = data[payload_start..total_frame_len].to_vec();
            frames.push(Http3Frame {
                frame_type: Http3FrameType::from(frame_type_val),
                length,
                payload,
            });

            data = &data[total_frame_len..];
        }

        frames
    }

    /// Dissects a HEADERS frame payload using QPACK static/dynamic decoding.
    pub fn decode_headers(payload: &[u8]) -> Vec<(String, String)> {
        let map = QpackDecoder::decode(payload);
        let mut list: Vec<_> = map.into_iter().collect();
        list.sort_by(|a, b| a.0.cmp(&b.0));
        list
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quic_varint_roundtrip() {
        let test_cases = [
            0u64,
            25,
            63,
            64,
            1500,
            16383,
            16384,
            100000,
            1073741823,
            1073741824,
            4611686018427387900,
        ];

        for &val in &test_cases {
            let encoded = encode_quic_varint(val);
            let (decoded, consumed) =
                decode_quic_varint(&encoded).expect("Must decode QUIC varint");
            assert_eq!(decoded, val, "Failed roundtrip for value: {}", val);
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn test_http3_parse_data_and_headers_frames() {
        // Frame 1: HEADERS (type 0x01)
        // QPACK: 0xD1 (:method: GET, idx 17), 0xC1 (:path: /, idx 1)
        let mut stream = Vec::new();
        stream.extend_from_slice(&encode_quic_varint(1)); // Type = HEADERS
        let headers_payload = vec![0xd1, 0xc1];
        stream.extend_from_slice(&encode_quic_varint(headers_payload.len() as u64));
        stream.extend_from_slice(&headers_payload);

        // Frame 2: DATA (type 0x00, len 5, payload "hello")
        stream.extend_from_slice(&encode_quic_varint(0)); // Type = DATA
        stream.extend_from_slice(&encode_quic_varint(5));
        stream.extend_from_slice(b"hello");

        let frames = Http3Parser::parse_frames(&stream);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].frame_type, Http3FrameType::Headers);
        assert_eq!(frames[0].length, 2);

        let headers = Http3Parser::decode_headers(&frames[0].payload);
        assert!(headers.iter().any(|(k, v)| k == ":method" && v == "GET"));
        assert!(headers.iter().any(|(k, v)| k == ":path" && v == "/"));

        assert_eq!(frames[1].frame_type, Http3FrameType::Data);
        assert_eq!(frames[1].payload, b"hello");
    }
}
