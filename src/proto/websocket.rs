//! RFC 6455 WebSocket Frame & Stream Dissector.
//!
//! Provides zero-copy parsing, frame unmasking, control frame handling,
//! multi-frame message defragmentation, and JSON payload inspection for WSS/WS traffic.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WebSocketOpcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
    Reserved(u8),
}

impl From<u8> for WebSocketOpcode {
    fn from(val: u8) -> Self {
        match val {
            0x0 => WebSocketOpcode::Continuation,
            0x1 => WebSocketOpcode::Text,
            0x2 => WebSocketOpcode::Binary,
            0x8 => WebSocketOpcode::Close,
            0x9 => WebSocketOpcode::Ping,
            0xA => WebSocketOpcode::Pong,
            other => WebSocketOpcode::Reserved(other),
        }
    }
}

impl std::fmt::Display for WebSocketOpcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebSocketOpcode::Continuation => write!(f, "CONTINUATION"),
            WebSocketOpcode::Text => write!(f, "TEXT"),
            WebSocketOpcode::Binary => write!(f, "BINARY"),
            WebSocketOpcode::Close => write!(f, "CLOSE"),
            WebSocketOpcode::Ping => write!(f, "PING"),
            WebSocketOpcode::Pong => write!(f, "PONG"),
            WebSocketOpcode::Reserved(v) => write!(f, "RESERVED(0x{:X})", v),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketCloseDetails {
    pub code: u16,
    pub description: &'static str,
    pub reason: String,
}

impl WebSocketCloseDetails {
    pub fn description_for_code(code: u16) -> &'static str {
        match code {
            1000 => "Normal Closure",
            1001 => "Going Away",
            1002 => "Protocol Error",
            1003 => "Unsupported Data",
            1005 => "No Status Received",
            1006 => "Abnormal Closure",
            1007 => "Invalid Frame Payload Data",
            1008 => "Policy Violation",
            1009 => "Message Too Big",
            1010 => "Mandatory Extension Missing",
            1011 => "Internal Server Error",
            1015 => "TLS Handshake Failure",
            _ => "User Defined / Reserved",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketFrame {
    pub fin: bool,
    pub rsv1: bool,
    pub rsv2: bool,
    pub rsv3: bool,
    pub opcode: WebSocketOpcode,
    pub masked: bool,
    pub payload_len: usize,
    pub masking_key: Option<[u8; 4]>,
    #[serde(skip_serializing)]
    pub payload: Vec<u8>,
    pub text_preview: Option<String>,
    pub is_json: bool,
}

pub struct WebSocketParser;

impl WebSocketParser {
    /// Attempts to parse a single RFC 6455 frame from raw bytes.
    /// Returns `Some((frame, bytes_consumed))` on success.
    pub fn parse_frame(data: &[u8]) -> Option<(WebSocketFrame, usize)> {
        if data.len() < 2 {
            return None;
        }

        let b0 = data[0];
        let fin = (b0 & 0x80) != 0;
        let rsv1 = (b0 & 0x40) != 0;
        let rsv2 = (b0 & 0x20) != 0;
        let rsv3 = (b0 & 0x10) != 0;
        let opcode = WebSocketOpcode::from(b0 & 0x0F);

        let b1 = data[1];
        let masked = (b1 & 0x80) != 0;
        let initial_len = (b1 & 0x7F) as usize;

        let mut offset = 2;
        let payload_len: usize = match initial_len {
            0..=125 => initial_len,
            126 => {
                if data.len() < offset + 2 {
                    return None;
                }
                let len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                offset += 2;
                len
            }
            127 => {
                if data.len() < offset + 8 {
                    return None;
                }
                let len = u64::from_be_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ]) as usize;
                offset += 8;
                len
            }
            _ => unreachable!(),
        };

        let masking_key = if masked {
            if data.len() < offset + 4 {
                return None;
            }
            let key = [
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ];
            offset += 4;
            Some(key)
        } else {
            None
        };

        if data.len() < offset + payload_len {
            return None;
        }

        let raw_payload = &data[offset..offset + payload_len];
        let mut unmasked = raw_payload.to_vec();

        if let Some(key) = masking_key {
            for (i, byte) in unmasked.iter_mut().enumerate() {
                *byte ^= key[i % 4];
            }
        }

        let total_consumed = offset + payload_len;

        let (text_preview, is_json) = if opcode == WebSocketOpcode::Text
            || (opcode == WebSocketOpcode::Continuation && !unmasked.is_empty())
        {
            if let Ok(text) = std::str::from_utf8(&unmasked) {
                let trimmed = text.trim();
                let is_json = (trimmed.starts_with('{') && trimmed.ends_with('}'))
                    || (trimmed.starts_with('[') && trimmed.ends_with(']'));
                (Some(text.to_string()), is_json)
            } else {
                (None, false)
            }
        } else if opcode == WebSocketOpcode::Close && unmasked.len() >= 2 {
            let code = u16::from_be_bytes([unmasked[0], unmasked[1]]);
            let desc = WebSocketCloseDetails::description_for_code(code);
            let reason = if unmasked.len() > 2 {
                String::from_utf8_lossy(&unmasked[2..]).to_string()
            } else {
                String::new()
            };
            (
                Some(format!("Code {} ({}) - Reason: {}", code, desc, reason)),
                false,
            )
        } else {
            (None, false)
        };

        Some((
            WebSocketFrame {
                fin,
                rsv1,
                rsv2,
                rsv3,
                opcode,
                masked,
                payload_len,
                masking_key,
                payload: unmasked,
                text_preview,
                is_json,
            },
            total_consumed,
        ))
    }

    /// Parses all complete WebSocket frames present in a byte stream.
    pub fn parse_all_frames(mut data: &[u8]) -> Vec<WebSocketFrame> {
        let mut frames = Vec::new();
        while !data.is_empty() {
            if let Some((frame, consumed)) = Self::parse_frame(data) {
                if consumed == 0 {
                    break;
                }
                frames.push(frame);
                data = &data[consumed..];
            } else {
                break;
            }
        }
        frames
    }

    /// Heuristic detector to determine if bytes match an RFC 6455 WebSocket frame.
    pub fn is_probable_websocket(data: &[u8]) -> bool {
        if data.len() < 2 {
            return false;
        }

        // Must not be HTTP/1.x ASCII verbs
        let http_verbs: [&[u8]; 9] = [
            b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ",
            b"HTTP/1.",
        ];
        if http_verbs.iter().any(|verb| data.starts_with(verb)) {
            return false;
        }

        // Must not be HTTP/2 client preface
        if data.starts_with(b"PRI * HTTP/2.0") {
            return false;
        }

        let b0 = data[0];
        let opcode = b0 & 0x0F;
        // Valid RFC opcodes are 0x0..=0x2 (data) or 0x8..=0xA (control)
        let valid_opcode = opcode <= 0x2 || (0x8..=0xA).contains(&opcode);
        if !valid_opcode {
            return false;
        }

        // Control frames must not be fragmented (FIN must be 1) and payload <= 125
        let fin = (b0 & 0x80) != 0;
        let b1 = data[1];
        let len_field = b1 & 0x7F;

        if opcode >= 0x8 && (!fin || len_field > 125) {
            return false;
        }

        // Try parsing the frame
        if let Some((frame, consumed)) = Self::parse_frame(data) {
            // Either the whole slice is consumed, or the remainder starts another valid frame
            if consumed == data.len() || (data.len() > consumed && Self::parse_frame(&data[consumed..]).is_some()) {
                return true;
            }
            // Even if slightly fragmented at the boundary, a valid frame parsed at start is strong indication
            if frame.payload_len == frame.payload.len() && consumed <= data.len() {
                return true;
            }
        }

        false
    }
}

/// Multi-frame message assembler for defragmenting split WebSocket messages.
#[derive(Default)]
pub struct WebSocketAssembler {
    current_opcode: Option<WebSocketOpcode>,
    buffer: Vec<u8>,
}

impl WebSocketAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Process a frame. Returns `Some((opcode, complete_payload))` if message is complete.
    pub fn process_frame(&mut self, frame: WebSocketFrame) -> Option<(WebSocketOpcode, Vec<u8>)> {
        match frame.opcode {
            WebSocketOpcode::Text | WebSocketOpcode::Binary => {
                if frame.fin {
                    self.current_opcode = None;
                    self.buffer.clear();
                    Some((frame.opcode, frame.payload))
                } else {
                    self.current_opcode = Some(frame.opcode);
                    self.buffer = frame.payload;
                    None
                }
            }
            WebSocketOpcode::Continuation => {
                self.buffer.extend_from_slice(&frame.payload);
                if frame.fin {
                    let opcode = self.current_opcode.take().unwrap_or(WebSocketOpcode::Text);
                    let payload = std::mem::take(&mut self.buffer);
                    Some((opcode, payload))
                } else {
                    None
                }
            }
            control => {
                // Control frames can be interleaved and are not buffered
                Some((control, frame.payload))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_masked_text_frame() {
        // Unmasked: "Hello"
        // Mask: [0x37, 0xfa, 0x21, 0x3d]
        // Encoded payload:
        // 'H' (0x48) ^ 0x37 = 0x7F
        // 'e' (0x65) ^ 0xfa = 0x9F
        // 'l' (0x6c) ^ 0x21 = 0x4D
        // 'l' (0x6c) ^ 0x3d = 0x51
        // 'o' (0x6f) ^ 0x37 = 0x58
        let raw_frame = vec![
            0x81, // FIN=1, Opcode=Text (0x1)
            0x85, // Masked=1, Len=5
            0x37, 0xfa, 0x21, 0x3d, // Masking Key
            0x7f, 0x9f, 0x4d, 0x51, 0x58, // Masked payload
        ];

        let (frame, consumed) = WebSocketParser::parse_frame(&raw_frame).expect("Should parse");
        assert_eq!(consumed, raw_frame.len());
        assert!(frame.fin);
        assert_eq!(frame.opcode, WebSocketOpcode::Text);
        assert!(frame.masked);
        assert_eq!(frame.payload, b"Hello");
        assert_eq!(frame.text_preview.as_deref(), Some("Hello"));
        assert!(!frame.is_json);
    }

    #[test]
    fn test_parse_json_websocket_frame() {
        let json_str = r#"{"action":"subscribe","channel":"ticker"}"#;
        let mut raw = vec![0x81, json_str.len() as u8];
        raw.extend_from_slice(json_str.as_bytes());

        let (frame, consumed) = WebSocketParser::parse_frame(&raw).unwrap();
        assert_eq!(consumed, raw.len());
        assert!(frame.fin);
        assert_eq!(frame.opcode, WebSocketOpcode::Text);
        assert!(frame.is_json);
        assert_eq!(frame.text_preview.as_deref(), Some(json_str));
    }

    #[test]
    fn test_parse_close_frame() {
        // Close frame with code 1000 (0x03E8) and reason "Normal"
        let raw = vec![0x88, 0x08, 0x03, 0xE8, b'N', b'o', b'r', b'm', b'a', b'l'];
        let (frame, consumed) = WebSocketParser::parse_frame(&raw).unwrap();
        assert_eq!(consumed, 10);
        assert_eq!(frame.opcode, WebSocketOpcode::Close);
        assert!(frame.text_preview.unwrap().contains("Normal Closure"));
    }

    #[test]
    fn test_fragmented_websocket_message() {
        let mut assembler = WebSocketAssembler::new();

        // Frame 1: Text, FIN=0, payload: "Hello "
        let f1 = WebSocketFrame {
            fin: false,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: WebSocketOpcode::Text,
            masked: false,
            payload_len: 6,
            masking_key: None,
            payload: b"Hello ".to_vec(),
            text_preview: Some("Hello ".to_string()),
            is_json: false,
        };
        assert!(assembler.process_frame(f1).is_none());

        // Frame 2: Continuation, FIN=1, payload: "World!"
        let f2 = WebSocketFrame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: WebSocketOpcode::Continuation,
            masked: false,
            payload_len: 6,
            masking_key: None,
            payload: b"World!".to_vec(),
            text_preview: Some("World!".to_string()),
            is_json: false,
        };
        let (opcode, complete) = assembler.process_frame(f2).expect("Should complete message");
        assert_eq!(opcode, WebSocketOpcode::Text);
        assert_eq!(complete, b"Hello World!");
    }
}
