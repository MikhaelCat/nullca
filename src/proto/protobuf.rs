//! Schema-less Protocol Buffers (Protobuf) Wire Format Dissector.
//!
//! Decodes gRPC and raw Protobuf payloads without needing `.proto` definition files.
//! Recursively extracts tags, wire types, varints, strings, nested sub-messages, and raw byte arrays.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ProtobufError {
    #[error("Unexpected end of buffer while reading varint")]
    TruncatedVarint,
    #[error("Varint exceeds 64-bit capacity (more than 10 bytes)")]
    VarintOverflow,
    #[error("Unexpected end of buffer while reading payload")]
    TruncatedPayload,
    #[error("Unsupported wire type: {0}")]
    UnsupportedWireType(u8),
}

/// Protobuf Wire Types as defined in encoding spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireType {
    Varint = 0,
    Fixed64 = 1,
    LengthDelimited = 2,
    StartGroup = 3, // Deprecated
    EndGroup = 4,   // Deprecated
    Fixed32 = 5,
}

impl TryFrom<u8> for WireType {
    type Error = ProtobufError;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0 => Ok(WireType::Varint),
            1 => Ok(WireType::Fixed64),
            2 => Ok(WireType::LengthDelimited),
            3 => Ok(WireType::StartGroup),
            4 => Ok(WireType::EndGroup),
            5 => Ok(WireType::Fixed32),
            other => Err(ProtobufError::UnsupportedWireType(other)),
        }
    }
}

/// Decoded Protobuf value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProtobufValue {
    Varint(u64),
    Fixed64(u64),
    Fixed32(u32),
    String(String),
    Message(ProtobufMessage),
    Bytes(Vec<u8>),
}

/// Decoded Protobuf message representing a collection of fields.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ProtobufMessage {
    pub fields: BTreeMap<u32, Vec<ProtobufValue>>,
}

impl ProtobufMessage {
    pub fn new() -> Self {
        Self {
            fields: BTreeMap::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Recursively decodes a raw Protobuf byte slice into a message tree.
    pub fn decode(mut data: &[u8]) -> Result<Self, ProtobufError> {
        let mut msg = ProtobufMessage::new();

        while !data.is_empty() {
            let (tag_wire, bytes_read) = decode_varint(data)?;
            data = &data[bytes_read..];

            let field_number = (tag_wire >> 3) as u32;
            let wire_type = WireType::try_from((tag_wire & 0x07) as u8)?;

            if field_number == 0 {
                // Invalid field number according to proto specification
                break;
            }

            let value = match wire_type {
                WireType::Varint => {
                    let (val, n) = decode_varint(data)?;
                    data = &data[n..];
                    ProtobufValue::Varint(val)
                }
                WireType::Fixed64 => {
                    if data.len() < 8 {
                        return Err(ProtobufError::TruncatedPayload);
                    }
                    let val = u64::from_le_bytes(data[..8].try_into().unwrap());
                    data = &data[8..];
                    ProtobufValue::Fixed64(val)
                }
                WireType::Fixed32 => {
                    if data.len() < 4 {
                        return Err(ProtobufError::TruncatedPayload);
                    }
                    let val = u32::from_le_bytes(data[..4].try_into().unwrap());
                    data = &data[4..];
                    ProtobufValue::Fixed32(val)
                }
                WireType::LengthDelimited => {
                    let (length, n) = decode_varint(data)?;
                    data = &data[n..];
                    let len = length as usize;
                    if data.len() < len {
                        return Err(ProtobufError::TruncatedPayload);
                    }
                    let slice = &data[..len];
                    data = &data[len..];

                    // Heuristics:
                    // 1. Try decoding as nested Protobuf message if len > 1
                    if len > 1 {
                        if let Ok(nested) = ProtobufMessage::decode(slice) {
                            if !nested.is_empty() {
                                msg.fields
                                    .entry(field_number)
                                    .or_default()
                                    .push(ProtobufValue::Message(nested));
                                continue;
                            }
                        }
                    }

                    // 2. Try decoding as UTF-8 string
                    if let Ok(s) = std::str::from_utf8(slice) {
                        if s.chars()
                            .all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t')
                        {
                            ProtobufValue::String(s.to_string())
                        } else {
                            ProtobufValue::Bytes(slice.to_vec())
                        }
                    } else {
                        // 3. Fallback to raw bytes
                        ProtobufValue::Bytes(slice.to_vec())
                    }
                }
                WireType::StartGroup | WireType::EndGroup => {
                    // Deprecated groups, ignore or break
                    break;
                }
            };

            msg.fields.entry(field_number).or_default().push(value);
        }

        Ok(msg)
    }

    /// Converts message to human-readable JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Decodes an unsigned LEB128 varint from the input slice.
pub fn decode_varint(data: &[u8]) -> Result<(u64, usize), ProtobufError> {
    let mut result: u64 = 0;
    let mut shift = 0;

    for (i, &byte) in data.iter().enumerate() {
        if i >= 10 {
            return Err(ProtobufError::VarintOverflow);
        }
        let val = (byte & 0x7F) as u64;
        result |= val << shift;
        if (byte & 0x80) == 0 {
            return Ok((result, i + 1));
        }
        shift += 7;
    }

    Err(ProtobufError::TruncatedVarint)
}

/// Encodes an unsigned 64-bit integer into LEB128 varint bytes.
pub fn encode_varint(mut val: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    while val >= 0x80 {
        buf.push(((val & 0x7F) as u8) | 0x80);
        val >>= 7;
    }
    buf.push((val & 0x7F) as u8);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_roundtrip() {
        let values = [0, 1, 127, 128, 300, 16384, u32::MAX as u64, u64::MAX];
        for &val in &values {
            let encoded = encode_varint(val);
            let (decoded, n) = decode_varint(&encoded).unwrap();
            assert_eq!(val, decoded);
            assert_eq!(n, encoded.len());
        }
    }

    #[test]
    fn test_protobuf_decode_simple() {
        // Construct protobuf message:
        // Field 1 (Varint): 150 -> tag = (1 << 3) | 0 = 0x08, value = 0x96, 0x01
        // Field 2 (String): "testing" -> tag = (2 << 3) | 2 = 0x12, len = 7, "testing"
        let mut wire = Vec::new();
        wire.push(0x08);
        wire.extend_from_slice(&encode_varint(150));
        wire.push(0x12);
        wire.extend_from_slice(&encode_varint(7));
        wire.extend_from_slice(b"testing");

        let msg = ProtobufMessage::decode(&wire).expect("Should decode successfully");
        assert_eq!(msg.fields.get(&1).unwrap()[0], ProtobufValue::Varint(150));
        assert_eq!(
            msg.fields.get(&2).unwrap()[0],
            ProtobufValue::String("testing".into())
        );
    }
}
