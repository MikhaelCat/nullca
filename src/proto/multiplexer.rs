//! HTTP/2 Session Multiplexer and Concurrent Stream Reassembler.
//!
//! Reassembles interleaved frames across multiple concurrent `stream_id`s,
//! buffers `CONTINUATION` frames until `END_HEADERS`, and reassembles stream
//! data chunks until `END_STREAM`.

use crate::proto::grpc::GrpcMessage;
use crate::proto::http2::{HpackDecoder, Http2Frame, Http2FrameType};
use std::collections::HashMap;

/// Lifecycle state of an individual HTTP/2 logical stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamState {
    Idle,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

/// In-progress HTTP/2 Stream Assembly Buffer.
#[derive(Debug, Clone, Default)]
pub struct Http2StreamBuffer {
    pub stream_id: u32,
    pub state: Option<StreamState>,
    pub header_block_buffer: Vec<u8>,
    pub headers_complete: bool,
    pub headers: Vec<(String, String)>,
    pub data_buffer: Vec<u8>,
    pub end_stream_received: bool,
}

/// A fully reassembled HTTP/2 request or response transaction on a stream.
#[derive(Debug, Clone)]
pub struct Http2Transaction {
    pub stream_id: u32,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub is_grpc: bool,
    pub grpc_messages: Vec<GrpcMessage>,
}

/// Manages full HTTP/2 connection state, dynamic HPACK tables, and active streams.
pub struct Http2Session {
    pub streams: HashMap<u32, Http2StreamBuffer>,
    pub hpack_decoder: HpackDecoder,
    pub max_header_list_size: usize,
    pub completed_transactions: Vec<Http2Transaction>,
}

impl Default for Http2Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Http2Session {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
            hpack_decoder: HpackDecoder::default(),
            max_header_list_size: 65536,
            completed_transactions: Vec::new(),
        }
    }

    /// Feeds an incoming HTTP/2 frame into the session state machine.
    /// Returns any newly completed stream transactions.
    pub fn process_frame(&mut self, frame: Http2Frame) -> Vec<Http2Transaction> {
        let mut completed = Vec::new();

        if frame.stream_id == 0 {
            // Connection-level frame
            match frame.frame_type {
                Http2FrameType::Settings => {
                    // Update connection settings if needed
                }
                Http2FrameType::GoAway => {
                    // Connection closing
                }
                _ => {}
            }
            return completed;
        }

        let stream_id = frame.stream_id;
        let stream = self.streams.entry(stream_id).or_insert_with(|| Http2StreamBuffer {
            stream_id,
            state: Some(StreamState::Open),
            ..Default::default()
        });

        match frame.frame_type {
            Http2FrameType::Headers => {
                let end_headers = (frame.flags & 0x04) != 0;
                let end_stream = (frame.flags & 0x01) != 0;

                // Handle priority flag padding if present
                let mut payload_offset = 0;
                if (frame.flags & 0x08) != 0 && !frame.payload.is_empty() {
                    // Pad length present
                    let pad_len = frame.payload[0] as usize;
                    payload_offset += 1;
                    if frame.payload.len() >= payload_offset + pad_len {
                        // Strip padding at end
                    }
                }
                if (frame.flags & 0x20) != 0 && frame.payload.len() >= payload_offset + 5 {
                    // Stream Dependency (4 bytes) + Weight (1 byte)
                    payload_offset += 5;
                }

                if payload_offset < frame.payload.len() {
                    stream.header_block_buffer.extend_from_slice(&frame.payload[payload_offset..]);
                }

                if end_headers {
                    stream.headers_complete = true;
                    if let Ok(hdrs) = self.hpack_decoder.decode(&stream.header_block_buffer) {
                        stream.headers = hdrs.into_iter().map(|h| (h.name, h.value)).collect();
                    }
                }

                if end_stream {
                    stream.end_stream_received = true;
                }
            }
            Http2FrameType::Continuation => {
                let end_headers = (frame.flags & 0x04) != 0;
                stream.header_block_buffer.extend_from_slice(&frame.payload);

                if end_headers {
                    stream.headers_complete = true;
                    if let Ok(hdrs) = self.hpack_decoder.decode(&stream.header_block_buffer) {
                        stream.headers = hdrs.into_iter().map(|h| (h.name, h.value)).collect();
                    }
                }
            }
            Http2FrameType::Data => {
                let end_stream = (frame.flags & 0x01) != 0;
                let mut data_slice = &frame.payload[..];

                // Handle padding if flag 0x08 set
                if (frame.flags & 0x08) != 0 && !data_slice.is_empty() {
                    let pad_len = data_slice[0] as usize;
                    if data_slice.len() > pad_len + 1 {
                        data_slice = &data_slice[1..data_slice.len() - pad_len];
                    }
                }

                stream.data_buffer.extend_from_slice(data_slice);

                if end_stream {
                    stream.end_stream_received = true;
                }
            }
            Http2FrameType::RstStream => {
                stream.state = Some(StreamState::Closed);
            }
            _ => {}
        }

        // If stream has reached end of stream and headers are complete, emit transaction
        if let Some(stream_buf) = self.streams.get(&stream_id) {
            if stream_buf.headers_complete && stream_buf.end_stream_received {
                let is_grpc = stream_buf.headers.iter().any(|(k, v)| {
                    k.eq_ignore_ascii_case("content-type") && v.starts_with("application/grpc")
                });

                let mut grpc_messages = Vec::new();
                if is_grpc && !stream_buf.data_buffer.is_empty() {
                    let mut cur = &stream_buf.data_buffer[..];
                    while let Ok((msg, remaining)) = GrpcMessage::parse(cur) {
                        grpc_messages.push(msg);
                        if remaining.is_empty() || remaining.len() == cur.len() {
                            break;
                        }
                        cur = remaining;
                    }
                }

                let tx = Http2Transaction {
                    stream_id,
                    headers: stream_buf.headers.clone(),
                    body: stream_buf.data_buffer.clone(),
                    is_grpc,
                    grpc_messages,
                };

                completed.push(tx);
                self.streams.remove(&stream_id);
            }
        }

        completed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http2_session_reassembly() {
        let mut session = Http2Session::new();

        // Feed HEADERS frame for stream 1 with END_HEADERS
        let headers_frame = Http2Frame {
            length: 1,
            frame_type: Http2FrameType::Headers,
            flags: 0x04, // END_HEADERS
            stream_id: 1,
            payload: vec![0x82], // :method: GET (Index 2 in static table)
        };

        let txs = session.process_frame(headers_frame);
        assert!(txs.is_empty()); // Still waiting for DATA or END_STREAM

        // Feed DATA frame for stream 1 with END_STREAM
        let data_frame = Http2Frame {
            length: 5,
            frame_type: Http2FrameType::Data,
            flags: 0x01, // END_STREAM
            stream_id: 1,
            payload: b"hello".to_vec(),
        };

        let txs = session.process_frame(data_frame);
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].stream_id, 1);
        assert_eq!(txs[0].headers[0], (":method".into(), "GET".into()));
        assert_eq!(&txs[0].body, b"hello");
    }
}
