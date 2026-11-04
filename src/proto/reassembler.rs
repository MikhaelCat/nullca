use crate::engine::event::Direction;
use std::collections::HashMap;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ConnectionKey {
    pub pid: u32,
    pub fd: i32,
    pub direction: Direction,
}

#[derive(Default)]
pub struct StreamReassembler {
    buffers: HashMap<ConnectionKey, Vec<u8>>,
    max_buffer_size: usize,
}

impl StreamReassembler {
    pub fn new(max_buffer_size: usize) -> Self {
        Self {
            buffers: HashMap::new(),
            max_buffer_size,
        }
    }

    pub fn push_chunk(&mut self, key: ConnectionKey, chunk: &[u8]) -> Option<Vec<u8>> {
        let buf = self.buffers.entry(key).or_default();
        buf.extend_from_slice(chunk);

        // Check for complete HTTP/1.1 message boundary
        if let Some(msg_len) = Self::detect_http1_complete(buf) {
            let complete_msg = buf[..msg_len].to_vec();
            buf.drain(..msg_len);
            return Some(complete_msg);
        }

        // Buffer limit protection against memory exhaustion
        if buf.len() > self.max_buffer_size {
            let drained = std::mem::take(buf);
            return Some(drained);
        }

        None
    }

    fn detect_http1_complete(data: &[u8]) -> Option<usize> {
        let text = String::from_utf8_lossy(data);
        let header_end = text.find("\r\n\r\n")?;
        let headers_len = header_end + 4;

        // Extract Content-Length if present
        let mut content_length = None;
        let mut is_chunked = false;

        for line in text[..header_end].lines() {
            if let Some((k, v)) = line.split_once(':') {
                let key = k.trim().to_lowercase();
                if key == "content-length" {
                    content_length = v.trim().parse::<usize>().ok();
                } else if key == "transfer-encoding" && v.to_lowercase().contains("chunked") {
                    is_chunked = true;
                }
            }
        }

        if is_chunked {
            // Check for chunked termination: "0\r\n\r\n"
            if text[headers_len..].contains("0\r\n\r\n") {
                let term_pos = text[headers_len..].find("0\r\n\r\n").unwrap();
                return Some(headers_len + term_pos + 5);
            }
            return None;
        }

        if let Some(cl) = content_length {
            let total_len = headers_len + cl;
            if data.len() >= total_len {
                return Some(total_len);
            }
            return None;
        }

        // If no body expected (e.g. standard GET without body)
        Some(headers_len)
    }

    pub fn clear_connection(&mut self, key: &ConnectionKey) {
        self.buffers.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reassemble_fragmented_http1() {
        let mut reassembler = StreamReassembler::new(65536);
        let key = ConnectionKey {
            pid: 1234,
            fd: 5,
            direction: Direction::Egress,
        };

        let chunk1 = b"POST /submit HTTP/1.1\r\nHost: test.com\r\nContent-Length: 5\r\n\r\nhe";
        let chunk2 = b"llo";

        assert!(reassembler.push_chunk(key.clone(), chunk1).is_none());
        let complete = reassembler
            .push_chunk(key, chunk2)
            .expect("Should reassemble full message");

        assert_eq!(
            String::from_utf8_lossy(&complete),
            "POST /submit HTTP/1.1\r\nHost: test.com\r\nContent-Length: 5\r\n\r\nhello"
        );
    }
}
