use crate::engine::event::Direction;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ConnectionKey {
    pub pid: u32,
    pub fd: i32,
    pub direction: Direction,
}

#[derive(Debug, Clone)]
pub struct BufferEntry {
    pub data: Vec<u8>,
    pub last_seen: Instant,
}

pub struct StreamReassembler {
    buffers: HashMap<ConnectionKey, BufferEntry>,
    max_buffer_size: usize,
    max_connections: usize,
    default_ttl: Duration,
}

impl Default for StreamReassembler {
    fn default() -> Self {
        Self::new(65536)
    }
}

impl StreamReassembler {
    pub const DEFAULT_MAX_CONNECTIONS: usize = 10_000;
    pub const DEFAULT_TTL: Duration = Duration::from_secs(60);

    pub fn new(max_buffer_size: usize) -> Self {
        Self::with_limits(
            max_buffer_size,
            Self::DEFAULT_MAX_CONNECTIONS,
            Self::DEFAULT_TTL,
        )
    }

    pub fn with_limits(
        max_buffer_size: usize,
        max_connections: usize,
        default_ttl: Duration,
    ) -> Self {
        Self {
            buffers: HashMap::new(),
            max_buffer_size,
            max_connections,
            default_ttl,
        }
    }

    pub fn active_connection_count(&self) -> usize {
        self.buffers.len()
    }

    /// Prunes connections that have not received data within `ttl`.
    pub fn prune_stale(&mut self, ttl: Duration) -> usize {
        let now = Instant::now();
        let initial_len = self.buffers.len();
        self.buffers.retain(|_, entry| {
            now.checked_duration_since(entry.last_seen)
                .unwrap_or_default()
                < ttl
        });
        initial_len - self.buffers.len()
    }

    pub fn push_chunk(&mut self, key: ConnectionKey, chunk: &[u8]) -> Option<Vec<u8>> {
        // Enforce max connections limit by evicting stale or oldest entry if capacity reached
        if !self.buffers.contains_key(&key)
            && self.buffers.len() >= self.max_connections
            && self.prune_stale(self.default_ttl) == 0
        {
            if let Some((oldest_key, _)) = self
                .buffers
                .iter()
                .min_by_key(|(_, entry)| entry.last_seen)
                .map(|(k, e)| (k.clone(), e.last_seen))
            {
                self.buffers.remove(&oldest_key);
            }
        }

        let now = Instant::now();
        let entry = self
            .buffers
            .entry(key.clone())
            .or_insert_with(|| BufferEntry {
                data: Vec::new(),
                last_seen: now,
            });
        entry.last_seen = now;
        entry.data.extend_from_slice(chunk);

        // Check for complete HTTP/1.1 message boundary
        if let Some(msg_len) = Self::detect_http1_complete(&entry.data) {
            let complete_msg = entry.data[..msg_len].to_vec();
            entry.data.drain(..msg_len);
            if entry.data.is_empty() {
                self.buffers.remove(&key);
            }
            return Some(complete_msg);
        }

        // Buffer limit protection against memory exhaustion
        if entry.data.len() > self.max_buffer_size {
            let drained = std::mem::take(&mut entry.data);
            self.buffers.remove(&key);
            return Some(drained);
        }

        None
    }

    fn detect_http1_complete(data: &[u8]) -> Option<usize> {
        let text = String::from_utf8_lossy(data);
        let header_end = text.find("\r\n\r\n")?;
        let headers_len = header_end + 4;

        let first_line = text.lines().next().unwrap_or("");
        let is_response = first_line.starts_with("HTTP/");

        // RFC 7230 §3.3.3: 1xx, 204, and 304 responses MUST NOT include a message-body
        if is_response {
            let parts: Vec<&str> = first_line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(code) = parts[1].parse::<u16>() {
                    if (100..200).contains(&code) || code == 204 || code == 304 {
                        return Some(headers_len);
                    }
                }
            }
        }

        // Extract Content-Length, Transfer-Encoding, and Connection headers
        let mut content_length = None;
        let mut is_chunked = false;
        let mut is_close = false;

        for line in text[..header_end].lines() {
            if let Some((k, v)) = line.split_once(':') {
                let key = k.trim().to_lowercase();
                if key == "content-length" {
                    content_length = v.trim().parse::<usize>().ok();
                } else if key == "transfer-encoding" && v.to_lowercase().contains("chunked") {
                    is_chunked = true;
                } else if key == "connection" && v.to_lowercase().contains("close") {
                    is_close = true;
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

        // RFC 7230 §3.3.3 Item 7: If a response is received without Content-Length
        // and Connection: close is specified, the body is delimited by EOF (connection close).
        // Delay completion until flush_connection() is invoked upon EOF.
        if is_response && is_close {
            return None;
        }

        // If no body expected (e.g. standard GET/HEAD request without body)
        Some(headers_len)
    }

    /// Flushes and returns any remaining buffered data for a closed connection (RFC 7230 §3.3.3 EOF termination).
    pub fn flush_connection(&mut self, key: &ConnectionKey) -> Option<Vec<u8>> {
        if let Some(entry) = self.buffers.remove(key) {
            if !entry.data.is_empty() {
                return Some(entry.data);
            }
        }
        None
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
        assert_eq!(reassembler.active_connection_count(), 1);

        let complete = reassembler
            .push_chunk(key, chunk2)
            .expect("Should reassemble full message");

        assert_eq!(
            String::from_utf8_lossy(&complete),
            "POST /submit HTTP/1.1\r\nHost: test.com\r\nContent-Length: 5\r\n\r\nhello"
        );
        // After draining completely, connection entry is pruned automatically
        assert_eq!(reassembler.active_connection_count(), 0);
    }

    #[test]
    fn test_reassembler_prune_stale_and_lru() {
        let mut reassembler = StreamReassembler::with_limits(1024, 2, Duration::from_millis(50));
        let k1 = ConnectionKey {
            pid: 1,
            fd: 1,
            direction: Direction::Ingress,
        };
        let k2 = ConnectionKey {
            pid: 2,
            fd: 2,
            direction: Direction::Ingress,
        };
        let k3 = ConnectionKey {
            pid: 3,
            fd: 3,
            direction: Direction::Ingress,
        };

        // Push partial chunk to k1 and k2
        reassembler.push_chunk(k1, b"PARTIAL1");
        reassembler.push_chunk(k2.clone(), b"PARTIAL2");
        assert_eq!(reassembler.active_connection_count(), 2);

        // Sleep to let k1 & k2 become stale
        std::thread::sleep(Duration::from_millis(60));

        // Pushing k3 when capacity is full will trigger prune_stale
        reassembler.push_chunk(k3, b"PARTIAL3");
        // Stale entries were pruned
        assert!(reassembler.active_connection_count() <= 2);
    }

    #[test]
    fn test_reassembler_max_connections_eviction() {
        let mut reassembler = StreamReassembler::with_limits(1024, 2, Duration::from_secs(3600));
        let k1 = ConnectionKey {
            pid: 10,
            fd: 1,
            direction: Direction::Ingress,
        };
        let k2 = ConnectionKey {
            pid: 20,
            fd: 2,
            direction: Direction::Ingress,
        };
        let k3 = ConnectionKey {
            pid: 30,
            fd: 3,
            direction: Direction::Ingress,
        };

        reassembler.push_chunk(k1, b"REQ1");
        std::thread::sleep(Duration::from_millis(5));
        reassembler.push_chunk(k2, b"REQ2");
        assert_eq!(reassembler.active_connection_count(), 2);

        // Max connections is 2, pushing k3 must evict oldest (k1)
        reassembler.push_chunk(k3, b"REQ3");
        assert_eq!(reassembler.active_connection_count(), 2);
    }

    #[test]
    fn test_reassemble_rfc7230_eof_delimited_response() {
        let mut reassembler = StreamReassembler::new(65536);
        let key = ConnectionKey {
            pid: 9999,
            fd: 42,
            direction: Direction::Ingress,
        };

        // HTTP response with Connection: close and NO Content-Length
        let header_chunk =
            b"HTTP/1.1 200 OK\r\nServer: Custom\r\nConnection: close\r\n\r\nBodyPart1";
        let res1 = reassembler.push_chunk(key.clone(), header_chunk);
        assert!(
            res1.is_none(),
            "Should wait for EOF instead of prematurely truncating at headers"
        );

        let body_chunk2 = b"-BodyPart2-EOF";
        let res2 = reassembler.push_chunk(key.clone(), body_chunk2);
        assert!(res2.is_none(), "Still waiting for EOF");

        // Connection closes (EOF)
        let flushed = reassembler
            .flush_connection(&key)
            .expect("Must return accumulated EOF response");
        let flushed_str = String::from_utf8_lossy(&flushed);
        assert!(flushed_str.contains("HTTP/1.1 200 OK"));
        assert!(flushed_str.contains("BodyPart1-BodyPart2-EOF"));
        assert_eq!(reassembler.active_connection_count(), 0);
    }

    #[test]
    fn test_reassemble_rfc7230_204_no_content() {
        let mut reassembler = StreamReassembler::new(65536);
        let key = ConnectionKey {
            pid: 8888,
            fd: 10,
            direction: Direction::Ingress,
        };

        let chunk = b"HTTP/1.1 204 No Content\r\nServer: test\r\n\r\n";
        let res = reassembler.push_chunk(key, chunk);
        assert!(
            res.is_some(),
            "204 No Content must immediately complete without expecting body"
        );
    }
}
