use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Direction {
    Ingress, // Inbound read (e.g. SSL_read return)
    Egress,  // Outbound write (e.g. SSL_write entry)
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Direction::Ingress => write!(f, "RECV"),
            Direction::Egress => write!(f, "SEND"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolType {
    Http1,
    Http2,
    Grpc,
    RawTls,
}

impl std::fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolType::Http1 => write!(f, "HTTP/1.1"),
            ProtocolType::Http2 => write!(f, "HTTP/2"),
            ProtocolType::Grpc => write!(f, "gRPC"),
            ProtocolType::RawTls => write!(f, "TLS-Plaintext"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub fd: i32,
    pub direction: Direction,
    #[serde(skip_serializing)]
    pub data: Vec<u8>,
    pub data_len: usize,
    pub latency_us: Option<u64>,
}

impl TlsEvent {
    pub fn new(
        timestamp_ns: u64,
        pid: u32,
        tid: u32,
        fd: i32,
        direction: Direction,
        data: Vec<u8>,
        latency_us: Option<u64>,
    ) -> Self {
        let data_len = data.len();
        Self {
            timestamp_ns,
            pid,
            tid,
            fd,
            direction,
            data,
            data_len,
            latency_us,
        }
    }

    pub fn detect_protocol(&self) -> ProtocolType {
        let slice = &self.data;
        if slice.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
            return ProtocolType::Http2;
        }

        // Check HTTP/1.1 methods or status line
        let http1_verbs: [&[u8]; 9] = [
            b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ",
            b"HTTP/1.",
        ];
        if http1_verbs.iter().any(|verb| slice.starts_with(*verb)) {
            return ProtocolType::Http1;
        }

        // Check HTTP/2 frame pattern (Length 3 bytes, Type 1 byte, Flags 1 byte, StreamID 4 bytes)
        if slice.len() >= 9 {
            let frame_type = slice[3];
            let stream_id = u32::from_be_bytes([slice[5] & 0x7f, slice[6], slice[7], slice[8]]);
            // Valid HTTP/2 frame types are 0x0 to 0x9
            if frame_type <= 0x9 && stream_id < 0x7fffffff {
                // Heuristic confirmation: check if payload contains gRPC content-type
                if slice.windows(16).any(|w| w == b"application/grpc") {
                    return ProtocolType::Grpc;
                }
                return ProtocolType::Http2;
            }
        }

        ProtocolType::RawTls
    }
}
