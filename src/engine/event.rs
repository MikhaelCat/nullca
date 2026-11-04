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
    Http3,
    Grpc,
    WebSocket,
    Sse,
    Dns,
    X509,
    Redis,
    Database,
    Smtp,
    RawTls,
}

impl std::fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolType::Http1 => write!(f, "HTTP/1.1"),
            ProtocolType::Http2 => write!(f, "HTTP/2"),
            ProtocolType::Http3 => write!(f, "HTTP/3"),
            ProtocolType::Grpc => write!(f, "gRPC"),
            ProtocolType::WebSocket => write!(f, "WebSocket"),
            ProtocolType::Sse => write!(f, "SSE-Stream"),
            ProtocolType::Dns => write!(f, "DNS/DoH"),
            ProtocolType::X509 => write!(f, "X.509-Cert"),
            ProtocolType::Redis => write!(f, "Redis-TLS"),
            ProtocolType::Database => write!(f, "Database-TLS"),
            ProtocolType::Smtp => write!(f, "SMTP-TLS"),
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
    pub comm: String,
    #[serde(default, skip_serializing)]
    pub data: Vec<u8>,
    pub data_len: usize,
    pub latency_us: Option<u64>,
    #[serde(default)]
    pub src_addr: Option<String>,
    #[serde(default)]
    pub dst_addr: Option<String>,
    #[serde(default)]
    pub src_port: Option<u16>,
    #[serde(default)]
    pub dst_port: Option<u16>,
}

impl TlsEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        timestamp_ns: u64,
        pid: u32,
        tid: u32,
        fd: i32,
        direction: Direction,
        comm: String,
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
            comm,
            data,
            data_len,
            latency_us,
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
        }
    }

    pub fn with_socket_info(
        mut self,
        src_addr: Option<String>,
        dst_addr: Option<String>,
        src_port: Option<u16>,
        dst_port: Option<u16>,
    ) -> Self {
        self.src_addr = src_addr;
        self.dst_addr = dst_addr;
        self.src_port = src_port;
        self.dst_port = dst_port;
        self
    }

    /// Attempts to resolve source and destination endpoints from /proc for this event.
    pub fn resolve_endpoints(&mut self) {
        if self.src_addr.is_none() && self.pid > 0 && self.fd > 0 {
            if let Some((src, sp, dst, dp)) =
                crate::engine::discover::SocketResolver::resolve_endpoints(
                    self.pid,
                    self.fd,
                    self.direction,
                )
            {
                self.src_addr = Some(src);
                self.src_port = Some(sp);
                self.dst_addr = Some(dst);
                self.dst_port = Some(dp);
            }
        }
    }

    pub fn protocol(&self) -> ProtocolType {
        self.detect_protocol()
    }

    pub fn detect_protocol(&self) -> ProtocolType {
        let slice = &self.data;
        if slice.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
            return ProtocolType::Http2;
        }

        // Check HTTP/1.1 methods or status line
        let http1_verbs: [&[u8]; 9] = [
            b"GET ",
            b"POST ",
            b"PUT ",
            b"DELETE ",
            b"HEAD ",
            b"OPTIONS ",
            b"PATCH ",
            b"CONNECT ",
            b"HTTP/1.",
        ];
        if http1_verbs.iter().any(|verb| slice.starts_with(verb)) {
            return ProtocolType::Http1;
        }

        // Check X.509 Certificate (PEM or DER sequence)
        if slice.starts_with(b"-----BEGIN CERTIFICATE-----") {
            return ProtocolType::X509;
        }
        if slice.len() > 30
            && slice[0] == 0x30
            && slice[1] == 0x82
            && crate::proto::x509::X509Parser::parse(slice).is_some()
        {
            return ProtocolType::X509;
        }

        // Check Redis TLS protocol
        if crate::proto::database::NonHttpDissector::parse_redis(slice).is_some() {
            return ProtocolType::Redis;
        }

        // Check PostgreSQL / Database Query
        if crate::proto::database::NonHttpDissector::parse_postgres(slice).is_some() {
            return ProtocolType::Database;
        }

        // Check SMTP / Mail protocol
        if crate::proto::database::NonHttpDissector::parse_smtp(slice).is_some() {
            return ProtocolType::Smtp;
        }

        // Check RFC 6455 WebSocket framing
        if crate::proto::websocket::WebSocketParser::is_probable_websocket(slice) {
            return ProtocolType::WebSocket;
        }

        // Check Server-Sent Events (SSE / text/event-stream)
        if crate::proto::sse::SseParser::is_probable_sse(slice) {
            return ProtocolType::Sse;
        }

        // Check RFC 1035 / RFC 8484 DNS & DoH framing
        if crate::proto::dns::DnsParser::is_probable_dns(slice) {
            return ProtocolType::Dns;
        }

        // Check HTTP/3 / QUIC Framing
        let h3_frames = crate::proto::http3::Http3Parser::parse_frames(slice);
        if !h3_frames.is_empty()
            && (h3_frames[0].frame_type == crate::proto::http3::Http3FrameType::Headers
                || h3_frames[0].frame_type == crate::proto::http3::Http3FrameType::Data)
        {
            return ProtocolType::Http3;
        }

        // Check HTTP/2 frame pattern (Length 3 bytes, Type 1 byte, Flags 1 byte, StreamID 4 bytes)
        if slice.len() >= 9 {
            let frame_len =
                ((slice[0] as usize) << 16) | ((slice[1] as usize) << 8) | (slice[2] as usize);
            let frame_type = slice[3];
            let stream_id = u32::from_be_bytes([slice[5] & 0x7f, slice[6], slice[7], slice[8]]);
            // Valid HTTP/2 frame types are 0x0 to 0x9
            if frame_type <= 0x9 && stream_id < 0x7fffffff && frame_len + 9 <= slice.len() {
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
