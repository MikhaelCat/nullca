use crate::engine::event::{Direction, ProtocolType, TlsEvent};
use crate::proto::grpc::GrpcParser;
use crate::proto::http1::{Http1Message, Http1Parser};
use crate::proto::http2::{HpackDecoder, Http2FrameType, Http2Parser};
use colored::*;

pub struct TerminalFormatter {
    show_hexdump: bool,
    hpack: HpackDecoder,
}

impl Default for TerminalFormatter {
    fn default() -> Self {
        Self::new(false)
    }
}

impl TerminalFormatter {
    pub fn new(show_hexdump: bool) -> Self {
        Self {
            show_hexdump,
            hpack: HpackDecoder::default(),
        }
    }

    pub fn format_event(&mut self, event: &TlsEvent) -> String {
        let proto = event.detect_protocol();
        let dir_badge = match event.direction {
            Direction::Egress => ">>> [SEND]".bold().cyan(),
            Direction::Ingress => "<<< [RECV]".bold().green(),
        };

        let latency_str = event
            .latency_us
            .map(|us| format!("{}µs", us).dimmed())
            .unwrap_or_default();

        let header_line = format!(
            "{} PID:{} FD:{} Proto:{} Len:{}B {}",
            dir_badge,
            event.pid.to_string().yellow(),
            event.fd.to_string().magenta(),
            proto.to_string().bold().blue(),
            event.data_len.to_string().bold(),
            latency_str
        );

        let mut output = format!("{}\n", header_line);

        match proto {
            ProtocolType::Http1 => {
                if let Some(msg) = Http1Parser::parse(&event.data) {
                    match msg {
                        Http1Message::Request {
                            method,
                            uri,
                            version,
                            headers,
                            body,
                        } => {
                            output.push_str(&format!(
                                "  {} {} {}\n",
                                method.bold().bright_green(),
                                uri.bright_white(),
                                version.dimmed()
                            ));
                            for (k, v) in headers {
                                output.push_str(&format!("  {}: {}\n", k.dimmed(), v));
                            }
                            if !body.is_empty() {
                                let body_preview = String::from_utf8_lossy(&body);
                                output.push_str(&format!(
                                    "  [Body: {} bytes]\n  {}\n",
                                    body.len(),
                                    body_preview.trim()
                                ));
                            }
                        }
                        Http1Message::Response {
                            status_code,
                            reason,
                            version,
                            headers,
                            body,
                        } => {
                            let status_colored = if status_code < 300 {
                                status_code.to_string().bold().green()
                            } else if status_code < 400 {
                                status_code.to_string().bold().yellow()
                            } else {
                                status_code.to_string().bold().red()
                            };

                            output.push_str(&format!(
                                "  {} {} {}\n",
                                version.dimmed(),
                                status_colored,
                                reason.dimmed()
                            ));
                            for (k, v) in headers {
                                output.push_str(&format!("  {}: {}\n", k.dimmed(), v));
                            }
                            if !body.is_empty() {
                                let body_preview = String::from_utf8_lossy(&body);
                                output.push_str(&format!(
                                    "  [Body: {} bytes]\n  {}\n",
                                    body.len(),
                                    body_preview.trim()
                                ));
                            }
                        }
                    }
                } else {
                    output.push_str(&Self::hexdump_preview(&event.data));
                }
            }
            ProtocolType::Http2 => {
                let frames = Http2Parser::parse_frames(&event.data);
                for frame in frames {
                    output.push_str(&format!(
                        "  [H2 Frame] Stream:{} Type:{:?} Flags:0x{:02x} Len:{}\n",
                        frame.stream_id, frame.frame_type, frame.flags, frame.length
                    ));

                    if frame.frame_type == Http2FrameType::Headers {
                        if let Ok(headers) = self.hpack.decode(&frame.payload) {
                            for h in headers {
                                output.push_str(&format!("    {}: {}\n", h.name.cyan(), h.value));
                            }
                        }
                    } else if frame.frame_type == Http2FrameType::Data && !frame.payload.is_empty()
                    {
                        let text = String::from_utf8_lossy(&frame.payload);
                        output.push_str(&format!("    [Data]: {}\n", text.trim()));
                    }
                }
            }
            ProtocolType::Grpc => {
                let messages = GrpcParser::parse_messages(&event.data);
                for msg in messages {
                    output.push_str(&format!(
                        "  [gRPC Message] Len:{} Compressed:{}\n",
                        msg.length, msg.is_compressed
                    ));
                    output.push_str(&Self::hexdump_preview(&msg.payload));
                }
            }
            ProtocolType::WebSocket => {
                let frames =
                    crate::proto::websocket::WebSocketParser::parse_all_frames(&event.data);
                for frame in frames {
                    output.push_str(&format!(
                        "  [WebSocket Frame] Opcode:{} FIN:{} Masked:{} Len:{}\n",
                        frame.opcode.to_string().cyan(),
                        frame.fin,
                        frame.masked,
                        frame.payload_len
                    ));
                    if let Some(ref text) = frame.text_preview {
                        output.push_str(&format!("  Payload: {}\n", text.green()));
                    } else if !frame.payload.is_empty() {
                        output.push_str(&Self::hexdump_preview(&frame.payload));
                    }
                }
            }
            ProtocolType::X509 => {
                if let Some(cert) = crate::proto::x509::X509Parser::parse(&event.data) {
                    output.push_str(&format!(
                        "  [X.509 Certificate] Subject: CN={} | Issuer: CN={}\n",
                        cert.subject_cn.as_deref().unwrap_or("Unknown").green(),
                        cert.issuer_cn.as_deref().unwrap_or("Unknown").yellow()
                    ));
                    output.push_str(&format!(
                        "  Validity: {} -> {} | SANs: {:?}\n",
                        cert.not_before.as_deref().unwrap_or("?").dimmed(),
                        cert.not_after.as_deref().unwrap_or("?").dimmed(),
                        cert.subject_alt_names
                    ));
                    output.push_str(&format!("  SHA-256: {}\n", cert.fingerprint_sha256.cyan()));
                }
            }
            ProtocolType::Redis => {
                if let Some(cmd) =
                    crate::proto::database::NonHttpDissector::parse_redis(&event.data)
                {
                    output.push_str(&format!(
                        "  [Redis Command] {} {}\n",
                        cmd.command.red().bold(),
                        cmd.args.join(" ").white()
                    ));
                }
            }
            ProtocolType::Database => {
                if let Some(query) =
                    crate::proto::database::NonHttpDissector::parse_postgres(&event.data)
                {
                    output.push_str(&format!("  [Database SQL Query] {}\n", query.blue().bold()));
                }
            }
            ProtocolType::Smtp => {
                if let Some(line) =
                    crate::proto::database::NonHttpDissector::parse_smtp(&event.data)
                {
                    output.push_str(&format!("  [SMTP Protocol] {}\n", line.yellow()));
                }
            }
            ProtocolType::Dns => {
                if let Some(dns) = crate::proto::dns::DnsParser::parse(&event.data) {
                    output.push_str(&format!(
                        "  [DNS / DoH] ID: 0x{:04x} | {}\n",
                        dns.id,
                        dns.rcode_str().green()
                    ));
                    for q in &dns.questions {
                        output.push_str(&format!(
                            "    Question: {} ({})\n",
                            q.qname.cyan(),
                            q.qtype
                        ));
                    }
                    for a in &dns.answers {
                        output.push_str(&format!(
                            "    Answer: {} {} ➔ {}\n",
                            a.name,
                            a.rtype,
                            a.rdata.green().bold()
                        ));
                    }
                }
            }
            ProtocolType::Sse => {
                let sse_events = crate::proto::sse::SseParser::parse_stream(&event.data);
                output.push_str(&format!(
                    "  [Server-Sent Events] {} chunks\n",
                    sse_events.len()
                ));
                for s in &sse_events {
                    output.push_str(&format!(
                        "    event: {} | data: {}\n",
                        s.event_type.as_deref().unwrap_or("-").yellow(),
                        s.data.dimmed()
                    ));
                }
            }
            ProtocolType::Http3 => {
                let frames = crate::proto::http3::Http3Parser::parse_frames(&event.data);
                output.push_str(&format!("  [HTTP/3 (QUIC)] {} frames\n", frames.len()));
                for f in &frames {
                    output.push_str(&format!(
                        "    Frame: {:?} ({} bytes)\n",
                        f.frame_type, f.length
                    ));
                }
            }
            ProtocolType::RawTls => {
                if self.show_hexdump {
                    output.push_str(&Self::hexdump(&event.data));
                } else {
                    output.push_str(&Self::hexdump_preview(&event.data));
                }
            }
        }

        if self.show_hexdump && proto != ProtocolType::RawTls {
            output.push_str("\n  [Hexdump]:\n");
            output.push_str(&Self::hexdump(&event.data));
        }

        output
    }

    pub fn hexdump(data: &[u8]) -> String {
        let mut out = String::new();
        for chunk_idx in (0..data.len()).step_by(16) {
            let chunk = &data[chunk_idx..(chunk_idx + 16).min(data.len())];

            let hex_part: Vec<String> = chunk.iter().map(|b| format!("{:02x}", b)).collect();
            let mut hex_str = hex_part.join(" ");
            while hex_str.len() < 48 {
                hex_str.push(' ');
            }

            let ascii_part: String = chunk
                .iter()
                .map(|&b| {
                    if (32..=126).contains(&b) {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();

            out.push_str(&format!(
                "  {:08x}  {}  |{}|\n",
                chunk_idx, hex_str, ascii_part
            ));
        }
        out
    }

    fn hexdump_preview(data: &[u8]) -> String {
        let preview_len = data.len().min(64);
        Self::hexdump(&data[..preview_len])
    }
}
