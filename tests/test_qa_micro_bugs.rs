//! Comprehensive QA Validation Suite: Micro-Bugs, Edge Cases & Protocol RFC Edge Behaviors.
//!
//! Validates:
//! 1. Server-Sent Events (SSE) CRLF (\r\n\r\n) multi-event dispatch and comments
//! 2. DNS multi-segment TXT (DKIM/SPF) concatenation and MX record parsing
//! 3. HTTP/1.1 non-ASCII header offset safety (preventing byte drift into body)
//! 4. HTTP Request Smuggling detection (TE.CL / CL.TE / CL.CL conflicting headers)
//! 5. HAR 1.2 binary payload base64 encoding and URL query string parsing
//! 6. StreamReassembler false-positive avoidance on chunk payloads containing `0\r\n\r\n`
//! 7. StreamReassembler chunked messages with HTTP trailers
//! 8. WebSocketAssembler memory exhaustion limit and RFC 6455 0-byte Close frames
//! 9. JWT flexible base64 decoding (padded/unpadded) and future `nbf` claim detection
//! 10. GraphQL schema synthesizer depth bounding on adversarial nested JSON

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use nullca::engine::audit::{AuditCategory, AuditSeverity, SecurityAuditor};
use nullca::engine::event::{Direction, TlsEvent};
use nullca::engine::jwt_audit::JwtAuditor;
use nullca::export::graphql::{GraphQLSchema, GraphQLSynthesizer};
use nullca::export::har::HarExporter;
use nullca::proto::dns::{DnsParser, DnsRecordType};
use nullca::proto::http1::{Http1Message, Http1Parser};
use nullca::proto::reassembler::{ConnectionKey, StreamReassembler};
use nullca::proto::sse::SseParser;
use nullca::proto::websocket::{
    WebSocketAssembler, WebSocketFrame, WebSocketOpcode, WebSocketParser,
};

#[test]
fn test_micro_bug_sse_crlf_and_comment_interleaving() {
    let raw = b": keepalive ping\r\nevent: update\r\nid: evt-101\r\ndata: {\"status\":\"online\"}\r\n\r\n: second comment\r\nevent: delta\r\ndata: line one\r\ndata: line two\r\n\r\n";
    let events = SseParser::parse_stream(raw);

    assert_eq!(
        events.len(),
        2,
        "Must parse exactly 2 CRLF-delimited SSE events"
    );
    assert_eq!(events[0].event_type.as_deref(), Some("update"));
    assert_eq!(events[0].id.as_deref(), Some("evt-101"));
    assert_eq!(events[0].data, "{\"status\":\"online\"}");
    assert!(events[0].is_json);

    assert_eq!(events[1].event_type.as_deref(), Some("delta"));
    assert_eq!(events[1].data, "line one\nline two");
    assert!(!events[1].is_json);
}

#[test]
fn test_micro_bug_dns_multisegment_txt_dkim_spf_and_mx() {
    // Synthetic DNS response with a 2-segment TXT record and an MX record
    let mut raw = vec![
        0x43, 0x21, // ID
        0x81, 0x80, // Standard response, NoError
        0x00, 0x00, // QDCOUNT = 0
        0x00, 0x02, // ANCOUNT = 2
        0x00, 0x00, 0x00, 0x00,
    ];

    // Answer 1: TXT record for "auth.example.com"
    raw.extend_from_slice(&[
        0x04, b'a', b'u', b't', b'h', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c',
        b'o', b'm', 0x00,
    ]);
    raw.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]); // TYPE: TXT (16), CLASS: IN
    raw.extend_from_slice(&[0x00, 0x00, 0x0e, 0x10]); // TTL: 3600
    let chunk1 = b"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA";
    let chunk2 = b"abcdefghijklmnopqrstuvwxyz0123456789+QIDAQAB";
    let rdlength = (1 + chunk1.len() + 1 + chunk2.len()) as u16;
    raw.extend_from_slice(&rdlength.to_be_bytes());
    raw.push(chunk1.len() as u8);
    raw.extend_from_slice(chunk1);
    raw.push(chunk2.len() as u8);
    raw.extend_from_slice(chunk2);

    // Answer 2: MX record (preference: 20, host: mx2.example.com)
    raw.extend_from_slice(&[0xC0, 0x0C]); // Pointer
    raw.extend_from_slice(&[0x00, 0x0F, 0x00, 0x01]); // TYPE: MX (15), CLASS: IN
    raw.extend_from_slice(&[0x00, 0x00, 0x0e, 0x10]); // TTL: 3600
    let mut mx_rdata = Vec::new();
    mx_rdata.extend_from_slice(&20u16.to_be_bytes());
    mx_rdata.extend_from_slice(&[
        0x03, b'm', b'x', b'2', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o',
        b'm', 0x00,
    ]);
    raw.extend_from_slice(&(mx_rdata.len() as u16).to_be_bytes());
    raw.extend_from_slice(&mx_rdata);

    let parsed = DnsParser::parse(&raw).expect("Must dissect multi-segment TXT and MX");
    assert_eq!(parsed.answers.len(), 2);
    assert_eq!(parsed.answers[0].rtype, DnsRecordType::Txt);
    let expected_txt = format!(
        "{}{}",
        std::str::from_utf8(chunk1).unwrap(),
        std::str::from_utf8(chunk2).unwrap()
    );
    assert_eq!(
        parsed.answers[0].rdata, expected_txt,
        "Multi-segment TXT must be concatenated"
    );

    assert_eq!(parsed.answers[1].rtype, DnsRecordType::Mx);
    assert_eq!(parsed.answers[1].rdata, "20 mx2.example.com");
}

#[test]
fn test_micro_bug_http1_non_ascii_header_offset_drift() {
    let mut raw = Vec::new();
    raw.extend_from_slice(b"POST /api/upload HTTP/1.1\r\nHost: example.com\r\nX-Bad: \x80\xFF\xFE\r\nContent-Length: 6\r\n\r\nBINARY");

    let parsed = Http1Parser::parse(&raw).expect("Must parse HTTP/1.1 message");
    if let Http1Message::Request { body, headers, .. } = parsed {
        assert_eq!(
            &body, b"BINARY",
            "Body bytes must remain perfectly aligned despite non-ASCII header replacement chars"
        );
        assert_eq!(headers.get("content-length").map(|s| s.as_str()), Some("6"));
    } else {
        panic!("Expected Request");
    }
}

#[test]
fn test_micro_bug_http1_request_smuggling_te_cl_cl_cl() {
    // 1. Conflicting multiple Content-Length headers
    let cl_cl_raw = b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nContent-Length: 12\r\n\r\nhello";
    let parsed = Http1Parser::parse(cl_cl_raw).expect("Must parse message");
    if let Http1Message::Request { headers, .. } = parsed {
        assert_eq!(
            headers.get("x-nullca-smuggling-risk").map(|s| s.as_str()),
            Some("conflicting-content-length"),
            "Must flag conflicting Content-Length smuggling risk"
        );
    } else {
        panic!("Expected Request");
    }

    // 2. TE.CL smuggling ambiguity audited by SecurityAuditor
    let mut req_headers = std::collections::HashMap::new();
    req_headers.insert("host".to_string(), "vulnerable.com".to_string());
    req_headers.insert("transfer-encoding".to_string(), "chunked".to_string());
    req_headers.insert("content-length".to_string(), "10".to_string());

    let auditor = SecurityAuditor::new();
    let mut findings = Vec::new();
    auditor.audit_single_exchange(
        "POST https://vulnerable.com/smuggle",
        &req_headers,
        b"0\r\n\r\n",
        200,
        &std::collections::HashMap::new(),
        b"OK",
        &mut findings,
    );

    let smuggling_finding = findings
        .iter()
        .find(|f| f.category == AuditCategory::HttpRequestSmuggling);
    assert!(
        smuggling_finding.is_some(),
        "Must report Critical HTTP Request Smuggling finding"
    );
    assert_eq!(smuggling_finding.unwrap().severity, AuditSeverity::Critical);
}

#[test]
fn test_micro_bug_har_binary_body_base64_and_query_string() {
    let raw_binary = vec![
        0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0xFF, 0xFE, 0x00,
    ];

    let req_data =
        b"GET /images/logo.png?v=2&theme=dark&retina HTTP/1.1\r\nHost: cdn.example.com\r\n\r\n";
    let mut resp_data =
        b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 11\r\n\r\n".to_vec();
    resp_data.extend_from_slice(&raw_binary);

    let req_event = TlsEvent::new(
        1_700_000_000_000_000_000,
        1000,
        1001,
        42,
        Direction::Egress,
        "curl".into(),
        req_data.to_vec(),
        None,
    );

    let resp_event = TlsEvent::new(
        1_700_000_000_050_000_000,
        1000,
        1001,
        42,
        Direction::Ingress,
        "curl".into(),
        resp_data,
        Some(50_000),
    );

    let har = HarExporter::export_events(&[req_event, resp_event]);
    assert_eq!(har.log.entries.len(), 1);

    let entry = &har.log.entries[0];
    // Check Query String
    assert_eq!(entry.request.query_string.len(), 3);
    assert_eq!(entry.request.query_string[0].name, "v");
    assert_eq!(entry.request.query_string[0].value, "2");
    assert_eq!(entry.request.query_string[1].name, "theme");
    assert_eq!(entry.request.query_string[1].value, "dark");
    assert_eq!(entry.request.query_string[2].name, "retina");
    assert_eq!(entry.request.query_string[2].value, "");

    // Check Binary Body Base64 preservation
    assert_eq!(entry.response.content.mime_type, "image/png");
    assert_eq!(entry.response.content.encoding.as_deref(), Some("base64"));
    let b64_text = entry
        .response
        .content
        .text
        .as_ref()
        .expect("Must have base64 text");
    let decoded = BASE64_STANDARD
        .decode(b64_text)
        .expect("Must decode base64");
    assert_eq!(
        decoded, raw_binary,
        "Binary data in HAR must be preserved bit-for-bit"
    );
}

#[test]
fn test_micro_bug_stream_reassembler_chunked_payload_containing_terminal_pattern() {
    let mut reassembler = StreamReassembler::default();
    let key = ConnectionKey {
        pid: 1,
        fd: 10,
        direction: Direction::Ingress,
    };

    // Body contains 6 bytes: "0\r\n\r\n!x" (hex 7) followed by terminal chunk "0\r\n\r\n"
    let mut data = Vec::new();
    data.extend_from_slice(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
    data.extend_from_slice(b"7\r\n0\r\n\r\n!x\r\n"); // 7-byte chunk containing literal "0\r\n\r\n!x"
    data.extend_from_slice(b"0\r\n\r\n"); // real terminal chunk

    let assembled = reassembler.push_chunk(key, &data);
    assert!(
        assembled.is_some(),
        "Reassembler must handle chunks containing '0\\r\\n\\r\\n' without premature cut-off"
    );
    let complete = assembled.unwrap();
    assert_eq!(complete, data);
}

#[test]
fn test_micro_bug_stream_reassembler_chunked_with_http_trailers() {
    let mut reassembler = StreamReassembler::default();
    let key = ConnectionKey {
        pid: 2,
        fd: 11,
        direction: Direction::Ingress,
    };

    let mut data = Vec::new();
    data.extend_from_slice(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
    data.extend_from_slice(b"4\r\nWiki\r\n");
    data.extend_from_slice(b"0\r\n"); // terminal chunk
    data.extend_from_slice(b"X-Checksum: a1b2c3d4\r\n\r\n"); // trailers followed by \r\n\r\n

    let assembled = reassembler.push_chunk(key, &data);
    assert!(
        assembled.is_some(),
        "Reassembler must assemble chunked response with trailers"
    );
    let complete = assembled.unwrap();
    assert_eq!(complete, data);
}

#[test]
fn test_micro_bug_websocket_assembler_memory_protection() {
    // 1. Memory ceiling protection
    let mut assembler = WebSocketAssembler::with_max_size(100);
    let frame1 = WebSocketFrame {
        fin: false,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: WebSocketOpcode::Text,
        masked: false,
        payload_len: 60,
        masking_key: None,
        payload: vec![b'A'; 60],
        text_preview: None,
        is_json: false,
    };
    let res1 = assembler.process_frame(frame1);
    assert!(res1.is_none());

    // Second continuation frame pushes buffer over 100 bytes (60 + 50 = 110 > 100)
    let frame2 = WebSocketFrame {
        fin: true,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: WebSocketOpcode::Continuation,
        masked: false,
        payload_len: 50,
        masking_key: None,
        payload: vec![b'B'; 50],
        text_preview: None,
        is_json: false,
    };
    let res2 = assembler.process_frame(frame2);
    assert!(
        res2.is_none(),
        "Assembler must drop oversized stream to protect memory"
    );

    // 2. 0-byte close frame parsed as Code 1005 (No Status Received)
    let close_raw = vec![0x88, 0x00]; // FIN=1, Opcode=Close (0x8), Len=0
    let (close_frame, consumed) =
        WebSocketParser::parse_frame(&close_raw).expect("Must parse close frame");
    assert_eq!(consumed, 2);
    assert_eq!(close_frame.opcode, WebSocketOpcode::Close);
    assert_eq!(
        close_frame.text_preview.as_deref(),
        Some("Code 1005 (No Status Received)")
    );
}

#[test]
fn test_micro_bug_jwt_flexible_base64_and_temporal_validation() {
    // Standard padded base64 test
    let h_padded = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    // payload with "nbf" set to 2 hours in the future
    let future_nbf = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 7200;
    let payload_json = format!("{{\"sub\":\"tester\",\"nbf\":{}}}", future_nbf);
    let p_b64 = BASE64_STANDARD.encode(payload_json.as_bytes());

    let raw_jwt = format!("{}.{}.fake_sig_here", h_padded, p_b64);
    let report = JwtAuditor::audit_token(&raw_jwt).expect("Must parse JWT with padded base64");

    assert!(
        report
            .vulnerabilities
            .iter()
            .any(|v| v.title.contains("Premature JWT Token")),
        "Must flag premature token with future nbf"
    );
}

#[test]
fn test_micro_bug_graphql_deep_recursion_protection() {
    let mut schema = GraphQLSchema::default();

    // Construct 40 levels of nested JSON
    let mut nested = serde_json::json!({"leaf": "value"});
    for i in 0..40 {
        nested = serde_json::json!({ format!("level_{}", i): nested });
    }

    let req_body = br#"{"query": "query { deepQuery { id } }"}"#;
    let res_body = serde_json::to_vec(&serde_json::json!({
        "data": {
            "deepQuery": nested
        }
    }))
    .unwrap();

    // Must not stack overflow or crash
    GraphQLSynthesizer::ingest_exchange(&mut schema, req_body, &res_body);
    let sdl = schema.to_sdl_string();
    assert!(
        sdl.contains("type Query"),
        "Synthesizer must safely bound recursion and produce schema"
    );
}
