//! End-to-End QA Stress, Edge-Case & Real-World Validation Suite.
//!
//! Rigorously exercises all subsystems under adverse, adversarial, and boundary conditions:
//! - Malformed DNS compression pointer loops & out-of-bounds corruption
//! - HTTP/3 QUIC 62-bit varint boundary extremes and overflow guards
//! - SSE massive streaming with unescaped and escaped JSON tokens
//! - Adversarial and malformed JWT token permutations
//! - Postman v2.1.0 and OpenAPI 3.0 generation under non-standard HTTP traffic
//! - Live HTTP Mock Server testing for Replay & Fuzzing engines
//! - WebSocket corrupted compression stream fallback
//! - Concurrent StreamReassembler load and memory bounding

use nullca::engine::event::{Direction, TlsEvent};
use nullca::engine::fuzz::{FuzzEngine, FuzzPayload};
use nullca::engine::jwt_audit::{JwtAuditor, JwtVulnerabilitySeverity};
use nullca::engine::replay::{ReplayEngine, ReplayRequest};
use nullca::export::openapi::OpenApiGenerator;
use nullca::export::pcapng::PcapNgWriter;
use nullca::export::postman::PostmanExporter;
use nullca::proto::dns::DnsParser;
use nullca::proto::http3::{decode_quic_varint, encode_quic_varint, Http3Parser};
use nullca::proto::reassembler::{ConnectionKey, StreamReassembler};
use nullca::proto::sse::SseParser;
use nullca::proto::websocket::WebSocketParser;
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ============================================================================
// 1. DNS & DoH Stress: Compression Pointer Loop & Out-of-Bounds Guards
// ============================================================================

#[test]
fn test_qa_dns_compression_pointer_loop_protection() {
    // Construct a DNS packet where a pointer points to itself (offset 12 points to 12)
    let mut bad_packet = vec![
        0x12, 0x34, // Transaction ID
        0x81, 0x80, // Flags (Standard query response)
        0x00, 0x01, // 1 Question
        0x00, 0x01, // 1 Answer
        0x00, 0x00, 0x00, 0x00,
    ];
    // Question: Pointer loop pointing to itself (0xC0, 0x0C -> offset 12)
    bad_packet.extend_from_slice(&[0xC0, 0x0C]);
    bad_packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QType A, QClass IN

    // Parser must detect jump loop and terminate cleanly without stack overflow or hang
    let parsed = DnsParser::parse(&bad_packet);
    assert!(parsed.is_none(), "Pointer loop must be rejected gracefully");
}

#[test]
fn test_qa_dns_out_of_bounds_and_truncated_records() {
    // Truncated header (< 12 bytes)
    assert!(DnsParser::parse(&[0x01, 0x02, 0x03]).is_none());

    // Label length claim of 100 bytes on a 15-byte packet
    let bad_label_packet = vec![
        0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x64, // 100 bytes length prefix
        b'a', b'b', b'c',
    ];
    assert!(DnsParser::parse(&bad_label_packet).is_none());

    // Out-of-bounds pointer (0xC0, 0xFF pointing past end of packet)
    let bad_ptr_packet = vec![
        0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xFF,
    ];
    assert!(DnsParser::parse(&bad_ptr_packet).is_none());
}

// ============================================================================
// 2. HTTP/3 & QUIC Varint: Extremes & Length Overflow Protections
// ============================================================================

#[test]
fn test_qa_http3_quic_varint_boundary_limits_and_overflows() {
    let boundary_values: &[u64] = &[
        0,
        63,                  // 1-byte boundary
        64,                  // 2-byte boundary
        16383,               // 2-byte boundary
        16384,               // 4-byte boundary
        1073741823,          // 4-byte boundary
        1073741824,          // 8-byte boundary
        4611686018427387903, // 62-bit maximum QUIC varint (2^62 - 1)
    ];

    for &val in boundary_values {
        let encoded = encode_quic_varint(val);
        let (decoded, consumed) = decode_quic_varint(&encoded).expect("Must decode boundary value");
        assert_eq!(decoded, val, "Decoded varint mismatch for {}", val);
        assert_eq!(consumed, encoded.len());
    }

    // Huge frame length claiming 2^60 bytes in a 5-byte buffer
    let mut huge_frame = Vec::new();
    huge_frame.extend_from_slice(&encode_quic_varint(0x00)); // Type: DATA
    huge_frame.extend_from_slice(&encode_quic_varint(4611686018427387900)); // Huge length
    huge_frame.extend_from_slice(b"partial");

    // Parser must recognize length exceeds buffer and terminate without overflow panic
    let frames = Http3Parser::parse_frames(&huge_frame);
    assert!(frames.is_empty(), "Incomplete huge frame must be ignored");
}

// ============================================================================
// 3. SSE & LLM Streaming: Massive Token Assembly & Escapes
// ============================================================================

#[test]
fn test_qa_sse_massive_stream_and_escapes() {
    let mut stream_bytes = Vec::new();

    // Generate 100 streaming token chunks simulating a real LLM generation
    for i in 0..100 {
        let chunk = format!(
            "data: {{\"choices\":[{{\"delta\":{{\"content\":\"token_{} \"}}}}]}}\n\n",
            i
        );
        stream_bytes.extend_from_slice(chunk.as_bytes());
    }
    stream_bytes.extend_from_slice(b"data: [DONE]\n\n");

    let events = SseParser::parse_stream(&stream_bytes);
    assert_eq!(events.len(), 101);

    let assembled = SseParser::extract_ai_stream_text(&events);
    assert!(assembled.starts_with("token_0 token_1 "));
    assert!(assembled.contains("token_99 "));
    assert!(!assembled.contains("[DONE]"));

    // Verify unescaped tabs and backslashes
    let escape_test = br#"data: {"choices":[{"delta":{"content":"path:\\C:\\files\tinfo"}}]}"#;
    let esc_events = SseParser::parse_stream(escape_test);
    let esc_text = SseParser::extract_ai_stream_text(&esc_events);
    assert_eq!(esc_text, "path:\\C:\\files\tinfo");
}

// ============================================================================
// 4. Deep JWT Cryptographic Security Scanner: Adversarial Permutations
// ============================================================================

#[test]
fn test_qa_jwt_adversarial_malformed_tokens() {
    // 1. Single dot or no dots
    assert!(JwtAuditor::audit_token("not-a-jwt").is_none());
    assert!(JwtAuditor::audit_token("a.b").is_none());
    assert!(JwtAuditor::audit_token("a.b.c.d").is_none());

    // 2. Corrupted Base64
    assert!(JwtAuditor::audit_token("??? . !!! . ###").is_none());

    // 3. Non-JSON valid base64
    let garbage_b64 = "Z2FyYmFnZQ"; // "garbage"
    let token_garbage = format!("{}.{}.{}", garbage_b64, garbage_b64, garbage_b64);
    let report = JwtAuditor::audit_token(&token_garbage).expect("Parses base64");
    // Should flag missing expiration and default algorithm
    assert!(report.is_vulnerable());

    // 4. Offline Cracker against dictionary
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let h = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
    let p = URL_SAFE_NO_PAD.encode(b"{\"sub\":\"admin\",\"role\":\"root\",\"exp\":9999999999}");
    let signing_input = format!("{}.{}", h, p);

    for &secret in &["123456", "admin", "password", "supersecret", "development"] {
        let sig = JwtAuditor::compute_hmac_sha256(secret.as_bytes(), signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig);
        let raw = format!("{}.{}", signing_input, sig_b64);

        let rep = JwtAuditor::audit_token(&raw).expect("Must audit token");
        assert!(
            rep.vulnerabilities
                .iter()
                .any(|v| v.severity == JwtVulnerabilitySeverity::Critical
                    && v.title.contains(secret)),
            "Failed to crack secret: {}",
            secret
        );
    }
}

// ============================================================================
// 5. Postman & OpenAPI Export: Special Chars & Non-Standard Verbs
// ============================================================================

#[test]
fn test_qa_postman_and_openapi_special_characters_and_verbs() {
    let har_json = r#"{
        "log": {
            "version": "1.2",
            "creator": { "name": "nullca", "version": "0.1.0" },
            "entries": [
                {
                    "startedDateTime": "2026-11-05T00:00:00Z",
                    "time": 10.0,
                    "request": {
                        "method": "PATCH",
                        "url": "https://api.example.com/v1/users/99?filter=%20special%26value&debug=true",
                        "httpVersion": "HTTP/1.1",
                        "headers": [
                            { "name": "Content-Type", "value": "application/json" }
                        ],
                        "queryString": [],
                        "postData": {
                            "mimeType": "application/json",
                            "text": "{\"status\":\"active\",\"tags\":[\"admin\",\"qa\"]}"
                        },
                        "headersSize": 50,
                        "bodySize": 40
                    },
                    "response": {
                        "status": 200,
                        "statusText": "OK",
                        "httpVersion": "HTTP/1.1",
                        "headers": [],
                        "content": { "size": 0, "mimeType": "application/json" },
                        "redirectURL": "",
                        "headersSize": 50,
                        "bodySize": 0
                    },
                    "cache": {},
                    "timings": { "send": 1.0, "wait": 5.0, "receive": 4.0 }
                }
            ]
        }
    }"#;

    // 1. Postman Exporter
    let postman_col = PostmanExporter::from_har_str(har_json, Some("QA Special Chars Test"))
        .expect("Must parse HAR into Postman");
    assert_eq!(postman_col.item.len(), 1);
    let item = &postman_col.item[0];
    assert_eq!(item.request.method, "PATCH");
    assert_eq!(item.request.url.query.len(), 2);
    assert_eq!(item.request.url.path, vec!["v1", "users", "99"]);

    // 2. OpenAPI Exporter
    let generator = OpenApiGenerator::new();
    let root: nullca::export::har::HarRoot = serde_json::from_str(har_json).unwrap();
    let spec = generator.generate_from_har_entries(&root.log.entries, "QA Test API", "1.0.0");
    // Verify parameterized path
    assert!(spec.paths.contains_key("/v1/users/{user_id}"));
    assert!(spec.paths["/v1/users/{user_id}"].patch.is_some());
}

// ============================================================================
// 6. PCAP-NG DSB: Wireshark Keylog Format Integrity
// ============================================================================

#[test]
fn test_qa_pcapng_dsb_alignment_and_keylog_types() {
    let tmp = NamedTempFile::new().expect("Temp file");
    let path = tmp.path();

    let complex_keylog = "\
CLIENT_RANDOM 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff\n\
SERVER_HANDSHAKE_TRAFFIC_SECRET aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899 99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa\n\
EXPORTER_SECRET 1234567812345678123456781234567812345678123456781234567812345678 abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01\n";

    {
        let mut writer = PcapNgWriter::create_with_secrets(path, Some(complex_keylog))
            .expect("Must create PCAP-NG with DSB");
        let event = TlsEvent::new(
            1700000000000000000,
            123,
            123,
            5,
            Direction::Egress,
            "curl".into(),
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
            None,
        );
        writer.write_event(&event).expect("Write event");
    }

    let raw_bytes = std::fs::read(path).expect("Read pcapng");
    // Verify Block Type 0x0000000A exists
    assert!(raw_bytes.windows(4).any(|w| w == [0x0A, 0x00, 0x00, 0x00]));
    // Verify Secrets Type 'TLSK'
    assert!(raw_bytes.windows(4).any(|w| w == b"TLSK"));
    // Verify all keylog types are preserved
    assert!(raw_bytes.windows(13).any(|w| w == b"CLIENT_RANDOM"));
    assert!(raw_bytes
        .windows(31)
        .any(|w| w == b"SERVER_HANDSHAKE_TRAFFIC_SECRET"));
    assert!(raw_bytes.windows(15).any(|w| w == b"EXPORTER_SECRET"));
}

// ============================================================================
// 7. WebSocket Permessage-Deflate Corruption Resilience
// ============================================================================

#[test]
fn test_qa_websocket_corrupted_compression_fallback() {
    // Frame with RSV1 = true (claims permessage-deflate) but payload is garbage non-zlib data
    // Byte 0: 0xC1 (FIN=1, RSV1=1, Opcode=0x1 Text)
    // Byte 1: 0x0C (Masked=0, Length=12)
    let mut raw_frame = vec![0xC1, 0x0C];
    raw_frame.extend_from_slice(b"GARBAGE_DATA");

    // Decompression should gracefully fail and return raw bytes without panicking
    let (frame, _) = WebSocketParser::parse_frame(&raw_frame).expect("Must parse frame");
    assert_eq!(frame.payload, b"GARBAGE_DATA");
}

// ============================================================================
// 8. StreamReassembler: 1,000 Concurrent Sockets Churn & Memory Bounds
// ============================================================================

#[test]
fn test_qa_stream_reassembler_heavy_churn_and_prune() {
    let mut reassembler = StreamReassembler::with_limits(8192, 200, Duration::from_millis(50));

    // Send partial data to 500 different connections
    for i in 0..500 {
        let key = ConnectionKey {
            pid: 1000 + (i % 20),
            fd: i as i32,
            direction: Direction::Ingress,
        };
        reassembler.push_chunk(key, b"GET /incomplete HTTP/1.1\r\nHost: test.local\r\n");
    }

    // Capacity is strictly capped at 200
    assert!(reassembler.active_connection_count() <= 200);

    // Sleep to let them become stale
    std::thread::sleep(Duration::from_millis(60));

    // Prune stale entries
    let pruned = reassembler.prune_stale(Duration::from_millis(50));
    assert!(pruned > 0);
    assert_eq!(reassembler.active_connection_count(), 0);
}

// ============================================================================
// 9. Live Mock HTTP Server: Replay & Fuzzing Engines Real Testing
// ============================================================================

#[tokio::test]
async fn test_qa_live_http_server_replay_and_fuzzing() {
    // 1. Launch a real asynchronous local HTTP server on random port
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Bind listener");
    let local_addr = listener.local_addr().expect("Local addr");
    let port = local_addr.port();

    let server_task = tokio::spawn(async move {
        // Accept and respond to 10 incoming requests
        for _ in 0..10 {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                if let Ok(n) = socket.read(&mut buf).await {
                    let req_str = String::from_utf8_lossy(&buf[..n]);
                    let resp = if req_str.contains("500") {
                        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\n\r\nError"
                    } else if req_str.contains("admin") {
                        "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nWelcome admin"
                    } else {
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
                    };
                    let _ = socket.write_all(resp.as_bytes()).await;
                }
            }
        }
    });

    // 2. Test Live Replay Engine against real server
    let req = ReplayRequest::new("127.0.0.1".into(), port, "GET".into(), "/api/test".into());
    let replay_res = ReplayEngine::execute(&req)
        .await
        .expect("Replay execute must succeed");
    assert_eq!(replay_res.status_code, 200);
    assert!(replay_res.metrics.total_duration_ms > 0.0);

    // 3. Test Live Parameter Fuzzer against real server
    let fuzz_payloads = vec![
        FuzzPayload::Custom("normal".into()),
        FuzzPayload::Custom("500_trigger".into()),
        FuzzPayload::Custom("admin".into()),
    ];

    let fuzz_results = FuzzEngine::fuzz_parameter(&req, "query", &fuzz_payloads)
        .await
        .expect("Fuzzing must succeed");

    assert_eq!(fuzz_results.len(), 3);
    assert!(fuzz_results
        .iter()
        .any(|r| r.status_code == 500 && r.is_anomaly));
    assert!(fuzz_results
        .iter()
        .any(|r| r.status_code == 200 && r.body_len == 13));

    server_task.abort();
}
