use nullca::engine::event::{Direction, TlsEvent};
use nullca::engine::filter::FilterEngine;
use nullca::proto::http2::{Http2Frame, Http2FrameType};
use nullca::proto::huffman::{decode_huffman, encode_huffman};
use nullca::proto::multiplexer::Http2Session;
use nullca::proto::protobuf::{encode_varint, ProtobufMessage, ProtobufValue};

#[test]
fn test_advanced_protobuf_nested_decode() {
    // Construct nested protobuf message:
    // Outer Field 1: Varint = 42
    // Outer Field 2: Nested Message containing:
    //   Inner Field 1: String = "sub-payload"
    //   Inner Field 2: Varint = 100
    let mut inner = Vec::new();
    // Inner field 1: string tag (1 << 3) | 2 = 0x0A
    inner.push(0x0A);
    let str_bytes = b"sub-payload";
    inner.extend_from_slice(&encode_varint(str_bytes.len() as u64));
    inner.extend_from_slice(str_bytes);
    // Inner field 2: varint tag (2 << 3) | 0 = 0x10
    inner.push(0x10);
    inner.extend_from_slice(&encode_varint(100));

    let mut outer = Vec::new();
    // Outer field 1: tag (1 << 3) | 0 = 0x08
    outer.push(0x08);
    outer.extend_from_slice(&encode_varint(42));
    // Outer field 2: nested message tag (2 << 3) | 2 = 0x12
    outer.push(0x12);
    outer.extend_from_slice(&encode_varint(inner.len() as u64));
    outer.extend_from_slice(&inner);

    let decoded = ProtobufMessage::decode(&outer).expect("Failed to decode outer protobuf");
    assert_eq!(
        decoded.fields.get(&1).unwrap()[0],
        ProtobufValue::Varint(42)
    );

    match &decoded.fields.get(&2).unwrap()[0] {
        ProtobufValue::Message(sub) => {
            assert_eq!(
                sub.fields.get(&1).unwrap()[0],
                ProtobufValue::String("sub-payload".to_string())
            );
            assert_eq!(sub.fields.get(&2).unwrap()[0], ProtobufValue::Varint(100));
        }
        other => panic!("Expected nested ProtobufValue::Message, got {:?}", other),
    }

    let json = decoded.to_json();
    assert!(json.contains("sub-payload"));
}

#[test]
fn test_advanced_filter_dsl_complex_logic() {
    let ev1 = TlsEvent::new(
        1000,
        2001,
        2001,
        6,
        Direction::Ingress,
        "envoy".into(),
        b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 12\r\n\r\nServer Crash".to_vec(),
        Some(250),
    );

    let ev2 = TlsEvent::new(
        2000,
        3002,
        3002,
        8,
        Direction::Egress,
        "grpc-client".into(),
        vec![0x00, 0x00, 0x00, 0x00, 0x04, 0x08, 0x01, 0x10, 0x02],
        Some(15),
    );

    let filter1 = FilterEngine::compile("comm == 'envoy' && body contains 'Server Crash'").unwrap();
    assert!(filter1.matches(&ev1));
    assert!(!filter1.matches(&ev2));

    let filter2 = FilterEngine::compile("pid == 3002 && (len < 50 || proto == 'http1')").unwrap();
    assert!(!filter2.matches(&ev1));
    assert!(filter2.matches(&ev2));

    let filter3 = FilterEngine::compile("! (comm == 'envoy')").unwrap();
    assert!(!filter3.matches(&ev1));
    assert!(filter3.matches(&ev2));
}

#[test]
fn test_advanced_http2_multiplexing_with_continuation() {
    let mut session = Http2Session::new();

    // Stream 1 HEADERS frame without END_HEADERS (flags = 0x00)
    let headers1_chunk1 = Http2Frame {
        length: 1,
        frame_type: Http2FrameType::Headers,
        flags: 0x00, // No END_HEADERS
        stream_id: 1,
        payload: vec![0x82], // :method: GET
    };
    let txs = session.process_frame(headers1_chunk1);
    assert!(txs.is_empty());

    // Stream 1 CONTINUATION frame with END_HEADERS (flags = 0x04)
    let headers1_continuation = Http2Frame {
        length: 1,
        frame_type: Http2FrameType::Continuation,
        flags: 0x04, // END_HEADERS
        stream_id: 1,
        payload: vec![0x84], // :path: /
    };
    let txs = session.process_frame(headers1_continuation);
    assert!(txs.is_empty());

    // Stream 1 DATA frame with END_STREAM (flags = 0x01)
    let data1 = Http2Frame {
        length: 9,
        frame_type: Http2FrameType::Data,
        flags: 0x01, // END_STREAM
        stream_id: 1,
        payload: b"ping-pong".to_vec(),
    };
    let txs = session.process_frame(data1);
    assert_eq!(txs.len(), 1);
    assert_eq!(txs[0].stream_id, 1);
    assert_eq!(&txs[0].body, b"ping-pong");
}

#[test]
fn test_huffman_stress_and_padding() {
    let strings = [
        ":authority",
        "gzip, deflate, br, zstd",
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M",
        "user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    ];

    for s in strings {
        let enc = encode_huffman(s.as_bytes());
        assert!(
            enc.len() <= s.len(),
            "Huffman encoding should compress or be near size"
        );
        let dec = decode_huffman(&enc).expect("Decoded bytes must succeed");
        assert_eq!(String::from_utf8(dec).unwrap(), s);
    }
}

#[test]
fn test_har_export_generation() {
    use nullca::export::har::HarExporter;

    let req = TlsEvent::new(
        1700000000000000000,
        5001,
        5001,
        7,
        Direction::Egress,
        "curl".into(),
        b"GET /api/v2/stats HTTP/1.1\r\nHost: metrics.internal\r\nAccept: application/json\r\n\r\n"
            .to_vec(),
        Some(100),
    );

    let resp = TlsEvent::new(
        1700000000050000000,
        5001,
        5001,
        7,
        Direction::Ingress,
        "curl".into(),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}".to_vec(),
        Some(50000), // 50ms latency
    );

    let har = HarExporter::export_events(&[req, resp]);
    assert_eq!(har.log.version, "1.2");
    assert_eq!(har.log.creator.name, "nullca");
    assert_eq!(har.log.entries.len(), 1);
    assert_eq!(har.log.entries[0].request.method, "GET");
    assert_eq!(
        har.log.entries[0].request.url,
        "https://metrics.internal/api/v2/stats"
    );
    assert_eq!(har.log.entries[0].response.status, 200);
}
