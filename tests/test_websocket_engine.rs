use nullca::proto::websocket::{
    WebSocketAssembler, WebSocketCloseDetails, WebSocketFrame, WebSocketOpcode, WebSocketParser,
};

#[test]
fn test_rfc6455_unmasked_text_frame() {
    let text = "NullCA WebSocket Inspection Test";
    let mut data = vec![0x81, text.len() as u8];
    data.extend_from_slice(text.as_bytes());

    let (frame, consumed) = WebSocketParser::parse_frame(&data).expect("Must parse valid frame");
    assert_eq!(consumed, data.len());
    assert!(frame.fin);
    assert_eq!(frame.opcode, WebSocketOpcode::Text);
    assert!(!frame.masked);
    assert_eq!(frame.payload, text.as_bytes());
    assert_eq!(frame.text_preview.as_deref(), Some(text));
}

#[test]
fn test_rfc6455_masked_binary_frame_16bit_length() {
    // 300 bytes payload (length = 300 -> extended 16-bit 0x012C)
    let payload_len: usize = 300;
    let payload: Vec<u8> = (0..payload_len).map(|i| (i % 256) as u8).collect();
    let mask_key: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

    let mut masked_payload = payload.clone();
    for (i, b) in masked_payload.iter_mut().enumerate() {
        *b ^= mask_key[i % 4];
    }

    let mut wire = Vec::new();
    wire.push(0x82); // FIN=1, Opcode=Binary (0x2)
    wire.push(0xFE); // MASK=1, Len=126 (16-bit extended)
    wire.extend_from_slice(&(payload_len as u16).to_be_bytes());
    wire.extend_from_slice(&mask_key);
    wire.extend_from_slice(&masked_payload);

    let (frame, consumed) = WebSocketParser::parse_frame(&wire).expect("Must parse 16-bit frame");
    assert_eq!(consumed, wire.len());
    assert!(frame.fin);
    assert_eq!(frame.opcode, WebSocketOpcode::Binary);
    assert!(frame.masked);
    assert_eq!(frame.masking_key, Some(mask_key));
    assert_eq!(frame.payload, payload); // Verified unmasking!
}

#[test]
fn test_rfc6455_ping_pong_control_frames() {
    // Ping frame with 4-byte nonce
    let ping_data = vec![0x89, 0x04, 0x11, 0x22, 0x33, 0x44];
    let (ping_frame, n1) = WebSocketParser::parse_frame(&ping_data).unwrap();
    assert_eq!(n1, 6);
    assert_eq!(ping_frame.opcode, WebSocketOpcode::Ping);
    assert_eq!(ping_frame.payload, vec![0x11, 0x22, 0x33, 0x44]);

    // Pong frame answering with same nonce
    let pong_data = vec![0x8A, 0x04, 0x11, 0x22, 0x33, 0x44];
    let (pong_frame, n2) = WebSocketParser::parse_frame(&pong_data).unwrap();
    assert_eq!(n2, 6);
    assert_eq!(pong_frame.opcode, WebSocketOpcode::Pong);
    assert_eq!(pong_frame.payload, ping_frame.payload);
}

#[test]
fn test_rfc6455_close_status_parsing() {
    let mut close_wire = vec![0x88, 0x09, 0x03, 0xE9]; // Code 1001 (0x03E9 = Going Away)
    close_wire.extend_from_slice(b"Restart");

    let (frame, _) = WebSocketParser::parse_frame(&close_wire).unwrap();
    assert_eq!(frame.opcode, WebSocketOpcode::Close);
    let preview = frame.text_preview.expect("Must have close description");
    assert!(preview.contains("1001"));
    assert!(preview.contains("Going Away"));
    assert!(preview.contains("Restart"));
    assert_eq!(
        WebSocketCloseDetails::description_for_code(1001),
        "Going Away"
    );
}

#[test]
fn test_multi_frame_assembler_stream() {
    let mut assembler = WebSocketAssembler::new();

    // Split "NullCA Is Phenomenal" into 3 fragments
    let part1 = b"NullCA ".to_vec();
    let part2 = b"Is ".to_vec();
    let part3 = b"Phenomenal".to_vec();

    // Frame 1: Text, FIN=false
    let f1 = WebSocketFrame {
        fin: false,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: WebSocketOpcode::Text,
        masked: false,
        payload_len: part1.len(),
        masking_key: None,
        payload: part1,
        text_preview: Some("NullCA ".into()),
        is_json: false,
    };
    assert!(assembler.process_frame(f1).is_none());

    // Frame 2: Continuation, FIN=false
    let f2 = WebSocketFrame {
        fin: false,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: WebSocketOpcode::Continuation,
        masked: false,
        payload_len: part2.len(),
        masking_key: None,
        payload: part2,
        text_preview: Some("Is ".into()),
        is_json: false,
    };
    assert!(assembler.process_frame(f2).is_none());

    // Frame 3: Continuation, FIN=true
    let f3 = WebSocketFrame {
        fin: true,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: WebSocketOpcode::Continuation,
        masked: false,
        payload_len: part3.len(),
        masking_key: None,
        payload: part3,
        text_preview: Some("Phenomenal".into()),
        is_json: false,
    };

    let (opcode, complete_payload) = assembler.process_frame(f3).expect("Should complete stream");
    assert_eq!(opcode, WebSocketOpcode::Text);
    assert_eq!(complete_payload, b"NullCA Is Phenomenal");
}
