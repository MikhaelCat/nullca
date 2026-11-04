use nullca::engine::event::Direction;
use nullca::proto::reassembler::{ConnectionKey, StreamReassembler};

#[test]
fn test_multiple_fragmented_http1_pipeline() {
    let mut reassembler = StreamReassembler::new(1024 * 1024);
    let key = ConnectionKey {
        pid: 9999,
        fd: 4,
        direction: Direction::Egress,
    };

    // First fragment
    let chunk1 = b"POST /api/v1/telemetry HTTP/1.1\r\n";
    assert!(reassembler.push_chunk(key.clone(), chunk1).is_none());

    // Second fragment
    let chunk2 = b"Host: telemetry.server.io\r\nContent-Length: 16\r\n\r\n";
    assert!(reassembler.push_chunk(key.clone(), chunk2).is_none());

    // Third fragment (half of body)
    let chunk3 = b"{\"event\":";
    assert!(reassembler.push_chunk(key.clone(), chunk3).is_none());

    // Fourth fragment (rest of body)
    let chunk4 = b"\"ping\"}";
    let complete = reassembler
        .push_chunk(key, chunk4)
        .expect("Stream reassembler should return complete message");

    let expected = b"POST /api/v1/telemetry HTTP/1.1\r\nHost: telemetry.server.io\r\nContent-Length: 16\r\n\r\n{\"event\":\"ping\"}";
    assert_eq!(&complete[..], expected);
}
