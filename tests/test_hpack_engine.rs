use nullca::proto::http2::HpackDecoder;

#[test]
fn test_rfc7541_indexed_header() {
    let mut decoder = HpackDecoder::default();
    // 0x82 is index 2 (:method: GET)
    // 0x84 is index 4 (:path: /)
    let payload = [0x82, 0x84];
    let headers = decoder.decode(&payload).expect("Decoding failed");

    assert_eq!(headers.len(), 2);
    assert_eq!(headers[0].name, ":method");
    assert_eq!(headers[0].value, "GET");
    assert_eq!(headers[1].name, ":path");
    assert_eq!(headers[1].value, "/");
}

#[test]
fn test_rfc7541_literal_header_incremental_indexing() {
    let mut decoder = HpackDecoder::default();
    // 0x40 = Literal Header Field with Incremental Indexing -- New Name
    // 0x0a = 10 bytes name length
    // "custom-key"
    // 0x0d = 13 bytes value length
    // "custom-header"
    let mut raw = Vec::new();
    raw.push(0x40);
    raw.push(0x0a);
    raw.extend_from_slice(b"custom-key");
    raw.push(0x0d);
    raw.extend_from_slice(b"custom-header");

    let headers = decoder.decode(&raw).expect("Failed to decode custom literal");
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].name, "custom-key");
    assert_eq!(headers[0].value, "custom-header");

    // The entry is now in dynamic table at index 62!
    // 0xbe = 0x80 | 62 = 10111110 = 0xbe
    let raw_indexed = [0xbe];
    let headers2 = decoder.decode(&raw_indexed).expect("Failed to look up dynamic table entry");
    assert_eq!(headers2.len(), 1);
    assert_eq!(headers2[0].name, "custom-key");
    assert_eq!(headers2[0].value, "custom-header");
}
