use nullca::engine::event::{Direction, TlsEvent};
use nullca::export::pcapng::PcapNgWriter;
use tempfile::NamedTempFile;

#[test]
fn test_pcapng_export_and_packet_dissection() {
    let tmp = NamedTempFile::new().expect("Failed to create temp file");
    let path = tmp.path();

    let mut writer = PcapNgWriter::create(path).expect("Failed to create PCAP-NG file");

    let events = vec![
        TlsEvent::new(
            1700000000000000000,
            1001,
            1001,
            5,
            Direction::Egress,
            "curl".into(),
            b"GET /index.html HTTP/1.1\r\nHost: example.org\r\n\r\n".to_vec(),
            Some(35),
        ),
        TlsEvent::new(
            1700000000050000000,
            1001,
            1001,
            5,
            Direction::Ingress,
            "curl".into(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!".to_vec(),
            Some(89),
        ),
    ];

    for ev in &events {
        writer.write_event(ev).expect("Failed to write packet");
    }

    let data = std::fs::read(path).expect("Failed to read file");
    // Verify Section Header Block
    assert_eq!(&data[0..4], &[0x0A, 0x0D, 0x0D, 0x0A]);

    // Verify file contains at least 2 Enhanced Packet Blocks (0x00000006)
    let epb_count = data
        .windows(4)
        .filter(|w| *w == [0x06, 0x00, 0x00, 0x00])
        .count();
    assert!(epb_count >= 2, "Expected at least 2 EPB blocks");
}
