use criterion::{black_box, criterion_group, criterion_main, Criterion};
use nullca::proto::http1::Http1Parser;
use nullca::proto::http2::{HpackDecoder, Http2Parser};

fn bench_http1_parsing(c: &mut Criterion) {
    let raw_request = b"POST /api/v1/charge HTTP/1.1\r\nHost: api.stripe.com\r\nAuthorization: Bearer sk_live_1234567890\r\nContent-Type: application/json\r\nContent-Length: 42\r\n\r\n{\"amount\": 5000, \"currency\": \"usd\", \"src\": \"tok_123\"}";

    c.bench_function("http1_request_parse", |b| {
        b.iter(|| {
            let parsed = Http1Parser::parse(black_box(raw_request));
            assert!(parsed.is_some());
        })
    });
}

fn bench_hpack_decoding(c: &mut Criterion) {
    let payload = [0x82, 0x84, 0x87, 0x88]; // Static table indexes: :method, :path, :scheme, :status

    c.bench_function("hpack_static_lookup", |b| {
        b.iter(|| {
            let mut decoder = HpackDecoder::default();
            let headers = decoder.decode(black_box(&payload)).unwrap();
            assert_eq!(headers.len(), 4);
        })
    });
}

fn bench_http2_frame_parse(c: &mut Criterion) {
    let raw_frame = [
        0x00, 0x00, 0x14, // 20 bytes length
        0x01,             // Type: HEADERS
        0x05,             // Flags: END_STREAM | END_HEADERS
        0x00, 0x00, 0x00, 0x01, // Stream 1
        0x82, 0x84, 0x87, 0x88, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e,
    ];

    c.bench_function("http2_frame_parse", |b| {
        b.iter(|| {
            let frames = Http2Parser::parse_frames(black_box(&raw_frame));
            assert_eq!(frames.len(), 1);
        })
    });
}

criterion_group!(benches, bench_http1_parsing, bench_hpack_decoding, bench_http2_frame_parse);
criterion_main!(benches);
