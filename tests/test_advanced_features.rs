use nullca::engine::fuzz::DEFAULT_FUZZ_DICTIONARY;
use nullca::engine::idor::IdorDetector;
use nullca::export::graphql::{GraphQLSchema, GraphQLSynthesizer};
use nullca::proto::compression::{CompressionAlgorithm, Decompressor};
use serde_json::json;

#[test]
fn test_integration_compression_detection_and_decompression() {
    // 1. Check header parsing
    assert_eq!(CompressionAlgorithm::from_header("gzip, deflate"), CompressionAlgorithm::Gzip);
    assert_eq!(CompressionAlgorithm::from_header("br"), CompressionAlgorithm::Brotli);
    assert_eq!(CompressionAlgorithm::from_header("zstd"), CompressionAlgorithm::Zstd);

    // 2. Raw uncompressed deflate block (BFINAL=1, BTYPE=00)
    let mut block = vec![0x01, 0x05, 0x00, 0xfa, 0xff];
    block.extend_from_slice(b"WORLD");

    let decompressed = Decompressor::decompress_deflate(&block).expect("Decompress deflate");
    assert_eq!(decompressed, b"WORLD");

    // 3. Fallback path when plaintext passed
    let plain = b"Hello, NullCA!";
    let res = Decompressor::decompress(plain, None);
    assert_eq!(res, plain);
}

#[test]
fn test_integration_graphql_full_schema_synthesis() {
    let mut schema = GraphQLSchema::default();

    let query_req = json!({
        "query": "query GetOrderDetails { order(id: 42) { id tracking_code total status } }"
    }).to_string();

    let query_res = json!({
        "data": {
            "order": {
                "id": "ord_1024",
                "tracking_code": "TRACK-9988",
                "total": 149.99,
                "status": "SHIPPED"
            }
        }
    }).to_string();

    let mutation_req = json!({
        "query": "mutation CancelOrder { cancelOrder(id: 42) { id success } }"
    }).to_string();

    let mutation_res = json!({
        "data": {
            "cancelOrder": {
                "id": "ord_1024",
                "success": true
            }
        }
    }).to_string();

    GraphQLSynthesizer::ingest_exchange(&mut schema, query_req.as_bytes(), query_res.as_bytes());
    GraphQLSynthesizer::ingest_exchange(&mut schema, mutation_req.as_bytes(), mutation_res.as_bytes());

    assert!(schema.query_fields.contains_key("order"));
    assert!(schema.mutation_fields.contains_key("cancelOrder"));
    assert!(schema.types.contains_key("Order"));

    let sdl = schema.to_sdl_string();
    assert!(sdl.contains("type Query {"));
    assert!(sdl.contains("order: Order"));
    assert!(sdl.contains("type Mutation {"));
    assert!(sdl.contains("cancelOrder: CancelOrder"));
    assert!(sdl.contains("type Order {"));
    assert!(sdl.contains("id: ID"));
    assert!(sdl.contains("total: Float"));
}

#[test]
fn test_integration_idor_multi_tenant_alerts() {
    let mut detector = IdorDetector::new();

    // Tenant 1 accesses their document
    detector.inspect_transaction("/api/v1/documents/550e8400-e29b-41d4-a716-446655440000", Some("Bearer tenant_1_token"), 200);
    assert!(detector.alerts.is_empty());

    // Tenant 2 tries to access Tenant 1's document and gets 403 Forbidden (Normal auth behavior)
    detector.inspect_transaction("/api/v1/documents/550e8400-e29b-41d4-a716-446655440000", Some("Bearer tenant_2_token"), 403);
    assert!(detector.alerts.is_empty());

    // Tenant 3 tries to access Tenant 1's document and gets 200 OK (CRITICAL BOLA/IDOR VULNERABILITY!)
    detector.inspect_transaction("/api/v1/documents/550e8400-e29b-41d4-a716-446655440000", Some("Bearer tenant_3_token"), 200);
    assert_eq!(detector.alerts.len(), 1);

    let alert = &detector.alerts[0];
    assert_eq!(alert.target_resource_id, "550e8400-e29b-41d4-a716-446655440000");
    assert_eq!(alert.original_identity, "Bearer tenant_1_token");
    assert_eq!(alert.accessing_identity, "Bearer tenant_3_token");
    assert_eq!(alert.status_code, 200);
    assert_eq!(alert.severity, "CRITICAL");
}

#[test]
fn test_integration_fuzz_dictionary_payloads() {
    assert!(DEFAULT_FUZZ_DICTIONARY.len() >= 10);
    let injection_count = DEFAULT_FUZZ_DICTIONARY.iter().filter(|p| matches!(p, nullca::engine::fuzz::FuzzPayload::InjectionCheck(_))).count();
    assert!(injection_count >= 3);
}
