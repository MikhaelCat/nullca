use nullca::engine::event::{Direction, ProtocolType, TlsEvent};
use nullca::proto::x509::X509Parser;

#[test]
fn test_x509_pem_certificate_dissection() {
    let pem = r#"-----BEGIN CERTIFICATE-----
MIIBdDCCARqgAwIBAgIUYItNEQKCk1EPmrmeHl4Oqx85XaswCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNTnVtYSBMb2NhbCBDQTAeFw0yNjA2MDIwMzE3MzRaFw0zNjA1
MzAwMzE3MzRaMBgxFjAUBgNVBAMMDU51bWEgTG9jYWwgQ0EwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAASbtMFVgZ++B/y7wBR7orv+ai/fQs1XdKjDjGwplcL9hl9m
AzeN8YsUWS/4HoVe1ZTw0EmcrDSC3N0UAp4V81n6o0IwQDAOBgNVHQ8BAf8EBAMC
AQYwHQYDVR0OBBYEFFkeCpXmD0go87uufqdqt1tNkvoFMA8GA1UdEwEB/wQFMAMB
Af8wCgYIKoZIzj0EAwIDSAAwRQIhAK3cAp0kvxSVWwBQBi+HFXBkgTEZ7avy8UA1
2MqTQxkTAiAYyJ4FvU2NtN8VsgDFvyw0KnucXFDJLA0DlX45sbOafA==
-----END CERTIFICATE-----"#;

    let cert = X509Parser::parse(pem.as_bytes()).expect("Must parse valid X.509 PEM");
    assert_eq!(cert.subject_cn.as_deref(), Some("Numa Local CA"));
    assert_eq!(cert.issuer_cn.as_deref(), Some("Numa Local CA"));
    assert!(!cert.fingerprint_sha256.is_empty());
}

#[test]
fn test_event_protocol_auto_detection_non_http() {
    // 1. Redis RESP
    let redis_wire = b"*2\r\n$4\r\nAUTH\r\n$12\r\nsecret_token\r\n";
    let ev_redis = TlsEvent::new(0, 1, 1, 3, Direction::Egress, "redis-cli".into(), redis_wire.to_vec(), None);
    assert_eq!(ev_redis.protocol(), ProtocolType::Redis);

    // 2. Postgres Query
    let query = b"SELECT 1 FROM dual;\0";
    let len = (4 + query.len()) as u32;
    let mut pg_wire = vec![b'Q'];
    pg_wire.extend_from_slice(&len.to_be_bytes());
    pg_wire.extend_from_slice(query);
    let ev_pg = TlsEvent::new(0, 1, 1, 3, Direction::Egress, "psql".into(), pg_wire, None);
    assert_eq!(ev_pg.protocol(), ProtocolType::Database);

    // 3. SMTP Mail
    let smtp_wire = b"MAIL FROM:<sender@secure.org>\r\n";
    let ev_smtp = TlsEvent::new(0, 1, 1, 3, Direction::Egress, "postfix".into(), smtp_wire.to_vec(), None);
    assert_eq!(ev_smtp.protocol(), ProtocolType::Smtp);

    // 4. X.509 Certificate
    let pem_wire = b"-----BEGIN CERTIFICATE-----\nMIIBdDCCARqgAwIBAgIUYItNEQKCk1EPmrmeHl4Oqx85XaswCgYIKoZIzj0EAwIw\n-----END CERTIFICATE-----\n";
    let ev_x509 = TlsEvent::new(0, 1, 1, 3, Direction::Ingress, "curl".into(), pem_wire.to_vec(), None);
    assert_eq!(ev_x509.protocol(), ProtocolType::X509);
}
