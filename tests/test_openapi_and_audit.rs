use nullca::engine::audit::{AuditCategory, AuditSeverity, SecurityAuditor};
use nullca::export::har::{
    HarContent, HarEntry, HarHeader, HarQueryParam, HarRequest, HarResponse, HarTimings,
};
use nullca::export::openapi::OpenApiGenerator;
use nullca::export::sslkeylog::{SslKeyLogEntry, SslKeyLogWriter, TlsKeyLabel};
use serde_json::json;
use tempfile::NamedTempFile;

#[test]
fn test_integration_har_to_openapi_schema_inference() {
    let generator = OpenApiGenerator::new();

    let entry = HarEntry {
        started_date_time: "2026-11-04T12:00:00Z".to_string(),
        time: 12.5,
        request: HarRequest {
            method: "POST".to_string(),
            url: "https://api.github.com/repos/MikhaelCat/nullca/issues/101/comments".to_string(),
            http_version: "HTTP/2".to_string(),
            headers: vec![HarHeader {
                name: "Content-Type".to_string(),
                value: "application/json".to_string(),
            }],
            query_string: vec![HarQueryParam {
                name: "page".to_string(),
                value: "1".to_string(),
            }],
            post_data: Some(nullca::export::har::HarPostData {
                mime_type: "application/json".to_string(),
                text: json!({
                    "body": "NullCA Zero-CA Engine is fully verified!",
                    "priority": 1,
                    "tags": ["ebpf", "rust"]
                })
                .to_string(),
            }),
            headers_size: 150,
            body_size: 120,
        },
        response: HarResponse {
            status: 201,
            status_text: "Created".to_string(),
            http_version: "HTTP/2".to_string(),
            headers: vec![HarHeader {
                name: "Content-Type".to_string(),
                value: "application/json".to_string(),
            }],
            content: HarContent {
                size: 85,
                mime_type: "application/json".to_string(),
                text: Some(
                    json!({
                        "id": 555,
                        "created_at": "2026-11-04T12:00:01Z",
                        "author": "MikhaelCat"
                    })
                    .to_string(),
                ),
            },
            redirect_url: "".to_string(),
            headers_size: 100,
            body_size: 85,
        },
        cache: json!({}),
        timings: HarTimings {
            send: 0.5,
            wait: 10.0,
            receive: 2.0,
        },
    };

    let spec = generator.generate_from_har_entries(&[entry], "GitHub Mock API", "v3");
    assert_eq!(spec.openapi, "3.0.3");

    // Path must be clustered to /repos/MikhaelCat/nullca/issues/{issue_id}/comments
    let path_key = "/repos/MikhaelCat/nullca/issues/{issue_id}/comments";
    assert!(
        spec.paths.contains_key(path_key),
        "Expected clustered path: {}",
        path_key
    );

    let path_item = spec.paths.get(path_key).unwrap();
    assert!(path_item.post.is_some());
    let op = path_item.post.as_ref().unwrap();

    // Check request body schema
    assert!(op.request_body.is_some());
    let req_content = &op.request_body.as_ref().unwrap().content;
    let json_media = req_content.get("application/json").unwrap();
    assert_eq!(json_media.schema.schema_type.as_deref(), Some("object"));
    assert!(json_media.schema.properties.contains_key("body"));
    assert!(json_media.schema.properties.contains_key("priority"));
    assert!(json_media.schema.properties.contains_key("tags"));

    // Check responses schema
    assert!(op.responses.contains_key("201"));
    let res = op.responses.get("201").unwrap();
    let res_media = res.content.get("application/json").unwrap();
    assert_eq!(res_media.schema.schema_type.as_deref(), Some("object"));
    assert!(res_media.schema.properties.contains_key("id"));
    assert_eq!(
        res_media
            .schema
            .properties
            .get("id")
            .unwrap()
            .schema_type
            .as_deref(),
        Some("integer")
    );
}

#[test]
fn test_integration_security_auditor_critical_findings() {
    let auditor = SecurityAuditor::new();

    let entry = HarEntry {
        started_date_time: "2026-11-04T12:00:00Z".to_string(),
        time: 5.0,
        request: HarRequest {
            method: "POST".to_string(),
            url: "https://auth.example.com/oauth/token".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: vec![],
            query_string: vec![],
            post_data: None,
            headers_size: 50,
            body_size: 0,
        },
        response: HarResponse {
            status: 200,
            status_text: "OK".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: vec![
                // 1. Wildcard origin + credentials = Critical
                HarHeader {
                    name: "Access-Control-Allow-Origin".to_string(),
                    value: "*".to_string(),
                },
                HarHeader {
                    name: "Access-Control-Allow-Credentials".to_string(),
                    value: "true".to_string(),
                },
                // 2. Cookie without Secure or HttpOnly = High
                HarHeader {
                    name: "Set-Cookie".to_string(),
                    value: "auth_session=abcdef1234567890; Path=/".to_string(),
                },
                // 3. Server disclosure
                HarHeader {
                    name: "Server".to_string(),
                    value: "Apache/2.4.49 (Unix) OpenSSL/1.1.1".to_string(),
                },
            ],
            // Leaked AWS access key in response body = Critical
            content: HarContent {
                size: 60,
                mime_type: "application/json".to_string(),
                text: Some(r#"{"status": "ok", "backup_key": "AKIAIOSFODNN7EXAMPLE"}"#.to_string()),
            },
            redirect_url: "".to_string(),
            headers_size: 150,
            body_size: 60,
        },
        cache: json!({}),
        timings: HarTimings {
            send: 0.5,
            wait: 3.5,
            receive: 1.0,
        },
    };

    let report = auditor.audit_har_entries(&[entry]);
    assert_eq!(report.total_transactions, 1);
    assert!(
        report.critical_count() >= 2,
        "Expected at least 2 critical findings (CORS + AWS key leak)"
    );

    let cors_finding = report
        .findings
        .iter()
        .find(|f| f.category == AuditCategory::InsecureCors)
        .unwrap();
    assert_eq!(cors_finding.severity, AuditSeverity::Critical);

    let secret_finding = report
        .findings
        .iter()
        .find(|f| f.category == AuditCategory::SecretLeak)
        .unwrap();
    assert_eq!(secret_finding.severity, AuditSeverity::Critical);

    let cookie_finding = report
        .findings
        .iter()
        .find(|f| f.category == AuditCategory::InsecureCookie)
        .unwrap();
    assert_eq!(cookie_finding.severity, AuditSeverity::High);
}

#[test]
fn test_integration_sslkeylog_file_write_and_parse() {
    let tmp = NamedTempFile::new().expect("Create tempfile");
    let mut writer = SslKeyLogWriter::open_append(tmp.path()).expect("Open keylog writer");

    let entry1 = SslKeyLogEntry::new(TlsKeyLabel::ClientRandom, vec![0x11; 32], vec![0x22; 48]);
    let entry2 = SslKeyLogEntry::new(
        TlsKeyLabel::ClientTrafficSecret0,
        vec![0x33; 32],
        vec![0x44; 32],
    );

    writer
        .write_entries(&[entry1.clone(), entry2.clone()])
        .expect("Write entries");

    let content = std::fs::read_to_string(tmp.path()).expect("Read keylog");
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 2);

    let parsed1 = SslKeyLogEntry::parse_nss_line(lines[0]).expect("Parse line 1");
    assert_eq!(parsed1, entry1);

    let parsed2 = SslKeyLogEntry::parse_nss_line(lines[1]).expect("Parse line 2");
    assert_eq!(parsed2, entry2);
}
