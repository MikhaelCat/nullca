use nullca::engine::diff::{DiffEngine, DiffKind};
use nullca::engine::event::{Direction, TlsEvent};

#[test]
fn test_diff_engine_json_body_comparison() {
    let json_a = r#"{"user":"alice","role":"guest","active":true}"#;
    let json_b = r#"{"user":"alice","role":"admin","active":true,"mfa":true}"#;

    let payload_a = format!(
        "POST /api/v1/auth HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\n\r\n{}",
        json_a
    );
    let payload_b = format!(
        "POST /api/v1/auth HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nX-Admin-Key: secret\r\n\r\n{}",
        json_b
    );

    let ev_a = TlsEvent::new(
        1000,
        1234,
        1234,
        3,
        Direction::Egress,
        "curl".into(),
        payload_a.into_bytes(),
        Some(10),
    );

    let ev_b = TlsEvent::new(
        2000,
        1234,
        1234,
        3,
        Direction::Egress,
        "curl".into(),
        payload_b.into_bytes(),
        Some(12),
    );

    let result = DiffEngine::diff_events(0, &ev_a, 1, &ev_b);

    // Header diff check: X-Admin-Key was added
    let admin_header = result
        .header_diffs
        .iter()
        .find(|h| h.name == "x-admin-key")
        .expect("x-admin-key header diff present");
    assert_eq!(admin_header.kind, DiffKind::Added);

    // Body diff check: role changed from guest to admin, mfa added
    let role_removed = result
        .body_diffs
        .iter()
        .find(|d| d.kind == DiffKind::Removed && d.content.contains("guest"));
    assert!(role_removed.is_some(), "Old guest role detected as removed");

    let role_added = result
        .body_diffs
        .iter()
        .find(|d| d.kind == DiffKind::Added && d.content.contains("admin"));
    assert!(role_added.is_some(), "New admin role detected as added");

    assert!(result.total_additions > 0);
    assert!(result.total_deletions > 0);

    // Check terminal rendering does not panic and contains summary
    let term_str = DiffEngine::format_terminal(&result);
    assert!(term_str.contains("additions"));
    assert!(term_str.contains("deletions"));
}

#[test]
fn test_diff_identical_events_zero_diff() {
    let payload = b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let ev = TlsEvent::new(
        1000,
        500,
        500,
        4,
        Direction::Egress,
        "app".into(),
        payload.to_vec(),
        None,
    );

    let result = DiffEngine::diff_events(0, &ev, 1, &ev);
    assert_eq!(result.total_additions, 0);
    assert_eq!(result.total_deletions, 0);
}
