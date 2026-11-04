use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use nullca::engine::event::{Direction, TlsEvent};
use nullca::ui::dashboard::{ActivePane, DashboardState};
use nullca::ui::repeater::{RepeaterField, RepeaterState};

#[test]
fn test_dashboard_state_navigation_and_scrolling() {
    let mut state = DashboardState::new();

    for i in 0..25 {
        let ev = TlsEvent::new(
            1000 + i as u64,
            1234,
            1234,
            3,
            Direction::Egress,
            "curl".into(),
            format!("GET /item/{} HTTP/1.1\r\nHost: example.com\r\n\r\n", i).into_bytes(),
            None,
        );
        state.push_event(ev);
    }

    assert_eq!(state.events.len(), 25);
    assert_eq!(state.filtered_indices.len(), 25);

    // Initial selected is the last one (auto-scroll down when not paused)
    assert_eq!(state.table_state.selected(), Some(24));

    // Previous packet navigation
    state.prev_packet();
    assert_eq!(state.table_state.selected(), Some(23));

    // Page up navigation
    state.page_up_packets(10);
    assert_eq!(state.table_state.selected(), Some(13));

    // Page down navigation
    state.page_down_packets(5);
    assert_eq!(state.table_state.selected(), Some(18));

    // Next packet navigation
    state.next_packet();
    assert_eq!(state.table_state.selected(), Some(19));
}

#[test]
fn test_dashboard_filter_and_fullscreen_toggle() {
    let mut state = DashboardState::new();

    let ev1 = TlsEvent::new(
        1001,
        1234,
        1234,
        3,
        Direction::Egress,
        "curl".into(),
        b"GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
        None,
    );
    let ev2 = TlsEvent::new(
        1002,
        1234,
        1234,
        3,
        Direction::Ingress,
        "curl".into(),
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
        None,
    );
    state.push_event(ev1);
    state.push_event(ev2);

    // Apply Filter DSL: status >= 400
    state.filter_input = "status >= 400".into();
    state.apply_filter();
    assert_eq!(state.filtered_indices.len(), 1);
    assert_eq!(state.filtered_indices[0], 1);

    // Fullscreen toggle
    assert_eq!(state.maximized_pane, None);
    state.active_pane = ActivePane::DecodedDetails;
    state.maximized_pane = Some(state.active_pane);
    assert_eq!(state.maximized_pane, Some(ActivePane::DecodedDetails));

    // Reset fullscreen
    state.maximized_pane = None;
    assert_eq!(state.maximized_pane, None);
}

#[test]
fn test_repeater_state_from_event_and_editing() {
    let raw_req = b"POST /api/v1/auth HTTP/1.1\r\nHost: target.internal:8443\r\nContent-Type: application/json\r\n\r\n{\"user\":\"admin\"}";
    let ev = TlsEvent::new(
        2000,
        5555,
        5555,
        4,
        Direction::Egress,
        "microservice".into(),
        raw_req.to_vec(),
        None,
    );

    let mut rep = RepeaterState::from_event(&ev);

    assert_eq!(rep.method, "POST");
    assert_eq!(rep.host, "target.internal");
    assert_eq!(rep.port, 8443);
    assert_eq!(rep.path, "/api/v1/auth");
    assert!(rep.body_text.contains("{\"user\":\"admin\"}"));

    // Cycle fields
    assert_eq!(rep.active_field, RepeaterField::Path);
    rep.active_field = rep.active_field.next();
    assert_eq!(rep.active_field, RepeaterField::Headers);
    rep.active_field = rep.active_field.next();
    assert_eq!(rep.active_field, RepeaterField::Body);
    rep.active_field = rep.active_field.next();
    assert_eq!(rep.active_field, RepeaterField::SendButton);
    rep.active_field = rep.active_field.next();
    assert_eq!(rep.active_field, RepeaterField::Method);

    // Edit Path field
    rep.active_field = RepeaterField::Path;
    let key = KeyEvent {
        code: KeyCode::Char('x'),
        modifiers: KeyModifiers::NONE,
        kind: KeyEventKind::Press,
        state: KeyEventState::NONE,
    };
    rep.handle_key(key);
    assert_eq!(rep.path, "/api/v1/authx");

    // Convert to ReplayRequest
    let req = rep.build_replay_request();
    assert_eq!(req.method, "POST");
    assert_eq!(req.host, "target.internal");
    assert_eq!(req.port, 8443);
    assert_eq!(req.path, "/api/v1/authx");
    assert_eq!(req.body, b"{\"user\":\"admin\"}".to_vec());
    assert_eq!(
        req.headers.get("content-type").map(|s| s.as_str()),
        Some("application/json")
    );
}

#[test]
fn test_repeater_ctrl_r_dispatch_trigger() {
    let raw_req = b"GET /health HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n";
    let ev = TlsEvent::new(
        3000,
        9999,
        9999,
        5,
        Direction::Egress,
        "app".into(),
        raw_req.to_vec(),
        None,
    );

    let mut rep = RepeaterState::from_event(&ev);

    let ctrl_r = KeyEvent {
        code: KeyCode::Char('r'),
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
        state: KeyEventState::NONE,
    };

    let dispatched = rep.handle_key(ctrl_r);
    assert!(dispatched.is_some(), "Ctrl+R must trigger request dispatch");
    let req = dispatched.unwrap();
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/health");
    assert!(rep.is_transmitting);
}

#[test]
fn test_dashboard_idor_detection_and_drop_counter() {
    let mut state = DashboardState::new();

    // Set dropped counter
    state
        .dropped_events
        .store(42, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        state
            .dropped_events
            .load(std::sync::atomic::Ordering::Relaxed),
        42
    );

    // 1. User Alice requests order 101
    let req1 = TlsEvent::new(
        1000, 111, 111, 4, Direction::Egress, "curl".into(),
        b"GET /api/orders/101 HTTP/1.1\r\nHost: api.com\r\nAuthorization: Bearer token_alice\r\n\r\n".to_vec(),
        None,
    );
    state.push_event(req1);

    let resp1 = TlsEvent::new(
        1050,
        111,
        111,
        4,
        Direction::Ingress,
        "curl".into(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
        None,
    );
    state.push_event(resp1);
    assert_eq!(state.idor_detector.alerts.len(), 0);

    // 2. User Bob requests order 101 -> 200 OK (IDOR bypass!)
    let req2 = TlsEvent::new(
        2000,
        222,
        222,
        5,
        Direction::Egress,
        "curl".into(),
        b"GET /api/orders/101 HTTP/1.1\r\nHost: api.com\r\nAuthorization: Bearer token_bob\r\n\r\n"
            .to_vec(),
        None,
    );
    state.push_event(req2);

    let resp2 = TlsEvent::new(
        2050,
        222,
        222,
        5,
        Direction::Ingress,
        "curl".into(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
        None,
    );
    state.push_event(resp2);

    assert_eq!(state.idor_detector.alerts.len(), 1);
    assert_eq!(state.idor_detector.alerts[0].target_resource_id, "101");
    // Packet index 3 (the response) should be tagged with IDOR alert
    assert!(state.idor_event_indices.contains(&3));
}

#[test]
fn test_dashboard_throughput_sparkline_accumulation() {
    let mut state = DashboardState::new();

    // Push events with data
    for i in 0..10 {
        let ev = TlsEvent::new(
            1000 + i as u64,
            123,
            123,
            3,
            Direction::Egress,
            "bench".into(),
            vec![0x41; 2048], // 2 KB each
            None,
        );
        state.push_event(ev);
    }

    assert_eq!(state.total_bytes, 20480);
    assert!(state.bytes_in_current_interval > 0 || !state.throughput_history.is_empty());

    // Force time elapse to verify sparkline bucket push
    state.last_sparkline_sample = std::time::Instant::now() - std::time::Duration::from_millis(600);
    state.update_throughput_sparkline();

    assert!(
        !state.throughput_history.is_empty(),
        "Sparkline history should contain samples"
    );
    assert_eq!(
        state.bytes_in_current_interval, 0,
        "Current interval counter should reset"
    );
}
