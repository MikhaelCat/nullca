//! Modal Overlays and Dialogs for the Terminal Cockpit.
//!
//! Includes keyboard help cheatsheet, quick export dialog, and filter DSL auto-hints.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

/// Helper to generate a centered rectangular area inside a parent container
pub fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

/// Draw the Full Help & Keyboard Reference overlay
#[allow(clippy::vec_init_then_push)]
pub fn draw_help_modal(f: &mut Frame, root_area: Rect) {
    let area = centered_rect(75, 80, root_area);
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(
            " ⚡ NullCA Terminal Cockpit ─ Keyboard & Command Reference ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .border_style(Style::default().fg(Color::Cyan));
    f.render_widget(block, area);

    let inner = Rect {
        x: area.x + 2,
        y: area.y + 1,
        width: area.width.saturating_sub(4),
        height: area.height.saturating_sub(2),
    };

    let mut lines = Vec::new();

    lines.push(Line::from(Span::styled(
        "Navigation & Pane Control:",
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(
        "  [j / Down]      Next packet in table / scroll down",
    ));
    lines.push(Line::from(
        "  [k / Up]        Previous packet in table / scroll up",
    ));
    lines.push(Line::from(
        "  [PgDn / PgUp]   Fast scroll in Decoded Details, Hexdump & Repeater",
    ));
    lines.push(Line::from(
        "  [g / Home]      Jump to first packet or top of buffer",
    ));
    lines.push(Line::from(
        "  [G / End]       Jump to last packet or bottom of buffer",
    ));
    lines.push(Line::from(
        "  [Tab]           Switch active pane focus (Table ⇄ Details ⇄ Hexdump)",
    ));
    lines.push(Line::from(
        "  [f / m]         Toggle Fullscreen mode for active pane",
    ));
    lines.push(Line::raw(""));

    lines.push(Line::from(Span::styled(
        "Inspection & Protocols:",
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(
        "  [1] Info        Headers, status codes, query strings & formatted bodies",
    ));
    lines.push(Line::from(
        "  [2] Protobuf    Schema-less Protocol Buffers tree & gRPC messages",
    ));
    lines.push(Line::from(
        "  [3] Secrets     JWT token claims, AWS keys, CTF flags detected",
    ));
    lines.push(Line::from(
        "  [4] cURL        Copy-ready executable cURL command",
    ));
    lines.push(Line::from(
        "  [5] WebSocket   RFC 6455 frame inspector & unmasked payloads",
    ));
    lines.push(Line::from(
        "  [6] X.509 PKI   ASN.1 certificates, SANs, validity, CRL & CSR",
    ));
    lines.push(Line::from(
        "  [7] Diff        Myers / LCS side-by-side diff against marked baseline",
    ));
    lines.push(Line::raw(""));

    lines.push(Line::from(Span::styled(
        "Offensive & Security Tools:",
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(
        "  [R]             Open Interactive Request Repeater & Tamper Cockpit",
    ));
    lines.push(Line::from(
        "  [r]             Fast live request retransmission to remote target",
    ));
    lines.push(Line::from(
        "  [d]             Mark baseline packet 📌 / toggle Side-by-Side Diff",
    ));
    lines.push(Line::from(
        "  [c]             Quick copy cURL command to status buffer",
    ));
    lines.push(Line::from(
        "  [s]             Save & Export menu (Raw body, cURL script, PCAP-NG, HAR)",
    ));
    lines.push(Line::from(
        "  [x]             Clear in-memory capture buffers",
    ));
    lines.push(Line::from(
        "  [Space / p]     Pause / Resume live packet capture",
    ));
    lines.push(Line::raw(""));

    lines.push(Line::from(Span::styled(
        "Filter DSL Query Syntax (/):",
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(
        "  proto == \"http2\"        Filter by protocol (http1, http2, ws, grpc, x509, redis, sql)",
    ));
    lines.push(Line::from(
        "  method == \"POST\"       Filter by HTTP method",
    ));
    lines.push(Line::from(
        "  status >= 400          Filter by HTTP status code",
    ));
    lines.push(Line::from(
        "  contains \"flag{\"       Match substring anywhere in payload",
    ));
    lines.push(Line::from(
        "  has_secret == true     Show only packets containing tokens/flags",
    ));
    lines.push(Line::from(
        "  len > 1024             Filter by payload byte size",
    ));
    lines.push(Line::raw(""));

    lines.push(Line::from(Span::styled(
        "Security Badges Legend:",
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(vec![
        Span::styled(
            "  [FLAG]  ",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        Span::raw("CTF Flag matched (e.g. flag{...}, CTF{...}, base64 token)"),
    ]));
    lines.push(Line::from(vec![
        Span::styled(
            "  [JWT]   ",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("JSON Web Token detected with decodeable header/payload claims"),
    ]));
    lines.push(Line::from(vec![
        Span::styled(
            "  [AWS]   ",
            Style::default()
                .fg(Color::LightRed)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("AWS Access Key (AKIA...) detected"),
    ]));
    lines.push(Line::from(vec![
        Span::styled(
            "  [BASIC] ",
            Style::default()
                .fg(Color::LightYellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("Basic Authorization header with plaintext user/password credentials"),
    ]));
    lines.push(Line::raw(""));

    lines.push(Line::from(Span::styled(
        "Press [Esc] or [?] to close this help window",
        Style::default().fg(Color::DarkGray),
    )));

    let p = Paragraph::new(lines).wrap(Wrap { trim: false });
    f.render_widget(p, inner);
}

/// Draw the Save & Export Dialog overlay
pub fn draw_export_modal(f: &mut Frame, root_area: Rect, choice: usize) {
    let area = centered_rect(55, 52, root_area);
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(
            " ⚡ Save & Export Menu ",
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ))
        .border_style(Style::default().fg(Color::LightCyan));
    f.render_widget(block, area);

    let inner = Rect {
        x: area.x + 2,
        y: area.y + 1,
        width: area.width.saturating_sub(4),
        height: area.height.saturating_sub(2),
    };

    let options = [
        (
            "[1] Save Selected Raw Payload to File (.bin)",
            "Dumps unformatted packet bytes to nullca_payload_#N.bin",
        ),
        (
            "[2] Save Selected Request as cURL Script (.sh)",
            "Generates ready-to-run curl shell script nullca_request_#N.sh",
        ),
        (
            "[3] Export Full Session to Wireshark PCAP-NG (.pcapng)",
            "Generates synthetic TCP Ethernet stream for Wireshark",
        ),
        (
            "[4] Export Full Session to HTTP Archive (HAR 1.2)",
            "Generates browser-compatible HAR JSON nullca_capture.har",
        ),
        (
            "[5] Export Inferred OpenAPI 3.0 Spec (.json)",
            "Generates REST endpoint schema catalog nullca_openapi.json",
        ),
    ];

    let mut lines = Vec::new();
    lines.push(Line::from(Span::styled(
        "Select an export format to save to disk:",
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::raw(""));

    for (i, (opt, desc)) in options.iter().enumerate() {
        let is_selected = i == choice;
        let prefix = if is_selected { " ▶ " } else { "   " };
        let opt_style = if is_selected {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(vec![
            Span::styled(prefix, Style::default().fg(Color::Green)),
            Span::styled(*opt, opt_style),
        ]));
        lines.push(Line::from(vec![
            Span::raw("     "),
            Span::styled(*desc, Style::default().fg(Color::DarkGray)),
        ]));
        lines.push(Line::raw(""));
    }

    lines.push(Line::from(Span::styled(
        "Press [1-5] or [Enter] to export, [Esc] to cancel",
        Style::default().fg(Color::LightGreen),
    )));

    let p = Paragraph::new(lines).wrap(Wrap { trim: false });
    f.render_widget(p, inner);
}
