//! Interactive Terminal TUI Cockpit ("Wireshark for CLI").
//!
//! Provides a real-time, interactive terminal dashboard for live stream inspection,
//! hex decoding, protocol dissection, JWT & secrets detection, and in-memory filtering.

use crate::engine::event::{Direction, ProtocolType, TlsEvent};
use crate::engine::filter::FilterEngine;
use crate::export::curl::CurlExporter;
use crate::export::har::HarExporter;
use crate::proto::grpc::GrpcMessage;
use crate::proto::http1::{Http1Message, Http1Parser};
use crate::proto::protobuf::ProtobufMessage;
use crate::proto::secrets::scan_secrets;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction as LayoutDirection, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap},
    Terminal,
};
use std::io::{self, Stdout};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivePane {
    PacketTable,
    DecodedDetails,
    Hexdump,
}

pub struct DashboardState {
    pub events: Vec<TlsEvent>,
    pub filtered_indices: Vec<usize>,
    pub table_state: TableState,
    pub active_pane: ActivePane,
    pub paused: bool,
    pub filter_input: String,
    pub is_filtering: bool,
    pub filter_engine: Option<FilterEngine>,
    pub total_bytes: usize,
    pub start_time: Instant,
    pub selected_tab: usize, // 0: Details, 1: Protobuf, 2: JWT & Secrets, 3: cURL Command
    pub status_message: Option<(String, Instant)>,
}

impl Default for DashboardState {
    fn default() -> Self {
        Self::new()
    }
}

impl DashboardState {
    pub fn new() -> Self {
        let mut table_state = TableState::default();
        table_state.select(Some(0));
        Self {
            events: Vec::new(),
            filtered_indices: Vec::new(),
            table_state,
            active_pane: ActivePane::PacketTable,
            paused: false,
            filter_input: String::new(),
            is_filtering: false,
            filter_engine: None,
            total_bytes: 0,
            start_time: Instant::now(),
            selected_tab: 0,
            status_message: None,
        }
    }

    pub fn set_status(&mut self, msg: String) {
        self.status_message = Some((msg, Instant::now()));
    }

    pub fn push_event(&mut self, event: TlsEvent) {
        self.total_bytes += event.data.len();
        let idx = self.events.len();
        let satisfies_filter = match &self.filter_engine {
            Some(engine) => engine.matches(&event),
            None => true,
        };
        self.events.push(event);
        if satisfies_filter {
            self.filtered_indices.push(idx);
            // If at the end and not paused, auto-scroll down
            if !self.paused && self.filtered_indices.len() > 1 {
                self.table_state.select(Some(self.filtered_indices.len() - 1));
            }
        }
    }

    pub fn apply_filter(&mut self) {
        if self.filter_input.trim().is_empty() {
            self.filter_engine = None;
            self.filtered_indices = (0..self.events.len()).collect();
        } else if let Ok(engine) = FilterEngine::compile(&self.filter_input) {
            self.filter_engine = Some(engine.clone());
            self.filtered_indices = self
                .events
                .iter()
                .enumerate()
                .filter(|(_, ev)| engine.matches(ev))
                .map(|(idx, _)| idx)
                .collect();
        }
        if self.filtered_indices.is_empty() {
            self.table_state.select(None);
        } else {
            self.table_state.select(Some(0));
        }
    }

    pub fn selected_event(&self) -> Option<&TlsEvent> {
        let sel = self.table_state.selected()?;
        let actual_idx = *self.filtered_indices.get(sel)?;
        self.events.get(actual_idx)
    }

    pub fn next_packet(&mut self) {
        if self.filtered_indices.is_empty() {
            return;
        }
        let current = self.table_state.selected().unwrap_or(0);
        let next = if current + 1 < self.filtered_indices.len() {
            current + 1
        } else {
            self.filtered_indices.len() - 1
        };
        self.table_state.select(Some(next));
    }

    pub fn prev_packet(&mut self) {
        if self.filtered_indices.is_empty() {
            return;
        }
        let current = self.table_state.selected().unwrap_or(0);
        let prev = current.saturating_sub(1);
        self.table_state.select(Some(prev));
    }
}

/// Runs the interactive terminal dashboard until the user presses 'q' or Ctrl-C.
pub async fn run_dashboard(
    mut event_rx: mpsc::Receiver<TlsEvent>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = DashboardState::new();
    let tick_rate = Duration::from_millis(50);

    let res = dashboard_loop(&mut terminal, &mut state, &mut event_rx, tick_rate).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        eprintln!("Dashboard error: {:?}", err);
    }

    Ok(())
}

async fn dashboard_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    state: &mut DashboardState,
    event_rx: &mut mpsc::Receiver<TlsEvent>,
    tick_rate: Duration,
) -> io::Result<()> {
    loop {
        // Read incoming events from BPF channel
        while let Ok(event) = event_rx.try_recv() {
            state.push_event(event);
        }

        // Render frame
        terminal.draw(|f| draw_ui(f, state))?;

        // Handle user input
        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                if state.is_filtering {
                    match key.code {
                        KeyCode::Enter => {
                            state.is_filtering = false;
                            state.apply_filter();
                        }
                        KeyCode::Esc => {
                            state.is_filtering = false;
                        }
                        KeyCode::Backspace => {
                            state.filter_input.pop();
                        }
                        KeyCode::Char(c) => {
                            state.filter_input.push(c);
                        }
                        _ => {}
                    }
                    continue;
                }

                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('p') | KeyCode::Char(' ') => {
                        state.paused = !state.paused;
                    }
                    KeyCode::Char('/') => {
                        state.is_filtering = true;
                    }
                    KeyCode::Char('c') => {
                        if let Some(ev) = state.selected_event() {
                            if let Some(curl_cmd) = CurlExporter::from_payload(&ev.data) {
                                state.set_status(format!("cURL: {}", curl_cmd.lines().next().unwrap_or("")));
                            } else {
                                state.set_status("Selected packet is not an HTTP request".into());
                            }
                        }
                    }
                    KeyCode::Char('e') => {
                        let path = "nullca_capture.har";
                        if HarExporter::write_to_file(&state.events, path).is_ok() {
                            state.set_status(format!("Exported {} packets to '{}'", state.events.len(), path));
                        } else {
                            state.set_status("Failed to export HAR file".into());
                        }
                    }
                    KeyCode::Char('x') => {
                        state.events.clear();
                        state.filtered_indices.clear();
                        state.total_bytes = 0;
                        state.table_state.select(None);
                        state.set_status("Buffer cleared".into());
                    }
                    KeyCode::Tab => {
                        state.active_pane = match state.active_pane {
                            ActivePane::PacketTable => ActivePane::DecodedDetails,
                            ActivePane::DecodedDetails => ActivePane::Hexdump,
                            ActivePane::Hexdump => ActivePane::PacketTable,
                        };
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        state.next_packet();
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        state.prev_packet();
                    }
                    KeyCode::Char('1') => state.selected_tab = 0,
                    KeyCode::Char('2') => state.selected_tab = 1,
                    KeyCode::Char('3') => state.selected_tab = 2,
                    KeyCode::Char('4') => state.selected_tab = 3,
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

fn draw_ui(f: &mut ratatui::Frame, state: &mut DashboardState) {
    let size = f.area();

    let chunks = Layout::default()
        .direction(LayoutDirection::Vertical)
        .constraints([
            Constraint::Length(3), // Header & stats
            Constraint::Length(3), // Filter bar
            Constraint::Percentage(50), // Packet Table
            Constraint::Percentage(40), // Details & Hex view
            Constraint::Length(1), // Footer hotkeys
        ])
        .split(size);

    draw_header(f, state, chunks[0]);
    draw_filter_bar(f, state, chunks[1]);
    draw_packet_table(f, state, chunks[2]);
    draw_details_and_hex(f, state, chunks[3]);
    draw_footer(f, state, chunks[4]);
}

fn draw_header(f: &mut ratatui::Frame, state: &DashboardState, area: Rect) {
    let elapsed = state.start_time.elapsed().as_secs();
    let speed_kb = if elapsed > 0 {
        (state.total_bytes / 1024) / elapsed as usize
    } else {
        0
    };

    let status_pill = if state.paused {
        Span::styled(" [PAUSED] ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
    } else {
        Span::styled(" [LIVE CAPTURE] ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
    };

    let mut title_spans = vec![
        Span::styled("⚡ nullca ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled("v0.1.0 • eBPF TLS/HTTP2/gRPC Sniffer", Style::default().fg(Color::DarkGray)),
        Span::raw(" | "),
        status_pill,
        Span::raw(" | Pkts: "),
        Span::styled(format!("{}", state.events.len()), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::raw(" (Filtered: "),
        Span::styled(format!("{}", state.filtered_indices.len()), Style::default().fg(Color::LightBlue)),
        Span::raw(") | Traffic: "),
        Span::styled(format!("{:.2} MB", state.total_bytes as f64 / (1024.0 * 1024.0)), Style::default().fg(Color::Magenta)),
        Span::styled(format!(" ({} KB/s)", speed_kb), Style::default().fg(Color::DarkGray)),
    ];

    if let Some((ref msg, ref ts)) = state.status_message {
        if ts.elapsed().as_secs() < 4 {
            title_spans.push(Span::raw(" | "));
            title_spans.push(Span::styled(format!("🔔 {}", msg), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
        }
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));
    let p = Paragraph::new(Line::from(title_spans)).block(block);
    f.render_widget(p, area);
}

fn draw_filter_bar(f: &mut ratatui::Frame, state: &DashboardState, area: Rect) {
    let prompt = if state.is_filtering {
        Span::styled("Filter > ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
    } else {
        Span::styled("Filter [/] : ", Style::default().fg(Color::DarkGray))
    };

    let text = if state.filter_input.is_empty() {
        if state.is_filtering {
            Span::raw("")
        } else {
            Span::styled("e.g. proto == 'http2' && status >= 400 || body contains 'token' (Press / to edit)", Style::default().fg(Color::DarkGray))
        }
    } else {
        Span::styled(&state.filter_input, Style::default().fg(Color::White))
    };

    let border_color = if state.is_filtering {
        Color::Yellow
    } else if state.filter_engine.is_some() {
        Color::Green
    } else {
        Color::DarkGray
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Filter DSL ")
        .border_style(Style::default().fg(border_color));
    let p = Paragraph::new(Line::from(vec![prompt, text])).block(block);
    f.render_widget(p, area);
}

fn draw_packet_table(f: &mut ratatui::Frame, state: &mut DashboardState, area: Rect) {
    let border_color = if state.active_pane == ActivePane::PacketTable {
        Color::Cyan
    } else {
        Color::DarkGray
    };

    let header_cells = ["#", "Time", "PID", "Process", "Dir", "Protocol", "Secrets", "Size", "Preview"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1).bottom_margin(1);

    let rows = state.filtered_indices.iter().enumerate().map(|(display_idx, &actual_idx)| {
        let ev = &state.events[actual_idx];
        let dir_str = match ev.direction {
            Direction::Ingress => "IN",
            Direction::Egress => "OUT",
        };
        let dir_style = match ev.direction {
            Direction::Ingress => Style::default().fg(Color::Green),
            Direction::Egress => Style::default().fg(Color::Blue),
        };

        let proto_str = match ev.protocol() {
            ProtocolType::Http1 => "HTTP/1.1",
            ProtocolType::Http2 => "HTTP/2",
            ProtocolType::Grpc => "gRPC",
            ProtocolType::RawTls => "TLS/RAW",
        };

        let proto_style = match ev.protocol() {
            ProtocolType::Http1 => Style::default().fg(Color::LightCyan),
            ProtocolType::Http2 => Style::default().fg(Color::Magenta),
            ProtocolType::Grpc => Style::default().fg(Color::LightGreen),
            ProtocolType::RawTls => Style::default().fg(Color::DarkGray),
        };

        // Scan secrets
        let detected = scan_secrets(&ev.data);
        let secret_badge = if !detected.is_empty() {
            let label = match detected[0].kind {
                crate::proto::secrets::SecretKind::JwtToken => "[JWT]",
                crate::proto::secrets::SecretKind::CtfFlag => "[FLAG]",
                crate::proto::secrets::SecretKind::BasicAuthCredentials => "[BASIC]",
                crate::proto::secrets::SecretKind::AwsAccessKey => "[AWS]",
                crate::proto::secrets::SecretKind::GitHubToken => "[GH-PAT]",
                _ => "[SECRET]",
            };
            Cell::from(label).style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
        } else {
            Cell::from("-").style(Style::default().fg(Color::DarkGray))
        };

        // Construct short preview
        let preview = String::from_utf8_lossy(&ev.data)
            .lines()
            .next()
            .unwrap_or("")
            .chars()
            .take(50)
            .collect::<String>();

        let time_str = format!("{:.3}s", (ev.timestamp_ns / 1_000_000) as f64 / 1000.0);

        let cells = vec![
            Cell::from(format!("{}", display_idx + 1)),
            Cell::from(time_str),
            Cell::from(format!("{}", ev.pid)),
            Cell::from(ev.comm.clone()),
            Cell::from(dir_str).style(dir_style),
            Cell::from(proto_str).style(proto_style),
            secret_badge,
            Cell::from(format!("{} B", ev.data.len())),
            Cell::from(preview),
        ];

        Row::new(cells).height(1)
    });

    let table = Table::new(
        rows,
        [
            Constraint::Length(5),
            Constraint::Length(9),
            Constraint::Length(8),
            Constraint::Length(14),
            Constraint::Length(5),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Min(20),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Live Streams ")
            .border_style(Style::default().fg(border_color)),
    )
    .row_highlight_style(
        Style::default()
            .bg(Color::Rgb(40, 44, 52))
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("▶ ");

    f.render_stateful_widget(table, area, &mut state.table_state);
}

fn draw_details_and_hex(f: &mut ratatui::Frame, state: &DashboardState, area: Rect) {
    let sub_chunks = Layout::default()
        .direction(LayoutDirection::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    let maybe_event = state.selected_event();

    // Left pane: Multi-tab details inspector
    let left_border = if state.active_pane == ActivePane::DecodedDetails {
        Color::Cyan
    } else {
        Color::DarkGray
    };

    let tab_titles = [" [1] Headers & Info ", " [2] Protobuf Tree ", " [3] JWT & Secrets ", " [4] cURL "]
        .iter()
        .enumerate()
        .map(|(i, &title)| {
            if i == state.selected_tab {
                Span::styled(title, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
            } else {
                Span::styled(title, Style::default().fg(Color::DarkGray))
            }
        })
        .collect::<Vec<_>>();

    let details_block = Block::default()
        .borders(Borders::ALL)
        .title(Line::from(tab_titles))
        .border_style(Style::default().fg(left_border));

    if let Some(ev) = maybe_event {
        let mut lines = Vec::new();

        lines.push(Line::from(vec![
            Span::styled("Process: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{} (PID: {})", ev.comm, ev.pid), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            Span::styled("  Socket FD: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{}", ev.fd), Style::default().fg(Color::LightBlue)),
        ]));

        lines.push(Line::from(vec![
            Span::styled("Protocol: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{:?}", ev.protocol()), Style::default().fg(Color::Magenta)),
            Span::styled("  Payload Size: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{} bytes", ev.data.len()), Style::default().fg(Color::Yellow)),
        ]));

        lines.push(Line::raw(""));

        match state.selected_tab {
            0 => {
                // Headers & Info
                match ev.protocol() {
                    ProtocolType::Http1 => {
                        if let Some(msg) = Http1Parser::parse(&ev.data) {
                            lines.push(Line::from(Span::styled("--- HTTP/1.1 Header Dissection ---", Style::default().fg(Color::Cyan))));
                            let (headers, body) = match msg {
                                Http1Message::Request { headers, body, .. } => (headers, body),
                                Http1Message::Response { headers, body, .. } => (headers, body),
                            };
                            for (k, v) in headers {
                                lines.push(Line::from(vec![
                                    Span::styled(format!("  {}: ", k), Style::default().fg(Color::LightCyan)),
                                    Span::raw(v),
                                ]));
                            }
                            if !body.is_empty() {
                                lines.push(Line::raw(""));
                                lines.push(Line::from(Span::styled(format!("--- Body ({} bytes) ---", body.len()), Style::default().fg(Color::Cyan))));
                                lines.push(Line::from(String::from_utf8_lossy(&body).to_string()));
                            }
                        }
                    }
                    ProtocolType::Grpc => {
                        if let Ok((grpc_msg, _)) = GrpcMessage::parse(&ev.data) {
                            lines.push(Line::from(Span::styled("--- gRPC Frame Dissection ---", Style::default().fg(Color::LightGreen))));
                            lines.push(Line::from(format!("  Compressed: {}", grpc_msg.is_compressed)));
                            lines.push(Line::from(format!("  Message Length: {} bytes", grpc_msg.length)));
                        }
                    }
                    _ => {
                        lines.push(Line::from(Span::styled("--- Raw Stream Payload ---", Style::default().fg(Color::DarkGray))));
                        let text = String::from_utf8_lossy(&ev.data);
                        for l in text.lines().take(15) {
                            lines.push(Line::raw(format!("  {}", l)));
                        }
                    }
                }
            }
            1 => {
                // Protobuf Tree
                if let Ok((grpc_msg, _)) = GrpcMessage::parse(&ev.data) {
                    if let Ok(pb) = ProtobufMessage::decode(&grpc_msg.payload) {
                        lines.push(Line::from(Span::styled("--- Protobuf Schema-less Tree ---", Style::default().fg(Color::Yellow))));
                        for line in pb.to_json().lines() {
                            lines.push(Line::raw(format!("  {}", line)));
                        }
                    }
                } else if let Ok(pb) = ProtobufMessage::decode(&ev.data) {
                    lines.push(Line::from(Span::styled("--- Protobuf Schema-less Tree ---", Style::default().fg(Color::Yellow))));
                    for line in pb.to_json().lines() {
                        lines.push(Line::raw(format!("  {}", line)));
                    }
                } else {
                    lines.push(Line::raw("No Protocol Buffers payload detected."));
                }
            }
            2 => {
                // JWT & Secrets
                let secrets = scan_secrets(&ev.data);
                if secrets.is_empty() {
                    lines.push(Line::raw("No sensitive tokens or JWTs detected in payload."));
                } else {
                    for (i, sec) in secrets.iter().enumerate() {
                        lines.push(Line::from(vec![
                            Span::styled(format!("[#{}] {:?}: ", i + 1, sec.kind), Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                            Span::raw(sec.raw_token.chars().take(40).collect::<String>()),
                        ]));
                        if let Some(ref details) = sec.decoded_details {
                            for dl in details.lines() {
                                lines.push(Line::from(Span::styled(format!("    {}", dl), Style::default().fg(Color::LightYellow))));
                            }
                        }
                        lines.push(Line::raw(""));
                    }
                }
            }
            3 => {
                // cURL Command Preview
                if let Some(curl_cmd) = CurlExporter::from_payload(&ev.data) {
                    lines.push(Line::from(Span::styled("--- Ready-to-Run cURL Command ---", Style::default().fg(Color::Green))));
                    for l in curl_cmd.lines() {
                        lines.push(Line::raw(l.to_string()));
                    }
                } else {
                    lines.push(Line::raw("Not an outbound HTTP request (cURL export available for requests only)."));
                }
            }
            _ => {}
        }

        let p = Paragraph::new(lines).block(details_block).wrap(Wrap { trim: false });
        f.render_widget(p, sub_chunks[0]);
    } else {
        let p = Paragraph::new("No packet selected").block(details_block);
        f.render_widget(p, sub_chunks[0]);
    }

    // Right pane: Colorized Hexdump
    let right_border = if state.active_pane == ActivePane::Hexdump {
        Color::Cyan
    } else {
        Color::DarkGray
    };

    let hex_block = Block::default()
        .borders(Borders::ALL)
        .title(" Raw Hex & ASCII Dump ")
        .border_style(Style::default().fg(right_border));

    if let Some(ev) = maybe_event {
        let mut hex_lines = Vec::new();
        let chunk_size = 16;

        for (chunk_idx, chunk) in ev.data.chunks(chunk_size).enumerate() {
            let offset = chunk_idx * chunk_size;
            let mut hex_part = String::new();
            let mut ascii_part = String::new();

            for (i, &b) in chunk.iter().enumerate() {
                hex_part.push_str(&format!("{:02x} ", b));
                if i == 7 {
                    hex_part.push(' ');
                }
                if b.is_ascii_graphic() || b == b' ' {
                    ascii_part.push(b as char);
                } else {
                    ascii_part.push('.');
                }
            }

            // Pad hex part if incomplete chunk
            while hex_part.len() < 50 {
                hex_part.push(' ');
            }

            let line = Line::from(vec![
                Span::styled(format!("{:08x}: ", offset), Style::default().fg(Color::DarkGray)),
                Span::styled(hex_part, Style::default().fg(Color::LightBlue)),
                Span::styled(format!("|{}|", ascii_part), Style::default().fg(Color::Yellow)),
            ]);
            hex_lines.push(line);

            if hex_lines.len() >= 30 {
                hex_lines.push(Line::from(Span::styled("... [truncated]", Style::default().fg(Color::DarkGray))));
                break;
            }
        }

        let p = Paragraph::new(hex_lines).block(hex_block);
        f.render_widget(p, sub_chunks[1]);
    } else {
        let p = Paragraph::new("No payload").block(hex_block);
        f.render_widget(p, sub_chunks[1]);
    }
}

fn draw_footer(f: &mut ratatui::Frame, _state: &DashboardState, area: Rect) {
    let hotkeys = Line::from(vec![
        Span::styled("[q]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Quit "),
        Span::styled("[Space]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Pause "),
        Span::styled("[/]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Filter "),
        Span::styled("[c]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Copy cURL "),
        Span::styled("[e]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Save HAR "),
        Span::styled("[1-4]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Tabs "),
        Span::styled("[Tab]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Panes "),
        Span::styled("[j/k]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Move "),
    ]);
    let p = Paragraph::new(hotkeys);
    f.render_widget(p, area);
}
