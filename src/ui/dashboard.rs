//! Interactive Terminal TUI Cockpit ("Wireshark for CLI").
//!
//! Provides a real-time, interactive terminal dashboard for live stream inspection,
//! hex decoding, protocol dissection, JWT & secrets detection, in-memory filtering,
//! WebSocket frame analysis, side-by-side packet diffing, and live request replaying.

use crate::engine::diff::DiffEngine;
use crate::engine::event::{Direction, ProtocolType, TlsEvent};
use crate::engine::filter::FilterEngine;
use crate::engine::replay::{ReplayEngine, ReplayRequest};
use crate::export::curl::CurlExporter;
use crate::export::har::HarExporter;
use crate::proto::grpc::GrpcMessage;
use crate::proto::http1::{Http1Message, Http1Parser};
use crate::proto::protobuf::ProtobufMessage;
use crate::proto::secrets::scan_secrets;
use crate::proto::websocket::WebSocketParser;

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
    pub selected_tab: usize, // 0: Info, 1: Protobuf, 2: JWT & Secrets, 3: cURL, 4: WebSocket, 5: Diff
    pub diff_baseline: Option<usize>,
    pub diff_mode: bool,
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
            diff_baseline: None,
            diff_mode: false,
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
        let input = self.filter_input.trim();
        if input.is_empty() {
            self.filter_engine = None;
            self.rebuild_filtered();
            self.set_status("Filter cleared".into());
            return;
        }

        match FilterEngine::compile(input) {
            Ok(engine) => {
                self.filter_engine = Some(engine);
                self.rebuild_filtered();
                self.set_status(format!("Filter applied: {} matches", self.filtered_indices.len()));
            }
            Err(e) => {
                self.set_status(format!("Filter error: {}", e));
            }
        }
    }

    pub fn rebuild_filtered(&mut self) {
        self.filtered_indices.clear();
        for (idx, event) in self.events.iter().enumerate() {
            let matches = match &self.filter_engine {
                Some(engine) => engine.matches(event),
                None => true,
            };
            if matches {
                self.filtered_indices.push(idx);
            }
        }

        if self.filtered_indices.is_empty() {
            self.table_state.select(None);
        } else {
            self.table_state.select(Some(0));
        }
    }

    pub fn next_packet(&mut self) {
        if self.filtered_indices.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => {
                if i >= self.filtered_indices.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    pub fn prev_packet(&mut self) {
        if self.filtered_indices.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.filtered_indices.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    pub fn selected_event(&self) -> Option<&TlsEvent> {
        let selected_table_idx = self.table_state.selected()?;
        let actual_event_idx = *self.filtered_indices.get(selected_table_idx)?;
        self.events.get(actual_event_idx)
    }

    pub fn selected_event_idx(&self) -> Option<usize> {
        let selected_table_idx = self.table_state.selected()?;
        self.filtered_indices.get(selected_table_idx).copied()
    }
}

pub async fn run_dashboard(
    mut event_rx: mpsc::Receiver<TlsEvent>,
    ipc_server: Option<crate::engine::ipc::IpcServer>,
) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = DashboardState::new();
    let tick_rate = Duration::from_millis(50);

    let res = dashboard_loop(&mut terminal, &mut state, &mut event_rx, tick_rate, ipc_server).await;

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
    ipc_server: Option<crate::engine::ipc::IpcServer>,
) -> io::Result<()> {
    let (status_tx, mut status_rx) = mpsc::channel::<String>(32);

    loop {
        // Read incoming events from BPF channel
        while let Ok(event) = event_rx.try_recv() {
            if let Some(ref srv) = ipc_server {
                srv.broadcast(&event);
            }
            state.push_event(event);
        }

        // Drain background task status notifications
        while let Ok(msg) = status_rx.try_recv() {
            state.set_status(msg);
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
                    KeyCode::Char('d') => {
                        if let Some(curr_idx) = state.selected_event_idx() {
                            if let Some(base_idx) = state.diff_baseline {
                                if base_idx == curr_idx {
                                    state.diff_baseline = None;
                                    state.diff_mode = false;
                                    state.set_status("Diff baseline cleared.".into());
                                } else {
                                    state.diff_mode = true;
                                    state.selected_tab = 5; // Switch to Diff tab
                                    state.set_status(format!("🔍 Comparing Baseline #{} vs #{}", base_idx + 1, curr_idx + 1));
                                }
                            } else {
                                state.diff_baseline = Some(curr_idx);
                                state.set_status(format!("📌 Baseline marked: #{}. Select another packet and press 'd' to diff!", curr_idx + 1));
                            }
                        }
                    }
                    KeyCode::Char('r') => {
                        if let Some(ev) = state.selected_event() {
                            if let Some(msg) = Http1Parser::parse(&ev.data) {
                                if let Http1Message::Request { method, uri, headers, body, .. } = msg {
                                    let host = headers.get("host").cloned().unwrap_or_else(|| "127.0.0.1".into());
                                    let port = if host.contains(":443") { 443 } else { 80 };
                                    let req = ReplayRequest {
                                        host: host.split(':').next().unwrap_or("127.0.0.1").to_string(),
                                        port,
                                        use_tls: port == 443,
                                        method,
                                        path: uri,
                                        headers,
                                        body,
                                    };
                                    let s_tx = status_tx.clone();
                                    tokio::spawn(async move {
                                        let _ = s_tx.send(format!("[REPLAY] Transmitting {} to {}:{}...", req.method, req.host, req.port)).await;
                                        match ReplayEngine::execute(&req).await {
                                            Ok(resp) => {
                                                let _ = s_tx.send(format!("[REPLAY OK] Status: {} (Latency: {:.1}ms, TTFB: {:.1}ms)", resp.status_code, resp.metrics.total_duration_ms, resp.metrics.ttfb_ms)).await;
                                            }
                                            Err(e) => {
                                                let _ = s_tx.send(format!("[REPLAY ERROR] {}", e)).await;
                                            }
                                        }
                                    });
                                } else {
                                    state.set_status("Can only replay HTTP Request packets".into());
                                }
                            } else {
                                state.set_status("Selected packet is not HTTP/1.1 Request".into());
                            }
                        }
                    }
                    KeyCode::Esc => {
                        if state.diff_mode {
                            state.diff_mode = false;
                            state.set_status("Exited Diff View".into());
                        } else if state.diff_baseline.is_some() {
                            state.diff_baseline = None;
                            state.set_status("Diff baseline cleared".into());
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
                        state.diff_baseline = None;
                        state.diff_mode = false;
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
                    KeyCode::Char('5') => state.selected_tab = 4,
                    KeyCode::Char('6') => state.selected_tab = 5,
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
        Span::styled(" [LIVE] ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
    };

    let diff_pill = if let Some(base) = state.diff_baseline {
        Span::styled(format!(" [BASE: #{}] ", base + 1), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
    } else {
        Span::raw("")
    };

    let title_line = Line::from(vec![
        Span::styled("⚡ NullCA Cockpit ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("─ eBPF Plaintext TLS, HTTP/2 & WebSocket Inspector "),
        status_pill,
        diff_pill,
    ]);

    let stats_line = Line::from(vec![
        Span::styled("Packets: ", Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{}", state.events.len()), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::raw(" | "),
        Span::styled("Filtered: ", Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{}", state.filtered_indices.len()), Style::default().fg(Color::LightCyan)),
        Span::raw(" | "),
        Span::styled("Throughput: ", Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{} KB/s", speed_kb), Style::default().fg(Color::Yellow)),
        Span::raw(" | "),
        Span::styled("Total: ", Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{:.2} MB", state.total_bytes as f64 / 1_048_576.0), Style::default().fg(Color::LightGreen)),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title_line)
        .border_style(Style::default().fg(Color::Cyan));

    let paragraph = Paragraph::new(stats_line).block(block);
    f.render_widget(paragraph, area);
}

fn draw_filter_bar(f: &mut ratatui::Frame, state: &DashboardState, area: Rect) {
    let border_color = if state.is_filtering {
        Color::Yellow
    } else if state.filter_engine.is_some() {
        Color::Green
    } else {
        Color::DarkGray
    };

    let title = if state.is_filtering {
        " Filter Expression (Type and press Enter, Esc to cancel) "
    } else {
        " Active Filter DSL (Press '/' to edit) "
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(border_color));

    let display_text = if state.is_filtering {
        format!("{}_", state.filter_input)
    } else if let Some(ref _engine) = state.filter_engine {
        state.filter_input.clone()
    } else {
        "No filter active (try: proto == \"websocket\" || status >= 400)".to_string()
    };

    let style = if state.is_filtering {
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
    } else if state.filter_engine.is_some() {
        Style::default().fg(Color::Green)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let p = Paragraph::new(display_text).style(style).block(block);
    f.render_widget(p, area);
}

fn draw_packet_table(f: &mut ratatui::Frame, state: &mut DashboardState, area: Rect) {
    let is_focused = state.active_pane == ActivePane::PacketTable;
    let border_color = if is_focused { Color::Cyan } else { Color::DarkGray };

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Captured Decrypted Packets ")
        .border_style(Style::default().fg(border_color));

    let header_cells = ["#", "DIR", "PROTO", "PROCESS", "PID", "SIZE", "SECURITY", "PAYLOAD PREVIEW"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1).bottom_margin(0);

    let rows: Vec<Row> = state
        .filtered_indices
        .iter()
        .map(|idx| {
            let ev = &state.events[*idx];

            let dir_str = match ev.direction {
                Direction::Ingress => "IN",
                Direction::Egress => "OUT",
            };
            let dir_style = match ev.direction {
                Direction::Ingress => Style::default().fg(Color::Green),
                Direction::Egress => Style::default().fg(Color::Blue),
            };

            let (proto_str, proto_style) = match ev.protocol() {
                ProtocolType::Http1 => ("HTTP/1.1", Style::default().fg(Color::LightCyan)),
                ProtocolType::Http2 => ("HTTP/2", Style::default().fg(Color::Magenta)),
                ProtocolType::Grpc => ("gRPC", Style::default().fg(Color::LightGreen)),
                ProtocolType::WebSocket => ("WS", Style::default().fg(Color::Cyan)),
                ProtocolType::RawTls => ("TLS/RAW", Style::default().fg(Color::DarkGray)),
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
            let preview = if ev.protocol() == ProtocolType::WebSocket {
                if let Some((frame, _)) = WebSocketParser::parse_frame(&ev.data) {
                    format!("[{}] {}", frame.opcode, frame.text_preview.unwrap_or_else(|| format!("{} bytes", frame.payload_len)))
                } else {
                    String::from_utf8_lossy(&ev.data).lines().next().unwrap_or("").to_string()
                }
            } else {
                String::from_utf8_lossy(&ev.data)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .chars()
                    .take(60)
                    .collect::<String>()
            };

            let id_label = if state.diff_baseline == Some(*idx) {
                format!("📌 #{}", idx + 1)
            } else {
                format!("#{}", idx + 1)
            };

            let cells = vec![
                Cell::from(id_label).style(Style::default().fg(Color::DarkGray)),
                Cell::from(dir_str).style(dir_style),
                Cell::from(proto_str).style(proto_style),
                Cell::from(ev.comm.clone()).style(Style::default().fg(Color::White)),
                Cell::from(ev.pid.to_string()).style(Style::default().fg(Color::DarkGray)),
                Cell::from(format!("{} B", ev.data.len())).style(Style::default().fg(Color::White)),
                secret_badge,
                Cell::from(preview).style(Style::default().fg(Color::White)),
            ];

            Row::new(cells).height(1)
        })
        .collect();

    let widths = [
        Constraint::Length(8),
        Constraint::Length(5),
        Constraint::Length(10),
        Constraint::Length(14),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Percentage(50),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(block)
        .row_highlight_style(
            Style::default()
                .bg(Color::Rgb(30, 40, 60))
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

    let left_border = if state.active_pane == ActivePane::DecodedDetails {
        Color::Cyan
    } else {
        Color::DarkGray
    };

    let tab_titles = [
        " [1] Headers & Info ",
        " [2] Protobuf Tree ",
        " [3] JWT & Secrets ",
        " [4] cURL ",
        " [5] WebSocket ",
        " [6] Diff Inspector ",
    ]
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
                    ProtocolType::WebSocket => {
                        let frames = WebSocketParser::parse_all_frames(&ev.data);
                        lines.push(Line::from(Span::styled(format!("--- WebSocket Dissection ({} frames) ---", frames.len()), Style::default().fg(Color::Cyan))));
                        for (i, f) in frames.iter().enumerate() {
                            lines.push(Line::from(format!("  Frame #{}: Opcode:{} FIN:{} Masked:{} Len:{}", i + 1, f.opcode, f.fin, f.masked, f.payload_len)));
                            if let Some(ref text) = f.text_preview {
                                lines.push(Line::from(Span::styled(format!("    Payload: {}", text), Style::default().fg(Color::LightGreen))));
                            }
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
                    lines.push(Line::from(Span::styled(format!("Detected {} sensitive token(s):", secrets.len()), Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))));
                    lines.push(Line::raw(""));
                    for sec in secrets {
                        lines.push(Line::from(vec![
                            Span::styled("Type: ", Style::default().fg(Color::DarkGray)),
                            Span::styled(format!("{:?}", sec.kind), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                            Span::styled(format!(" ({})", sec.location), Style::default().fg(Color::DarkGray)),
                        ]));
                        lines.push(Line::from(vec![
                            Span::styled("Raw: ", Style::default().fg(Color::DarkGray)),
                            Span::styled(sec.raw_token, Style::default().fg(Color::LightCyan)),
                        ]));
                        if let Some(details) = sec.decoded_details {
                            for l in details.lines() {
                                lines.push(Line::from(Span::styled(format!("  {}", l), Style::default().fg(Color::Green))));
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
            4 => {
                // WebSocket Tab
                let frames = WebSocketParser::parse_all_frames(&ev.data);
                if frames.is_empty() {
                    lines.push(Line::raw("No RFC 6455 WebSocket frames detected in this packet."));
                } else {
                    lines.push(Line::from(Span::styled(format!("--- WebSocket Stream Dissection ({} frames) ---", frames.len()), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));
                    for (i, f) in frames.iter().enumerate() {
                        lines.push(Line::from(vec![
                            Span::styled(format!("[Frame #{}] ", i + 1), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                            Span::styled(format!("Opcode: {} ", f.opcode), Style::default().fg(Color::LightCyan)),
                            Span::styled(format!("FIN: {} ", f.fin), Style::default().fg(if f.fin { Color::Green } else { Color::Yellow })),
                            Span::styled(format!("Masked: {} ", f.masked), Style::default().fg(Color::DarkGray)),
                            Span::styled(format!("Len: {} bytes", f.payload_len), Style::default().fg(Color::White)),
                        ]));
                        if let Some(ref key) = f.masking_key {
                            lines.push(Line::from(Span::styled(format!("  Masking Key: {:02x} {:02x} {:02x} {:02x}", key[0], key[1], key[2], key[3]), Style::default().fg(Color::DarkGray))));
                        }
                        if let Some(ref text) = f.text_preview {
                            let tag = if f.is_json { "[JSON]" } else { "[TEXT]" };
                            lines.push(Line::from(vec![
                                Span::styled(format!("  {} Payload: ", tag), Style::default().fg(Color::LightGreen)),
                                Span::raw(text.clone()),
                            ]));
                        } else if !f.payload.is_empty() {
                            lines.push(Line::from(Span::styled(format!("  [BINARY] {} raw bytes", f.payload.len()), Style::default().fg(Color::DarkGray))));
                        }
                        lines.push(Line::raw(""));
                    }
                }
            }
            5 => {
                // Diff Inspector Tab
                let curr_idx = state.selected_event_idx().unwrap_or(0);
                if let Some(base_idx) = state.diff_baseline {
                    if let Some(base_ev) = state.events.get(base_idx) {
                        let diff = DiffEngine::diff_events(base_idx, base_ev, curr_idx, ev);
                        let diff_lines = DiffEngine::to_ratatui_lines(&diff);
                        lines.extend(diff_lines);
                    }
                } else {
                    lines.push(Line::from(Span::styled("--- Side-by-Side Diff Inspector ---", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));
                    lines.push(Line::raw("No diff baseline selected yet."));
                    lines.push(Line::raw(""));
                    lines.push(Line::from(vec![
                        Span::raw("1. Navigate to a packet and press "),
                        Span::styled("[d]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                        Span::raw(" to set baseline 📌."),
                    ]));
                    lines.push(Line::from(vec![
                        Span::raw("2. Navigate to another packet and press "),
                        Span::styled("[d]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                        Span::raw(" to open live side-by-side diff!"),
                    ]));
                    lines.push(Line::from(vec![
                        Span::raw("3. Press "),
                        Span::styled("[Esc]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                        Span::raw(" to clear baseline or return."),
                    ]));
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

fn draw_footer(f: &mut ratatui::Frame, state: &DashboardState, area: Rect) {
    if let Some((ref msg, time)) = state.status_message {
        if time.elapsed() < Duration::from_secs(4) {
            let p = Paragraph::new(Line::from(vec![
                Span::styled("🔔 ", Style::default().fg(Color::Yellow)),
                Span::styled(msg, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            ]));
            f.render_widget(p, area);
            return;
        }
    }

    let hotkeys = Line::from(vec![
        Span::styled("[q]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Quit "),
        Span::styled("[Space]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Pause "),
        Span::styled("[/]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Filter "),
        Span::styled("[c]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" cURL "),
        Span::styled("[r]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Replay "),
        Span::styled("[d]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Diff "),
        Span::styled("[e]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" HAR "),
        Span::styled("[1-6]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Tabs "),
        Span::styled("[Tab]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Panes "),
        Span::styled("[j/k]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Move "),
    ]);
    let p = Paragraph::new(hotkeys);
    f.render_widget(p, area);
}
