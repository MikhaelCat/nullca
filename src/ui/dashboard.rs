//! Interactive Terminal TUI Cockpit ("Wireshark for CLI").
//!
//! Provides a real-time, interactive terminal dashboard for live stream inspection,
//! hex decoding, protocol dissection, JWT & secrets detection, in-memory filtering,
//! WebSocket frame analysis, side-by-side packet diffing, live request replaying,
//! full-screen inspection, and interactive request tampering.

use crate::engine::diff::DiffEngine;
use crate::engine::event::{Direction, ProtocolType, TlsEvent};
use crate::engine::filter::FilterEngine;
use crate::engine::replay::{ReplayEngine, ReplayRequest, ReplayResponse};
use crate::export::curl::CurlExporter;
use crate::export::har::HarExporter;
use crate::export::pcapng::PcapNgWriter;
use crate::proto::grpc::GrpcMessage;
use crate::proto::http1::{Http1Message, Http1Parser};
use crate::proto::protobuf::ProtobufMessage;
use crate::proto::secrets::scan_secrets;
use crate::proto::websocket::WebSocketParser;
use crate::proto::x509::X509Parser;
use crate::ui::modals::{draw_export_modal, draw_help_modal};
use crate::ui::repeater::RepeaterState;

use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind,
        MouseButton, MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction as LayoutDirection, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState,
        Table, TableState, Wrap,
    },
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

    // Filter DSL & History
    pub filter_input: String,
    pub is_filtering: bool,
    pub filter_engine: Option<FilterEngine>,
    pub filter_history: Vec<String>,
    pub filter_history_idx: Option<usize>,

    // Metrics
    pub total_bytes: usize,
    pub start_time: Instant,

    // Tab Navigation: 0..6
    pub selected_tab: usize,

    // Diff Engine
    pub diff_baseline: Option<usize>,
    pub diff_mode: bool,

    // Status Message Overlay
    pub status_message: Option<(String, Instant)>,

    // Scrolling Offsets
    pub details_scroll: usize,
    pub details_max_scroll: usize,
    pub hex_scroll: usize,
    pub hex_max_scroll: usize,

    // Full-screen Maximized Pane View
    pub maximized_pane: Option<ActivePane>,

    // Interactive Modals
    pub repeater: Option<RepeaterState>,
    pub show_export: bool,
    pub export_choice: usize,
    pub show_help: bool,
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
            filter_history: Vec::new(),
            filter_history_idx: None,
            total_bytes: 0,
            start_time: Instant::now(),
            selected_tab: 0,
            diff_baseline: None,
            diff_mode: false,
            status_message: None,
            details_scroll: 0,
            details_max_scroll: 0,
            hex_scroll: 0,
            hex_max_scroll: 0,
            maximized_pane: None,
            repeater: None,
            show_export: false,
            export_choice: 0,
            show_help: false,
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
        self.details_scroll = 0;
        self.hex_scroll = 0;
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
        self.details_scroll = 0;
        self.hex_scroll = 0;
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
        self.details_scroll = 0;
        self.hex_scroll = 0;
    }

    pub fn page_down_packets(&mut self, step: usize) {
        if self.filtered_indices.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => (i + step).min(self.filtered_indices.len() - 1),
            None => 0,
        };
        self.table_state.select(Some(i));
        self.details_scroll = 0;
        self.hex_scroll = 0;
    }

    pub fn page_up_packets(&mut self, step: usize) {
        if self.filtered_indices.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => i.saturating_sub(step),
            None => 0,
        };
        self.table_state.select(Some(i));
        self.details_scroll = 0;
        self.hex_scroll = 0;
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
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = DashboardState::new();
    let tick_rate = Duration::from_millis(50);

    let res = dashboard_loop(&mut terminal, &mut state, &mut event_rx, tick_rate, ipc_server).await;

    // Restore terminal cleanly
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
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
    let (replay_res_tx, mut replay_res_rx) = mpsc::channel::<(Result<ReplayResponse, String>, Instant)>(8);

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

        // Drain asynchronous Replay responses
        while let Ok((res, _)) = replay_res_rx.try_recv() {
            if let Some(ref mut rep) = state.repeater {
                rep.is_transmitting = false;
                match res {
                    Ok(resp) => {
                        rep.response_status = Some(resp.status_code);
                        rep.response_headers = resp.headers.into_iter().collect();
                        rep.response_body = String::from_utf8_lossy(&resp.body).to_string();
                        rep.response_metrics = Some((resp.metrics.total_duration_ms, resp.metrics.ttfb_ms));
                        rep.response_scroll = 0;
                        rep.error_msg = None;
                    }
                    Err(e) => {
                        rep.error_msg = Some(e);
                    }
                }
            }
        }

        // Render frame
        terminal.draw(|f| draw_ui(f, state))?;

        // Handle user input events
        if event::poll(tick_rate)? {
            match event::read()? {
                Event::Mouse(mouse) => {
                    handle_mouse_event(state, mouse, terminal.size()?);
                }
                Event::Key(key) => {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }

                    // 1. HELP MODAL ACTIVE
                    if state.show_help {
                        match key.code {
                            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?') | KeyCode::Char('h') | KeyCode::Enter => {
                                state.show_help = false;
                            }
                            _ => {}
                        }
                        continue;
                    }

                    // 2. EXPORT MODAL ACTIVE
                    if state.show_export {
                        match key.code {
                            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('s') => {
                                state.show_export = false;
                            }
                            KeyCode::Char('1') => {
                                state.export_choice = 0;
                                execute_export(state, 0);
                            }
                            KeyCode::Char('2') => {
                                state.export_choice = 1;
                                execute_export(state, 1);
                            }
                            KeyCode::Char('3') => {
                                state.export_choice = 2;
                                execute_export(state, 2);
                            }
                            KeyCode::Char('4') => {
                                state.export_choice = 3;
                                execute_export(state, 3);
                            }
                            KeyCode::Char('5') => {
                                state.export_choice = 4;
                                execute_export(state, 4);
                            }
                            KeyCode::Enter => {
                                execute_export(state, state.export_choice);
                            }
                            KeyCode::Down | KeyCode::Char('j') => {
                                state.export_choice = (state.export_choice + 1) % 5;
                            }
                            KeyCode::Up | KeyCode::Char('k') => {
                                state.export_choice = if state.export_choice == 0 { 4 } else { state.export_choice - 1 };
                            }
                            _ => {}
                        }
                        continue;
                    }

                    // 3. REPEATER MODAL ACTIVE
                    if let Some(ref mut rep) = state.repeater {
                        if key.code == KeyCode::Esc {
                            state.repeater = None;
                            state.set_status("Exited Repeater Cockpit".into());
                            continue;
                        }

                        if let Some(req) = rep.handle_key(key) {
                            let s_tx = status_tx.clone();
                            let r_tx = replay_res_tx.clone();
                            tokio::spawn(async move {
                                let _ = s_tx.send(format!("[REPEATER] Sending {} to {}:{}...", req.method, req.host, req.port)).await;
                                let now = Instant::now();
                                match ReplayEngine::execute(&req).await {
                                    Ok(resp) => {
                                        let _ = s_tx.send(format!("[REPEATER OK] Status: {} (Latency: {:.1}ms, TTFB: {:.1}ms)", resp.status_code, resp.metrics.total_duration_ms, resp.metrics.ttfb_ms)).await;
                                        let _ = r_tx.send((Ok(resp), now)).await;
                                    }
                                    Err(e) => {
                                        let _ = s_tx.send(format!("[REPEATER ERROR] {}", e)).await;
                                        let _ = r_tx.send((Err(e.to_string()), now)).await;
                                    }
                                }
                            });
                        }
                        continue;
                    }

                    // 4. FILTER DSL INPUT MODE
                    if state.is_filtering {
                        match key.code {
                            KeyCode::Enter => {
                                state.is_filtering = false;
                                let trimmed = state.filter_input.trim().to_string();
                                if !trimmed.is_empty() && state.filter_history.last().map(|s| s.as_str()) != Some(&trimmed) {
                                    state.filter_history.push(trimmed);
                                }
                                state.filter_history_idx = None;
                                state.apply_filter();
                            }
                            KeyCode::Esc => {
                                state.is_filtering = false;
                                state.filter_history_idx = None;
                            }
                            KeyCode::Up => {
                                if !state.filter_history.is_empty() {
                                    let next_idx = match state.filter_history_idx {
                                        Some(i) => if i > 0 { i - 1 } else { 0 },
                                        None => state.filter_history.len() - 1,
                                    };
                                    state.filter_history_idx = Some(next_idx);
                                    state.filter_input = state.filter_history[next_idx].clone();
                                }
                            }
                            KeyCode::Down => {
                                if let Some(i) = state.filter_history_idx {
                                    if i + 1 < state.filter_history.len() {
                                        state.filter_history_idx = Some(i + 1);
                                        state.filter_input = state.filter_history[i + 1].clone();
                                    } else {
                                        state.filter_history_idx = None;
                                        state.filter_input.clear();
                                    }
                                }
                            }
                            KeyCode::Tab => {
                                // Auto-suggest popular filter templates
                                if state.filter_input.is_empty() {
                                    state.filter_input = "proto == \"http2\"".into();
                                } else if state.filter_input.starts_with("p") {
                                    state.filter_input = "proto == \"ws\"".into();
                                } else if state.filter_input.starts_with("s") {
                                    state.filter_input = "status >= 400".into();
                                } else if state.filter_input.starts_with("c") {
                                    state.filter_input = "contains \"flag{\"".into();
                                }
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

                    // 5. STANDARD DASHBOARD HOTKEYS
                    match key.code {
                        KeyCode::Char('q') => break,
                        KeyCode::Char('p') | KeyCode::Char(' ') => {
                            state.paused = !state.paused;
                        }
                        KeyCode::Char('/') => {
                            state.is_filtering = true;
                        }
                        KeyCode::Char('?') | KeyCode::Char('h') => {
                            state.show_help = true;
                        }
                        KeyCode::Char('s') => {
                            state.show_export = true;
                        }
                        KeyCode::Char('f') | KeyCode::Char('m') => {
                            // Toggle Fullscreen maximized pane
                            if state.maximized_pane.is_some() {
                                state.maximized_pane = None;
                                state.set_status("Restored 3-pane Cockpit Layout".into());
                            } else {
                                state.maximized_pane = Some(state.active_pane);
                                state.set_status(format!("Maximized {:?} Pane (Press 'f' or Esc to exit)", state.active_pane));
                            }
                        }
                        KeyCode::Char('R') | KeyCode::Char('t') => {
                            // Open Interactive Repeater & Tamper Cockpit
                            if let Some(ev) = state.selected_event() {
                                state.repeater = Some(RepeaterState::from_event(ev));
                                state.set_status("⚡ Launched Request Repeater & Tamper Cockpit".into());
                            } else {
                                state.set_status("Select a packet to launch Repeater".into());
                            }
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
                                        state.selected_tab = 6; // Switch to Diff tab
                                        state.set_status(format!("🔍 Comparing Baseline #{} vs #{}", base_idx + 1, curr_idx + 1));
                                    }
                                } else {
                                    state.diff_baseline = Some(curr_idx);
                                    state.set_status(format!("📌 Baseline marked: #{}. Select another packet and press 'd' to diff!", curr_idx + 1));
                                }
                            }
                        }
                        KeyCode::Char('r') => {
                            // Fast instant replay of selected HTTP request
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
                                            let _ = s_tx.send(format!("[FAST REPLAY] Sending {} to {}:{}...", req.method, req.host, req.port)).await;
                                            match ReplayEngine::execute(&req).await {
                                                Ok(resp) => {
                                                    let _ = s_tx.send(format!("[FAST REPLAY OK] Status: {} (Latency: {:.1}ms, TTFB: {:.1}ms)", resp.status_code, resp.metrics.total_duration_ms, resp.metrics.ttfb_ms)).await;
                                                }
                                                Err(e) => {
                                                    let _ = s_tx.send(format!("[FAST REPLAY ERROR] {}", e)).await;
                                                }
                                            }
                                        });
                                    } else {
                                        state.set_status("Can only replay HTTP Request packets".into());
                                    }
                                } else {
                                    state.set_status("Selected packet is not HTTP/1.1 Request (Press 'R' for full Repeater)".into());
                                }
                            }
                        }
                        KeyCode::Esc => {
                            if state.maximized_pane.is_some() {
                                state.maximized_pane = None;
                                state.set_status("Restored 3-pane Cockpit Layout".into());
                            } else if state.diff_mode {
                                state.diff_mode = false;
                                state.set_status("Exited Diff View".into());
                            } else if state.diff_baseline.is_some() {
                                state.diff_baseline = None;
                                state.set_status("Diff baseline cleared".into());
                            }
                        }
                        KeyCode::Char('x') => {
                            state.events.clear();
                            state.filtered_indices.clear();
                            state.total_bytes = 0;
                            state.diff_baseline = None;
                            state.diff_mode = false;
                            state.details_scroll = 0;
                            state.hex_scroll = 0;
                            state.table_state.select(None);
                            state.set_status("Capture buffers cleared".into());
                        }
                        KeyCode::Tab => {
                            state.active_pane = match state.active_pane {
                                ActivePane::PacketTable => ActivePane::DecodedDetails,
                                ActivePane::DecodedDetails => ActivePane::Hexdump,
                                ActivePane::Hexdump => ActivePane::PacketTable,
                            };
                        }
                        KeyCode::BackTab => {
                            state.active_pane = match state.active_pane {
                                ActivePane::PacketTable => ActivePane::Hexdump,
                                ActivePane::Hexdump => ActivePane::DecodedDetails,
                                ActivePane::DecodedDetails => ActivePane::PacketTable,
                            };
                        }
                        KeyCode::Down | KeyCode::Char('j') => match state.active_pane {
                            ActivePane::PacketTable => state.next_packet(),
                            ActivePane::DecodedDetails => {
                                state.details_scroll = state.details_scroll.saturating_add(1);
                            }
                            ActivePane::Hexdump => {
                                state.hex_scroll = state.hex_scroll.saturating_add(1);
                            }
                        },
                        KeyCode::Up | KeyCode::Char('k') => match state.active_pane {
                            ActivePane::PacketTable => state.prev_packet(),
                            ActivePane::DecodedDetails => {
                                state.details_scroll = state.details_scroll.saturating_sub(1);
                            }
                            ActivePane::Hexdump => {
                                state.hex_scroll = state.hex_scroll.saturating_sub(1);
                            }
                        },
                        KeyCode::PageDown => match state.active_pane {
                            ActivePane::PacketTable => state.page_down_packets(10),
                            ActivePane::DecodedDetails => {
                                state.details_scroll = state.details_scroll.saturating_add(10);
                            }
                            ActivePane::Hexdump => {
                                state.hex_scroll = state.hex_scroll.saturating_add(10);
                            }
                        },
                        KeyCode::PageUp => match state.active_pane {
                            ActivePane::PacketTable => state.page_up_packets(10),
                            ActivePane::DecodedDetails => {
                                state.details_scroll = state.details_scroll.saturating_sub(10);
                            }
                            ActivePane::Hexdump => {
                                state.hex_scroll = state.hex_scroll.saturating_sub(10);
                            }
                        },
                        KeyCode::Home | KeyCode::Char('g') => match state.active_pane {
                            ActivePane::PacketTable => {
                                if !state.filtered_indices.is_empty() {
                                    state.table_state.select(Some(0));
                                    state.details_scroll = 0;
                                    state.hex_scroll = 0;
                                }
                            }
                            ActivePane::DecodedDetails => state.details_scroll = 0,
                            ActivePane::Hexdump => state.hex_scroll = 0,
                        },
                        KeyCode::End | KeyCode::Char('G') => match state.active_pane {
                            ActivePane::PacketTable => {
                                if !state.filtered_indices.is_empty() {
                                    state.table_state.select(Some(state.filtered_indices.len() - 1));
                                    state.details_scroll = 0;
                                    state.hex_scroll = 0;
                                }
                            }
                            ActivePane::DecodedDetails => {
                                state.details_scroll = state.details_max_scroll;
                            }
                            ActivePane::Hexdump => {
                                state.hex_scroll = state.hex_max_scroll;
                            }
                        },
                        KeyCode::Char('1') => state.selected_tab = 0,
                        KeyCode::Char('2') => state.selected_tab = 1,
                        KeyCode::Char('3') => state.selected_tab = 2,
                        KeyCode::Char('4') => state.selected_tab = 3,
                        KeyCode::Char('5') => state.selected_tab = 4,
                        KeyCode::Char('6') => state.selected_tab = 5,
                        KeyCode::Char('7') => state.selected_tab = 6,
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }

    Ok(())
}

fn handle_mouse_event(state: &mut DashboardState, mouse: crossterm::event::MouseEvent, size: ratatui::layout::Size) {
    match mouse.kind {
        MouseEventKind::ScrollDown => match state.active_pane {
            ActivePane::PacketTable => state.next_packet(),
            ActivePane::DecodedDetails => {
                state.details_scroll = state.details_scroll.saturating_add(3);
            }
            ActivePane::Hexdump => {
                state.hex_scroll = state.hex_scroll.saturating_add(3);
            }
        },
        MouseEventKind::ScrollUp => match state.active_pane {
            ActivePane::PacketTable => state.prev_packet(),
            ActivePane::DecodedDetails => {
                state.details_scroll = state.details_scroll.saturating_sub(3);
            }
            ActivePane::Hexdump => {
                state.hex_scroll = state.hex_scroll.saturating_sub(3);
            }
        },
        MouseEventKind::Down(MouseButton::Left) => {
            let y = mouse.row;
            if y < 6 {
                // Click in header / filter bar area
                if y == 3 || y == 4 {
                    state.is_filtering = true;
                }
            } else if y < size.height / 2 {
                state.active_pane = ActivePane::PacketTable;
                // Calculate clicked row
                let row_idx = y.saturating_sub(7) as usize;
                if row_idx < state.filtered_indices.len() {
                    state.table_state.select(Some(row_idx));
                    state.details_scroll = 0;
                    state.hex_scroll = 0;
                }
            } else {
                let x = mouse.column;
                let split_x = (size.width as usize) * 55 / 100;
                if (x as usize) < split_x {
                    state.active_pane = ActivePane::DecodedDetails;
                } else {
                    state.active_pane = ActivePane::Hexdump;
                }
            }
        }
        _ => {}
    }
}

fn execute_export(state: &mut DashboardState, choice: usize) {
    state.show_export = false;
    match choice {
        0 => {
            // Save raw payload of selected packet
            if let Some(ev) = state.selected_event() {
                let idx = state.selected_event_idx().unwrap_or(0);
                let path = format!("nullca_payload_{}.bin", idx + 1);
                if std::fs::write(&path, &ev.data).is_ok() {
                    state.set_status(format!("Saved {} bytes raw payload to '{}'", ev.data.len(), path));
                } else {
                    state.set_status("Failed to write payload file".into());
                }
            } else {
                state.set_status("No packet selected to save".into());
            }
        }
        1 => {
            // Save as cURL script
            if let Some(ev) = state.selected_event() {
                let idx = state.selected_event_idx().unwrap_or(0);
                if let Some(curl_cmd) = CurlExporter::from_payload(&ev.data) {
                    let path = format!("nullca_request_{}.sh", idx + 1);
                    let script = format!("#!/usr/bin/env bash\n# NullCA Exported cURL Request #\n\n{}\n", curl_cmd);
                    if std::fs::write(&path, script).is_ok() {
                        state.set_status(format!("Saved ready-to-run cURL script to '{}'", path));
                    } else {
                        state.set_status("Failed to save cURL script".into());
                    }
                } else {
                    state.set_status("Selected packet is not an HTTP request".into());
                }
            } else {
                state.set_status("No packet selected".into());
            }
        }
        2 => {
            // Export PCAP-NG
            let path = "nullca_capture.pcapng";
            if PcapNgWriter::write_to_file(&state.events, path).is_ok() {
                state.set_status(format!("Exported {} packets to Wireshark PCAP-NG '{}'", state.events.len(), path));
            } else {
                state.set_status("Failed to export PCAP-NG file".into());
            }
        }
        3 => {
            // Export HAR
            let path = "nullca_capture.har";
            if HarExporter::write_to_file(&state.events, path).is_ok() {
                state.set_status(format!("Exported {} packets to HAR 1.2 '{}'", state.events.len(), path));
            } else {
                state.set_status("Failed to export HAR file".into());
            }
        }
        4 => {
            // Export OpenAPI 3.0 specification
            let path = "nullca_openapi.json";
            let har = HarExporter::export_events(&state.events);
            let gen = crate::export::openapi::OpenApiGenerator::new();
            let spec = gen.generate_from_har_entries(&har.log.entries, "NullCA Intercepted API", "1.0.0");
            match gen.to_json_string(&spec) {
                Ok(json_str) => {
                    if std::fs::write(path, json_str).is_ok() {
                        state.set_status(format!("Exported OpenAPI 3.0 spec to '{}'", path));
                    } else {
                        state.set_status("Failed to write OpenAPI spec file".into());
                    }
                }
                Err(e) => {
                    state.set_status(format!("Failed to serialize OpenAPI spec: {}", e));
                }
            }
        }
        _ => {}
    }
}

fn draw_ui(f: &mut ratatui::Frame, state: &mut DashboardState) {
    let size = f.area();

    // Check if in Fullscreen Mode
    if let Some(pane) = state.maximized_pane {
        let chunks = Layout::default()
            .direction(LayoutDirection::Vertical)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Min(5),    // Fullscreen Pane
                Constraint::Length(1), // Footer
            ])
            .split(size);

        draw_header(f, state, chunks[0]);
        match pane {
            ActivePane::PacketTable => draw_packet_table(f, state, chunks[1]),
            ActivePane::DecodedDetails => draw_fullscreen_details(f, state, chunks[1]),
            ActivePane::Hexdump => draw_fullscreen_hexdump(f, state, chunks[1]),
        }
        draw_footer(f, state, chunks[2]);
    } else {
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

    // Modal Overlays
    if state.show_help {
        draw_help_modal(f, size);
    } else if state.show_export {
        draw_export_modal(f, size, state.export_choice);
    } else if let Some(ref mut rep) = state.repeater {
        rep.draw(f, size);
    }
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

    let fullscreen_pill = if let Some(pane) = state.maximized_pane {
        Span::styled(format!(" [FULLSCREEN: {:?}] ", pane), Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD))
    } else {
        Span::raw("")
    };

    let title_line = Line::from(vec![
        Span::styled("⚡ NullCA Cockpit v0.2.0 ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("─ Zero-CA eBPF Plaintext TLS, HTTP/2, WS & gRPC Inspector "),
        status_pill,
        diff_pill,
        fullscreen_pill,
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
        " Filter Expression (Type query, Up/Down for history, Enter to apply, Esc to cancel) "
    } else {
        " Active Filter DSL (Press '/' to edit, '?' for DSL cheat sheet) "
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
        "No filter active (try: proto == \"http2\" || status >= 400 || contains \"flag{\")".to_string()
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
        .title(" Captured Decrypted Packets [Tab to focus, j/k or wheel to scroll] ")
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
                ProtocolType::X509 => ("X.509", Style::default().fg(Color::Yellow)),
                ProtocolType::Redis => ("REDIS", Style::default().fg(Color::LightRed)),
                ProtocolType::Database => ("SQL", Style::default().fg(Color::LightBlue)),
                ProtocolType::Smtp => ("SMTP", Style::default().fg(Color::LightYellow)),
                ProtocolType::RawTls => ("TLS/RAW", Style::default().fg(Color::DarkGray)),
            };

            // Scan secrets & flags
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
            let preview = match ev.protocol() {
                ProtocolType::WebSocket => {
                    if let Some((frame, _)) = WebSocketParser::parse_frame(&ev.data) {
                        format!("[{}] {}", frame.opcode, frame.text_preview.unwrap_or_else(|| format!("{} bytes", frame.payload_len)))
                    } else {
                        String::from_utf8_lossy(&ev.data).lines().next().unwrap_or("").to_string()
                    }
                }
                ProtocolType::X509 => {
                    if let Some(cert) = X509Parser::parse(&ev.data) {
                        format!("CN={} (Issuer: {})", cert.subject_cn.as_deref().unwrap_or("Unknown"), cert.issuer_cn.as_deref().unwrap_or("Unknown"))
                    } else {
                        "X.509 Certificate Chain / Bundle".into()
                    }
                }
                ProtocolType::Redis => {
                    if let Some(cmd) = crate::proto::database::NonHttpDissector::parse_redis(&ev.data) {
                        format!("{} {}", cmd.command, cmd.args.join(" "))
                    } else {
                        String::from_utf8_lossy(&ev.data).lines().next().unwrap_or("").to_string()
                    }
                }
                ProtocolType::Database => {
                    if let Some(q) = crate::proto::database::NonHttpDissector::parse_postgres(&ev.data) {
                        q
                    } else {
                        String::from_utf8_lossy(&ev.data).lines().next().unwrap_or("").to_string()
                    }
                }
                ProtocolType::Smtp => {
                    if let Some(line) = crate::proto::database::NonHttpDissector::parse_smtp(&ev.data) {
                        line
                    } else {
                        String::from_utf8_lossy(&ev.data).lines().next().unwrap_or("").to_string()
                    }
                }
                _ => {
                    String::from_utf8_lossy(&ev.data)
                        .lines()
                        .next()
                        .unwrap_or("")
                        .chars()
                        .take(65)
                        .collect::<String>()
                }
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

fn draw_details_and_hex(f: &mut ratatui::Frame, state: &mut DashboardState, area: Rect) {
    let sub_chunks = Layout::default()
        .direction(LayoutDirection::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    draw_details_pane(f, state, sub_chunks[0]);
    draw_hexdump_pane(f, state, sub_chunks[1]);
}

fn draw_fullscreen_details(f: &mut ratatui::Frame, state: &mut DashboardState, area: Rect) {
    draw_details_pane(f, state, area);
}

fn draw_fullscreen_hexdump(f: &mut ratatui::Frame, state: &mut DashboardState, area: Rect) {
    draw_hexdump_pane(f, state, area);
}

fn draw_details_pane(f: &mut ratatui::Frame, state: &mut DashboardState, area: Rect) {
    let maybe_event = state.selected_event();
    let is_focused = state.active_pane == ActivePane::DecodedDetails;
    let left_border = if is_focused { Color::Cyan } else { Color::DarkGray };

    let tab_titles = [
        " [1] Info & Headers ",
        " [2] Protobuf ",
        " [3] Secrets & Flags ",
        " [4] cURL ",
        " [5] WebSocket ",
        " [6] X.509 PKI ",
        " [7] Diff ",
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

    let title_line = Line::from(tab_titles);
    let details_block = Block::default()
        .borders(Borders::ALL)
        .title(title_line)
        .border_style(Style::default().fg(left_border));

    if let Some(ev) = maybe_event {
        let mut lines = Vec::new();

        lines.push(Line::from(vec![
            Span::styled("Process: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{} (PID: {})", ev.comm, ev.pid), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            Span::styled("  Socket FD: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{}", ev.fd), Style::default().fg(Color::LightBlue)),
            Span::styled("  Direction: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{:?}", ev.direction), Style::default().fg(if ev.direction == Direction::Ingress { Color::Green } else { Color::Blue })),
        ]));

        lines.push(Line::from(vec![
            Span::styled("Protocol: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{:?}", ev.protocol()), Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
            Span::styled("  Payload Size: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{} bytes", ev.data.len()), Style::default().fg(Color::Yellow)),
        ]));

        lines.push(Line::raw(""));

        match state.selected_tab {
            0 => {
                // Info & Headers
                match ev.protocol() {
                    ProtocolType::Http1 => {
                        if let Some(msg) = Http1Parser::parse(&ev.data) {
                            lines.push(Line::from(Span::styled("--- HTTP/1.1 Header Dissection ---", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));
                            let (headers, body) = match msg {
                                Http1Message::Request { headers, body, method, uri, version } => {
                                    lines.push(Line::from(vec![
                                        Span::styled("Request: ", Style::default().fg(Color::DarkGray)),
                                        Span::styled(format!("{} {} {}", method, uri, version), Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)),
                                    ]));
                                    (headers, body)
                                }
                                Http1Message::Response { headers, body, status_code, reason, version } => {
                                    let status_color = if status_code < 300 { Color::Green } else if status_code < 400 { Color::Cyan } else { Color::Red };
                                    lines.push(Line::from(vec![
                                        Span::styled("Response: ", Style::default().fg(Color::DarkGray)),
                                        Span::styled(format!("{} {} {}", version, status_code, reason), Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
                                    ]));
                                    (headers, body)
                                }
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
                                for l in String::from_utf8_lossy(&body).lines() {
                                    lines.push(Line::raw(l.to_string()));
                                }
                            }
                        }
                    }
                    ProtocolType::Database => {
                        if let Some(q) = crate::proto::database::NonHttpDissector::parse_postgres(&ev.data) {
                            lines.push(Line::from(Span::styled("--- Database SQL Query Dissection ---", Style::default().fg(Color::LightBlue).add_modifier(Modifier::BOLD))));
                            lines.push(Line::raw(""));
                            for l in q.lines() {
                                lines.push(Line::from(Span::styled(l.to_string(), Style::default().fg(Color::White).add_modifier(Modifier::BOLD))));
                            }
                        }
                    }
                    ProtocolType::Redis => {
                        if let Some(cmd) = crate::proto::database::NonHttpDissector::parse_redis(&ev.data) {
                            lines.push(Line::from(Span::styled("--- Redis Protocol (RESP) Dissection ---", Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD))));
                            lines.push(Line::from(vec![
                                Span::styled("Command: ", Style::default().fg(Color::DarkGray)),
                                Span::styled(cmd.command, Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                            ]));
                            lines.push(Line::from(format!("Arguments ({}):", cmd.args.len())));
                            for (i, arg) in cmd.args.iter().enumerate() {
                                lines.push(Line::from(format!("  [{}] {}", i, arg)));
                            }
                        }
                    }
                    ProtocolType::Smtp => {
                        if let Some(line) = crate::proto::database::NonHttpDissector::parse_smtp(&ev.data) {
                            lines.push(Line::from(Span::styled("--- SMTP Mail Protocol Dissection ---", Style::default().fg(Color::LightYellow).add_modifier(Modifier::BOLD))));
                            lines.push(Line::from(Span::styled(line, Style::default().fg(Color::White))));
                        }
                    }
                    _ => {
                        lines.push(Line::from(Span::styled("--- Decoded Payload Stream ---", Style::default().fg(Color::DarkGray))));
                        let text = String::from_utf8_lossy(&ev.data);
                        for l in text.lines() {
                            lines.push(Line::raw(format!("  {}", l)));
                        }
                    }
                }
            }
            1 => {
                // Protobuf Tree
                if let Ok((grpc_msg, _)) = GrpcMessage::parse(&ev.data) {
                    if let Ok(pb) = ProtobufMessage::decode(&grpc_msg.payload) {
                        lines.push(Line::from(Span::styled("--- gRPC & Schema-less Protobuf Tree ---", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))));
                        for line in pb.to_json().lines() {
                            lines.push(Line::raw(format!("  {}", line)));
                        }
                    }
                } else if let Ok(pb) = ProtobufMessage::decode(&ev.data) {
                    lines.push(Line::from(Span::styled("--- Schema-less Protobuf Wire Tree ---", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))));
                    for line in pb.to_json().lines() {
                        lines.push(Line::raw(format!("  {}", line)));
                    }
                } else {
                    lines.push(Line::raw("No Protocol Buffers binary wire payload detected."));
                }
            }
            2 => {
                // Secrets & CTF Flags
                let secrets = scan_secrets(&ev.data);
                if secrets.is_empty() {
                    lines.push(Line::raw("No sensitive tokens, JWTs, or CTF flags detected in payload."));
                } else {
                    lines.push(Line::from(Span::styled(format!("Detected {} sensitive token(s) / flag(s):", secrets.len()), Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))));
                    lines.push(Line::raw(""));
                    for sec in secrets {
                        lines.push(Line::from(vec![
                            Span::styled("Type: ", Style::default().fg(Color::DarkGray)),
                            Span::styled(format!("{:?}", sec.kind), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                            Span::styled(format!(" ({})", sec.location), Style::default().fg(Color::DarkGray)),
                        ]));
                        lines.push(Line::from(vec![
                            Span::styled("Token: ", Style::default().fg(Color::DarkGray)),
                            Span::styled(sec.raw_token, Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)),
                        ]));
                        if let Some(details) = sec.decoded_details {
                            for l in details.lines() {
                                lines.push(Line::from(Span::styled(format!("  {}", l), Style::default().fg(Color::LightCyan))));
                            }
                        }
                        lines.push(Line::raw(""));
                    }
                }
            }
            3 => {
                // cURL
                if let Some(curl_cmd) = CurlExporter::from_payload(&ev.data) {
                    lines.push(Line::from(Span::styled("--- Ready-to-Run cURL Command ---", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))));
                    lines.push(Line::raw(""));
                    for l in curl_cmd.lines() {
                        lines.push(Line::raw(l.to_string()));
                    }
                } else {
                    lines.push(Line::raw("Not an outbound HTTP request (cURL export available for requests only)."));
                }
            }
            4 => {
                // WebSocket
                let frames = WebSocketParser::parse_all_frames(&ev.data);
                if frames.is_empty() {
                    lines.push(Line::raw("No RFC 6455 WebSocket frames detected in this packet."));
                } else {
                    lines.push(Line::from(Span::styled(format!("--- WebSocket Stream Dissection ({} frames) ---", frames.len()), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));
                    lines.push(Line::raw(""));
                    for (i, f) in frames.iter().enumerate() {
                        lines.push(Line::from(vec![
                            Span::styled(format!("[Frame #{}] ", i + 1), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                            Span::styled(format!("Opcode: {} ", f.opcode), Style::default().fg(Color::LightCyan)),
                            Span::styled(format!("FIN: {} ", f.fin), Style::default().fg(if f.fin { Color::Green } else { Color::Yellow })),
                            Span::styled(format!("Masked: {} ", f.masked), Style::default().fg(Color::DarkGray)),
                            Span::styled(format!("Len: {} bytes", f.payload_len), Style::default().fg(Color::White)),
                        ]));
                        if let Some(ref text) = f.text_preview {
                            let tag = if f.is_json { "[JSON]" } else { "[TEXT]" };
                            lines.push(Line::from(vec![
                                Span::styled(format!("  {} Payload: ", tag), Style::default().fg(Color::LightGreen)),
                                Span::raw(text.clone()),
                            ]));
                        }
                        lines.push(Line::raw(""));
                    }
                }
            }
            5 => {
                // X.509 PKI & Certificate Inspector
                if let Some(cert) = X509Parser::parse(&ev.data) {
                    lines.push(Line::from(Span::styled("--- X.509 Public Key Infrastructure Dissection ---", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))));
                    lines.push(Line::from(vec![
                        Span::styled("  Subject DN: ", Style::default().fg(Color::DarkGray)),
                        Span::styled(cert.subject_dn, Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                    ]));
                    lines.push(Line::from(vec![
                        Span::styled("  Issuer DN: ", Style::default().fg(Color::DarkGray)),
                        Span::styled(cert.issuer_dn, Style::default().fg(Color::Yellow)),
                    ]));
                    lines.push(Line::from(format!("  Public Key: {} | Signature: {}", cert.public_key_algorithm, cert.signature_algorithm)));
                    lines.push(Line::from(format!("  Validity: {} -> {}", cert.not_before.as_deref().unwrap_or("?"), cert.not_after.as_deref().unwrap_or("?"))));
                    let status_style = if cert.validity_status.starts_with("EXPIRED") { Style::default().fg(Color::Red).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::Green).add_modifier(Modifier::BOLD) };
                    lines.push(Line::from(vec![
                        Span::styled("  Status: ", Style::default().fg(Color::DarkGray)),
                        Span::styled(cert.validity_status, status_style),
                    ]));
                    lines.push(Line::from(vec![
                        Span::styled("  SHA-256 Fingerprint: ", Style::default().fg(Color::Cyan)),
                        Span::styled(cert.fingerprint_sha256, Style::default().fg(Color::LightCyan)),
                    ]));
                    if !cert.subject_alt_names.is_empty() {
                        lines.push(Line::from(Span::styled(format!("  SANs ({} hostnames):", cert.subject_alt_names.len()), Style::default().fg(Color::LightBlue))));
                        for san in cert.subject_alt_names.iter().take(10) {
                            lines.push(Line::from(format!("    • {}", san)));
                        }
                    }
                } else if let Some(crl) = X509Parser::parse_crl(&ev.data) {
                    lines.push(Line::from(Span::styled("--- X.509 Certificate Revocation List (CRL) ---", Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD))));
                    lines.push(Line::from(format!("  Issuer: {}", crl.issuer_dn)));
                    lines.push(Line::from(format!("  Revoked Certificates Count: {}", crl.revoked_count)));
                    lines.push(Line::from(format!("  Updates: {} -> {}", crl.this_update.as_deref().unwrap_or("?"), crl.next_update.as_deref().unwrap_or("?"))));
                } else if let Some(csr) = X509Parser::parse_csr(&ev.data) {
                    lines.push(Line::from(Span::styled("--- X.509 Certificate Signing Request (CSR) ---", Style::default().fg(Color::LightCyan).add_modifier(Modifier::BOLD))));
                    lines.push(Line::from(format!("  Subject: {}", csr.subject_dn)));
                    lines.push(Line::from(format!("  Public Key: {}", csr.public_key_algorithm)));
                } else {
                    lines.push(Line::raw("No X.509 ASN.1 certificate, CRL, or CSR payload detected."));
                }
            }
            6 => {
                // Diff Inspector
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
                    lines.push(Line::from("1. Navigate to a packet and press [d] to set baseline 📌."));
                    lines.push(Line::from("2. Navigate to another packet and press [d] to diff!"));
                    lines.push(Line::from("3. Press [Esc] to return."));
                }
            }
            _ => {}
        }

        let visible_h = area.height.saturating_sub(2) as usize;
        state.details_max_scroll = lines.len().saturating_sub(visible_h);
        state.details_scroll = state.details_scroll.min(state.details_max_scroll);

        let p = Paragraph::new(lines)
            .block(details_block)
            .scroll((state.details_scroll as u16, 0))
            .wrap(Wrap { trim: false });
        f.render_widget(p, area);

        // Render scrollbar
        if state.details_max_scroll > 0 {
            let mut scrollbar_state = ScrollbarState::new(state.details_max_scroll).position(state.details_scroll);
            let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("▲"))
                .end_symbol(Some("▼"))
                .track_symbol(Some("│"))
                .thumb_symbol("█");
            f.render_stateful_widget(scrollbar, area, &mut scrollbar_state);
        }
    } else {
        let p = Paragraph::new("No packet selected").block(details_block);
        f.render_widget(p, area);
    }
}

fn draw_hexdump_pane(f: &mut ratatui::Frame, state: &mut DashboardState, area: Rect) {
    let maybe_event = state.selected_event();
    let is_focused = state.active_pane == ActivePane::Hexdump;
    let right_border = if is_focused { Color::Cyan } else { Color::DarkGray };

    let hex_block = Block::default()
        .borders(Borders::ALL)
        .title(" Raw Hex & ASCII Dump [j/k or wheel to scroll] ")
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

            while hex_part.len() < 50 {
                hex_part.push(' ');
            }

            let line = Line::from(vec![
                Span::styled(format!("{:08x}: ", offset), Style::default().fg(Color::DarkGray)),
                Span::styled(hex_part, Style::default().fg(Color::LightBlue)),
                Span::styled(format!("|{}|", ascii_part), Style::default().fg(Color::Yellow)),
            ]);
            hex_lines.push(line);
        }

        let visible_h = area.height.saturating_sub(2) as usize;
        state.hex_max_scroll = hex_lines.len().saturating_sub(visible_h);
        state.hex_scroll = state.hex_scroll.min(state.hex_max_scroll);

        let p = Paragraph::new(hex_lines)
            .block(hex_block)
            .scroll((state.hex_scroll as u16, 0));
        f.render_widget(p, area);

        // Render scrollbar
        if state.hex_max_scroll > 0 {
            let mut scrollbar_state = ScrollbarState::new(state.hex_max_scroll).position(state.hex_scroll);
            let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("▲"))
                .end_symbol(Some("▼"))
                .track_symbol(Some("│"))
                .thumb_symbol("█");
            f.render_stateful_widget(scrollbar, area, &mut scrollbar_state);
        }
    } else {
        let p = Paragraph::new("No payload").block(hex_block);
        f.render_widget(p, area);
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
        Span::styled("[R]", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::raw(" Repeater "),
        Span::styled("[r]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" FastReplay "),
        Span::styled("[d]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Diff "),
        Span::styled("[f]", Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
        Span::raw(" Fullscreen "),
        Span::styled("[s]", Style::default().fg(Color::LightCyan).add_modifier(Modifier::BOLD)),
        Span::raw(" Save "),
        Span::styled("[?]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Help "),
        Span::styled("[Tab]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Panes "),
        Span::styled("[1-7]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" Tabs "),
    ]);
    let p = Paragraph::new(hotkeys);
    f.render_widget(p, area);
}
