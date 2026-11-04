//! Interactive Request Repeater & Tamper Cockpit ("Burp Repeater for CLI").
//!
//! Allows full manual editing of HTTP methods, targets, paths, headers, and request bodies,
//! dispatching live requests with microsecond latency metrics and displaying formatted responses.

use crate::engine::event::TlsEvent;
use crate::engine::replay::ReplayRequest;
use crate::proto::http1::{Http1Message, Http1Parser};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    layout::{Constraint, Direction as LayoutDirection, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepeaterField {
    Method,
    Host,
    Port,
    Path,
    Headers,
    Body,
    SendButton,
}

impl RepeaterField {
    pub fn next(self) -> Self {
        match self {
            Self::Method => Self::Host,
            Self::Host => Self::Port,
            Self::Port => Self::Path,
            Self::Path => Self::Headers,
            Self::Headers => Self::Body,
            Self::Body => Self::SendButton,
            Self::SendButton => Self::Method,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Method => Self::SendButton,
            Self::Host => Self::Method,
            Self::Port => Self::Host,
            Self::Path => Self::Port,
            Self::Headers => Self::Path,
            Self::Body => Self::Headers,
            Self::SendButton => Self::Body,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RepeaterState {
    pub method: String,
    pub host: String,
    pub port: u16,
    pub use_tls: bool,
    pub path: String,
    pub headers_text: String,
    pub body_text: String,
    pub active_field: RepeaterField,

    // Live Response Telemetry
    pub response_status: Option<u16>,
    pub response_headers: Vec<(String, String)>,
    pub response_body: String,
    pub response_metrics: Option<(f64, f64)>, // (total_duration_ms, ttfb_ms)
    pub response_scroll: usize,
    pub response_max_scroll: usize,
    pub is_transmitting: bool,
    pub error_msg: Option<String>,
}

impl RepeaterState {
    /// Initialize a Repeater session from a captured TLS packet event
    pub fn from_event(event: &TlsEvent) -> Self {
        let mut method = "GET".to_string();
        let mut host = "127.0.0.1".to_string();
        let mut port = 80u16;
        let mut use_tls = false;
        let mut path = "/".to_string();
        let headers_text;
        let mut body_text = String::new();

        if let Some(msg) = Http1Parser::parse(&event.data) {
            match msg {
                Http1Message::Request {
                    method: m,
                    uri,
                    headers,
                    body,
                    ..
                } => {
                    method = m;
                    path = uri;
                    if let Some(h) = headers.get("host") {
                        if let Some((h_str, p_str)) = h.split_once(':') {
                            host = h_str.to_string();
                            port = p_str.parse::<u16>().unwrap_or(80);
                        } else {
                            host = h.clone();
                            port = 80;
                        }
                    }
                    if port == 443 {
                        use_tls = true;
                    }

                    let mut h_lines = Vec::new();
                    for (k, v) in headers {
                        h_lines.push(format!("{}: {}", k, v));
                    }
                    headers_text = h_lines.join("\n");

                    if !body.is_empty() {
                        body_text = String::from_utf8_lossy(&body).to_string();
                    }
                }
                Http1Message::Response { .. } => {
                    headers_text = "User-Agent: nullca-repeater/0.2\nAccept: */*".into();
                }
            }
        } else {
            headers_text = "Host: 127.0.0.1\nUser-Agent: nullca/0.2\nAccept: */*".into();
        }

        Self {
            method,
            host,
            port,
            use_tls,
            path,
            headers_text,
            body_text,
            active_field: RepeaterField::Path,
            response_status: None,
            response_headers: Vec::new(),
            response_body: String::new(),
            response_metrics: None,
            response_scroll: 0,
            response_max_scroll: 0,
            is_transmitting: false,
            error_msg: None,
        }
    }

    /// Convert current editor buffers to a valid `ReplayRequest`
    pub fn build_replay_request(&self) -> ReplayRequest {
        let mut headers = HashMap::new();
        for line in self.headers_text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some((k, v)) = trimmed.split_once(':') {
                headers.insert(k.trim().to_lowercase(), v.trim().to_string());
            }
        }

        // Ensure Host header is present
        headers.entry("host".to_string()).or_insert_with(|| {
            if self.port == 80 || self.port == 443 {
                self.host.clone()
            } else {
                format!("{}:{}", self.host, self.port)
            }
        });

        let body = self.body_text.as_bytes().to_vec();

        ReplayRequest {
            host: self.host.clone(),
            port: self.port,
            use_tls: self.use_tls,
            method: self.method.clone(),
            path: self.path.clone(),
            headers,
            body,
        }
    }

    /// Handle key input inside Repeater modal
    /// Returns `Some(ReplayRequest)` when dispatch is requested
    pub fn handle_key(&mut self, key: KeyEvent) -> Option<ReplayRequest> {
        // Global send shortcut: Ctrl+R or F5
        if (key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('r'))
            || key.code == KeyCode::F(5)
        {
            self.is_transmitting = true;
            self.error_msg = None;
            return Some(self.build_replay_request());
        }

        // Response scrolling with PgUp / PgDn
        match key.code {
            KeyCode::PageDown => {
                self.response_scroll = self.response_scroll.saturating_add(8);
                return None;
            }
            KeyCode::PageUp => {
                self.response_scroll = self.response_scroll.saturating_sub(8);
                return None;
            }
            KeyCode::Tab => {
                self.active_field = self.active_field.next();
                return None;
            }
            KeyCode::BackTab => {
                self.active_field = self.active_field.prev();
                return None;
            }
            _ => {}
        }

        match self.active_field {
            RepeaterField::SendButton => {
                if key.code == KeyCode::Enter || key.code == KeyCode::Char(' ') {
                    self.is_transmitting = true;
                    self.error_msg = None;
                    return Some(self.build_replay_request());
                }
            }
            RepeaterField::Method => match key.code {
                KeyCode::Char(c) => self.method.push(c.to_ascii_uppercase()),
                KeyCode::Backspace => {
                    self.method.pop();
                }
                KeyCode::Enter => self.active_field = RepeaterField::Host,
                _ => {}
            },
            RepeaterField::Host => match key.code {
                KeyCode::Char(c) => self.host.push(c),
                KeyCode::Backspace => {
                    self.host.pop();
                }
                KeyCode::Enter => self.active_field = RepeaterField::Port,
                _ => {}
            },
            RepeaterField::Port => match key.code {
                KeyCode::Char(c) if c.is_ascii_digit() => {
                    let mut p_str = self.port.to_string();
                    p_str.push(c);
                    if let Ok(p) = p_str.parse::<u16>() {
                        self.port = p;
                        if p == 443 {
                            self.use_tls = true;
                        }
                    }
                }
                KeyCode::Backspace => {
                    let mut p_str = self.port.to_string();
                    p_str.pop();
                    self.port = p_str.parse::<u16>().unwrap_or(0);
                }
                KeyCode::Enter => self.active_field = RepeaterField::Path,
                _ => {}
            },
            RepeaterField::Path => match key.code {
                KeyCode::Char(c) => self.path.push(c),
                KeyCode::Backspace => {
                    self.path.pop();
                }
                KeyCode::Enter => self.active_field = RepeaterField::Headers,
                _ => {}
            },
            RepeaterField::Headers => match key.code {
                KeyCode::Char(c) => self.headers_text.push(c),
                KeyCode::Backspace => {
                    self.headers_text.pop();
                }
                KeyCode::Enter => self.headers_text.push('\n'),
                _ => {}
            },
            RepeaterField::Body => match key.code {
                KeyCode::Char(c) => self.body_text.push(c),
                KeyCode::Backspace => {
                    self.body_text.pop();
                }
                KeyCode::Enter => self.body_text.push('\n'),
                _ => {}
            },
        }

        None
    }

    /// Render interactive Request & Response split panes inside Repeater modal
    pub fn draw(&mut self, f: &mut Frame, area: Rect) {
        f.render_widget(Clear, area);

        let outer_block = Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(
                " ⚡ NullCA Request Repeater & Live Tamper Cockpit ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ))
            .border_style(Style::default().fg(Color::Cyan));
        f.render_widget(outer_block, area);

        let inner_area = Rect {
            x: area.x + 1,
            y: area.y + 1,
            width: area.width.saturating_sub(2),
            height: area.height.saturating_sub(2),
        };

        let main_split = Layout::default()
            .direction(LayoutDirection::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(inner_area);

        // LEFT: Request Editor
        self.draw_request_editor(f, main_split[0]);

        // RIGHT: Response Inspector
        self.draw_response_inspector(f, main_split[1]);
    }

    fn draw_request_editor(&self, f: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(
                " Request Editor ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ))
            .border_style(Style::default().fg(Color::Yellow));
        f.render_widget(block, area);

        let req_inner = Rect {
            x: area.x + 1,
            y: area.y + 1,
            width: area.width.saturating_sub(2),
            height: area.height.saturating_sub(2),
        };

        let v_chunks = Layout::default()
            .direction(LayoutDirection::Vertical)
            .constraints([
                Constraint::Length(3),      // Target config (Method, Host, Port)
                Constraint::Length(3),      // Path
                Constraint::Percentage(40), // Headers
                Constraint::Percentage(40), // Body
                Constraint::Length(3),      // Action bar
            ])
            .split(req_inner);

        // 1. Method / Host / Port line
        let h_target_chunks = Layout::default()
            .direction(LayoutDirection::Horizontal)
            .constraints([
                Constraint::Length(12),
                Constraint::Percentage(60),
                Constraint::Length(12),
            ])
            .split(v_chunks[0]);

        // Method
        let method_style = if self.active_field == RepeaterField::Method {
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        let method_block = Block::default()
            .borders(Borders::ALL)
            .title("Method")
            .border_style(if self.active_field == RepeaterField::Method {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::DarkGray)
            });
        let p_method = Paragraph::new(format!("{}_", self.method))
            .style(method_style)
            .block(method_block);
        f.render_widget(p_method, h_target_chunks[0]);

        // Host
        let host_style = if self.active_field == RepeaterField::Host {
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        let host_block = Block::default()
            .borders(Borders::ALL)
            .title("Target Host")
            .border_style(if self.active_field == RepeaterField::Host {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::DarkGray)
            });
        let p_host = Paragraph::new(format!("{}_", self.host))
            .style(host_style)
            .block(host_block);
        f.render_widget(p_host, h_target_chunks[1]);

        // Port
        let port_block = Block::default()
            .borders(Borders::ALL)
            .title(if self.use_tls { "Port (TLS)" } else { "Port" })
            .border_style(if self.active_field == RepeaterField::Port {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::DarkGray)
            });
        let p_port = Paragraph::new(format!("{}_", self.port)).block(port_block);
        f.render_widget(p_port, h_target_chunks[2]);

        // 2. Path
        let path_block = Block::default()
            .borders(Borders::ALL)
            .title("URI Path")
            .border_style(if self.active_field == RepeaterField::Path {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::DarkGray)
            });
        let p_path = Paragraph::new(format!("{}_", self.path)).block(path_block);
        f.render_widget(p_path, v_chunks[1]);

        // 3. Headers
        let headers_block = Block::default()
            .borders(Borders::ALL)
            .title("HTTP Request Headers (Key: Value)")
            .border_style(if self.active_field == RepeaterField::Headers {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::DarkGray)
            });
        let p_headers = Paragraph::new(format!("{}_", self.headers_text))
            .block(headers_block)
            .wrap(Wrap { trim: false });
        f.render_widget(p_headers, v_chunks[2]);

        // 4. Body
        let body_block = Block::default()
            .borders(Borders::ALL)
            .title("Request Body (JSON / Plaintext)")
            .border_style(if self.active_field == RepeaterField::Body {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::DarkGray)
            });
        let p_body = Paragraph::new(format!("{}_", self.body_text))
            .block(body_block)
            .wrap(Wrap { trim: false });
        f.render_widget(p_body, v_chunks[3]);

        // 5. Send Action Bar
        let btn_style = if self.active_field == RepeaterField::SendButton {
            Style::default()
                .bg(Color::Green)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD)
        } else if self.is_transmitting {
            Style::default().bg(Color::Yellow).fg(Color::Black)
        } else {
            Style::default()
                .fg(Color::LightGreen)
                .add_modifier(Modifier::BOLD)
        };
        let btn_label = if self.is_transmitting {
            " ⏳ Transmitting Live Request... "
        } else {
            " ▶ [Ctrl+R / Enter] Send Request "
        };
        let p_action = Paragraph::new(Line::from(vec![
            Span::styled(btn_label, btn_style),
            Span::raw("  "),
            Span::styled("[Tab]", Style::default().fg(Color::Yellow)),
            Span::raw(" Next Field  "),
            Span::styled("[Esc]", Style::default().fg(Color::Yellow)),
            Span::raw(" Close"),
        ]));
        f.render_widget(p_action, v_chunks[4]);
    }

    fn draw_response_inspector(&mut self, f: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(
                " Live Server Response ",
                Style::default()
                    .fg(Color::LightCyan)
                    .add_modifier(Modifier::BOLD),
            ))
            .border_style(Style::default().fg(Color::LightCyan));
        f.render_widget(block, area);

        let resp_inner = Rect {
            x: area.x + 1,
            y: area.y + 1,
            width: area.width.saturating_sub(2),
            height: area.height.saturating_sub(2),
        };

        if let Some(ref err) = self.error_msg {
            let p_err = Paragraph::new(Line::from(vec![
                Span::styled(
                    "❌ Replay Transmission Error: ",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::raw(err.clone()),
            ]));
            f.render_widget(p_err, resp_inner);
            return;
        }

        if self.is_transmitting {
            let p_loading = Paragraph::new(Span::styled(
                "⏳ Connecting to target & measuring latency telemetry...",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ));
            f.render_widget(p_loading, resp_inner);
            return;
        }

        if let Some(status) = self.response_status {
            let v_chunks = Layout::default()
                .direction(LayoutDirection::Vertical)
                .constraints([
                    Constraint::Length(3),      // Status & telemetry line
                    Constraint::Percentage(35), // Response headers
                    Constraint::Percentage(60), // Response body
                ])
                .split(resp_inner);

            // Status & Metrics bar
            let status_color = if status < 300 {
                Color::Green
            } else if status < 400 {
                Color::Cyan
            } else if status < 500 {
                Color::Yellow
            } else {
                Color::Red
            };

            let (total_ms, ttfb_ms) = self.response_metrics.unwrap_or((0.0, 0.0));
            let metrics_line = Line::from(vec![
                Span::styled(
                    format!("HTTP {} ", status),
                    Style::default()
                        .fg(status_color)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" | "),
                Span::styled("Total Latency: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{:.2} ms", total_ms),
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" | "),
                Span::styled("TTFB: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{:.2} ms", ttfb_ms),
                    Style::default().fg(Color::Yellow),
                ),
                Span::raw(" | "),
                Span::styled("Body Size: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{} bytes", self.response_body.len()),
                    Style::default().fg(Color::LightGreen),
                ),
            ]);
            let p_metrics = Paragraph::new(metrics_line)
                .block(Block::default().borders(Borders::ALL).title("Status"));
            f.render_widget(p_metrics, v_chunks[0]);

            // Response Headers
            let mut header_lines = Vec::new();
            for (k, v) in &self.response_headers {
                header_lines.push(Line::from(vec![
                    Span::styled(format!("{}: ", k), Style::default().fg(Color::LightCyan)),
                    Span::raw(v.clone()),
                ]));
            }
            let p_headers = Paragraph::new(header_lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Response Headers"),
                )
                .wrap(Wrap { trim: false });
            f.render_widget(p_headers, v_chunks[1]);

            // Response Body with vertical scrolling
            let mut body_lines = Vec::new();
            for l in self.response_body.lines() {
                body_lines.push(Line::raw(l.to_string()));
            }

            let visible_h = v_chunks[2].height.saturating_sub(2) as usize;
            self.response_max_scroll = body_lines.len().saturating_sub(visible_h);
            self.response_scroll = self.response_scroll.min(self.response_max_scroll);

            let body_title = format!(
                "Response Body (Scroll: {}/{} - PgUp/PgDn)",
                self.response_scroll, self.response_max_scroll
            );
            let p_body = Paragraph::new(body_lines)
                .block(Block::default().borders(Borders::ALL).title(body_title))
                .scroll((self.response_scroll as u16, 0))
                .wrap(Wrap { trim: false });
            f.render_widget(p_body, v_chunks[2]);
        } else {
            let p_idle = Paragraph::new(Line::from(vec![
                Span::styled("No response yet. ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    "Press [Ctrl+R] or Enter on 'Send Request' to transmit.",
                    Style::default().fg(Color::Yellow),
                ),
            ]));
            f.render_widget(p_idle, resp_inner);
        }
    }
}
