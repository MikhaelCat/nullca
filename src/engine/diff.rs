//! Side-by-Side & Unified Packet Diff Engine.
//!
//! Provides Myers / LCS line-by-line diffing for HTTP headers, JSON payloads,
//! Protobuf trees, and raw decrypted streams with ANSI and Ratatui highlighting.

use crate::engine::event::{Direction, ProtocolType, TlsEvent};
use crate::proto::http1::{Http1Message, Http1Parser};
use colored::*;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffKind {
    Equal,
    Added,
    Removed,
    Modified,
}

#[derive(Debug, Clone)]
pub struct DiffLine {
    pub kind: DiffKind,
    pub content: String,
    pub line_a: Option<usize>,
    pub line_b: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct HeaderDiffItem {
    pub name: String,
    pub kind: DiffKind,
    pub old_val: Option<String>,
    pub new_val: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EventDiffResult {
    pub event_a_id: usize,
    pub event_b_id: usize,
    pub proto_a: ProtocolType,
    pub proto_b: ProtocolType,
    pub dir_a: Direction,
    pub dir_b: Direction,
    pub comm_a: String,
    pub comm_b: String,
    pub header_diffs: Vec<HeaderDiffItem>,
    pub body_diffs: Vec<DiffLine>,
    pub total_additions: usize,
    pub total_deletions: usize,
}

pub struct DiffEngine;

impl DiffEngine {
    /// Computes Longest Common Subsequence (LCS) line diff between two multi-line texts.
    pub fn diff_text(text_a: &str, text_b: &str) -> Vec<DiffLine> {
        let lines_a: Vec<&str> = text_a.lines().collect();
        let lines_b: Vec<&str> = text_b.lines().collect();

        let n = lines_a.len();
        let m = lines_b.len();

        // DP table for LCS
        let mut dp = vec![vec![0usize; m + 1]; n + 1];
        for i in 1..=n {
            for j in 1..=m {
                if lines_a[i - 1] == lines_b[j - 1] {
                    dp[i][j] = dp[i - 1][j - 1] + 1;
                } else {
                    dp[i][j] = dp[i - 1][j].max(dp[i][j - 1]);
                }
            }
        }

        // Backtrack to build diff
        let mut diff = Vec::new();
        let mut i = n;
        let mut j = m;

        while i > 0 || j > 0 {
            if i > 0 && j > 0 && lines_a[i - 1] == lines_b[j - 1] {
                diff.push(DiffLine {
                    kind: DiffKind::Equal,
                    content: lines_a[i - 1].to_string(),
                    line_a: Some(i),
                    line_b: Some(j),
                });
                i -= 1;
                j -= 1;
            } else if j > 0 && (i == 0 || dp[i][j - 1] >= dp[i - 1][j]) {
                diff.push(DiffLine {
                    kind: DiffKind::Added,
                    content: lines_b[j - 1].to_string(),
                    line_a: None,
                    line_b: Some(j),
                });
                j -= 1;
            } else if i > 0 && (j == 0 || dp[i][j - 1] < dp[i - 1][j]) {
                diff.push(DiffLine {
                    kind: DiffKind::Removed,
                    content: lines_a[i - 1].to_string(),
                    line_a: Some(i),
                    line_b: None,
                });
                i -= 1;
            }
        }

        diff.reverse();
        diff
    }

    /// Compares two sets of HTTP headers into added, removed, modified, and equal items.
    pub fn diff_headers(
        headers_a: &HashMap<String, String>,
        headers_b: &HashMap<String, String>,
    ) -> Vec<HeaderDiffItem> {
        let mut sorted_a: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in headers_a {
            sorted_a.insert(k.to_lowercase(), v.clone());
        }

        let mut sorted_b: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in headers_b {
            sorted_b.insert(k.to_lowercase(), v.clone());
        }

        let mut all_keys: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for k in sorted_a.keys().chain(sorted_b.keys()) {
            all_keys.insert(k.clone());
        }

        let mut items = Vec::new();
        for key in all_keys {
            match (sorted_a.get(&key), sorted_b.get(&key)) {
                (Some(val_a), Some(val_b)) => {
                    if val_a == val_b {
                        items.push(HeaderDiffItem {
                            name: key,
                            kind: DiffKind::Equal,
                            old_val: Some(val_a.clone()),
                            new_val: Some(val_b.clone()),
                        });
                    } else {
                        items.push(HeaderDiffItem {
                            name: key,
                            kind: DiffKind::Modified,
                            old_val: Some(val_a.clone()),
                            new_val: Some(val_b.clone()),
                        });
                    }
                }
                (Some(val_a), None) => {
                    items.push(HeaderDiffItem {
                        name: key,
                        kind: DiffKind::Removed,
                        old_val: Some(val_a.clone()),
                        new_val: None,
                    });
                }
                (None, Some(val_b)) => {
                    items.push(HeaderDiffItem {
                        name: key,
                        kind: DiffKind::Added,
                        old_val: None,
                        new_val: Some(val_b.clone()),
                    });
                }
                (None, None) => {}
            }
        }
        items
    }

    /// Performs deep semantic diffing between two intercepted TLS events.
    pub fn diff_events(
        id_a: usize,
        event_a: &TlsEvent,
        id_b: usize,
        event_b: &TlsEvent,
    ) -> EventDiffResult {
        let headers_a = Self::extract_headers(event_a);
        let headers_b = Self::extract_headers(event_b);
        let header_diffs = Self::diff_headers(&headers_a, &headers_b);

        let body_str_a = Self::extract_body_string(event_a);
        let body_str_b = Self::extract_body_string(event_b);
        let body_diffs = Self::diff_text(&body_str_a, &body_str_b);

        let mut additions = 0;
        let mut deletions = 0;

        for h in &header_diffs {
            match h.kind {
                DiffKind::Added => additions += 1,
                DiffKind::Removed => deletions += 1,
                DiffKind::Modified => {
                    additions += 1;
                    deletions += 1;
                }
                DiffKind::Equal => {}
            }
        }

        for b in &body_diffs {
            match b.kind {
                DiffKind::Added => additions += 1,
                DiffKind::Removed => deletions += 1,
                _ => {}
            }
        }

        EventDiffResult {
            event_a_id: id_a,
            event_b_id: id_b,
            proto_a: event_a.protocol(),
            proto_b: event_b.protocol(),
            dir_a: event_a.direction,
            dir_b: event_b.direction,
            comm_a: event_a.comm.clone(),
            comm_b: event_b.comm.clone(),
            header_diffs,
            body_diffs,
            total_additions: additions,
            total_deletions: deletions,
        }
    }

    fn extract_headers(event: &TlsEvent) -> HashMap<String, String> {
        if let Some(msg) = Http1Parser::parse(&event.data) {
            match msg {
                Http1Message::Request { headers, .. } => return headers,
                Http1Message::Response { headers, .. } => return headers,
            }
        }
        HashMap::new()
    }

    fn extract_body_string(event: &TlsEvent) -> String {
        let raw_body = if let Some(msg) = Http1Parser::parse(&event.data) {
            match msg {
                Http1Message::Request { body, .. } => body,
                Http1Message::Response { body, .. } => body,
            }
        } else {
            event.data.clone()
        };

        if let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(&raw_body) {
            if let Ok(pretty) = serde_json::to_string_pretty(&json_val) {
                return pretty;
            }
        }

        String::from_utf8_lossy(&raw_body).to_string()
    }

    /// Renders the diff as an ANSI colored string for terminal output.
    pub fn format_terminal(diff: &EventDiffResult) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "{}\n",
            format!(
                "=== Diff: Event #{} ({:?} {}) vs Event #{} ({:?} {}) ===",
                diff.event_a_id + 1,
                diff.proto_a,
                diff.comm_a,
                diff.event_b_id + 1,
                diff.proto_b,
                diff.comm_b
            )
            .bold()
            .cyan()
        ));
        out.push_str(&format!(
            "Summary: {} {} {}\n\n",
            format!("+{} additions", diff.total_additions)
                .green()
                .bold(),
            "|".dimmed(),
            format!("-{} deletions", diff.total_deletions).red().bold(),
        ));

        out.push_str(&format!(
            "{}\n",
            "── Headers ────────────────────────".bold().yellow()
        ));
        for h in &diff.header_diffs {
            match h.kind {
                DiffKind::Added => {
                    out.push_str(&format!(
                        "  {} {}: {}\n",
                        "+".green().bold(),
                        h.name.green(),
                        h.new_val.as_deref().unwrap_or("").green()
                    ));
                }
                DiffKind::Removed => {
                    out.push_str(&format!(
                        "  {} {}: {}\n",
                        "-".red().bold(),
                        h.name.red(),
                        h.old_val.as_deref().unwrap_or("").red()
                    ));
                }
                DiffKind::Modified => {
                    out.push_str(&format!(
                        "  {} {}: {} -> {}\n",
                        "~".yellow().bold(),
                        h.name.yellow(),
                        h.old_val.as_deref().unwrap_or("").red(),
                        h.new_val.as_deref().unwrap_or("").green()
                    ));
                }
                DiffKind::Equal => {
                    out.push_str(&format!(
                        "    {}: {}\n",
                        h.name.dimmed(),
                        h.old_val.as_deref().unwrap_or("").dimmed()
                    ));
                }
            }
        }

        out.push_str(&format!(
            "\n{}\n",
            "── Body / Payload ─────────────────".bold().yellow()
        ));
        for b in &diff.body_diffs {
            match b.kind {
                DiffKind::Added => {
                    out.push_str(&format!("+ {}\n", b.content).green().to_string());
                }
                DiffKind::Removed => {
                    out.push_str(&format!("- {}\n", b.content).red().to_string());
                }
                DiffKind::Equal => {
                    out.push_str(&format!("  {}\n", b.content).dimmed().to_string());
                }
                _ => {}
            }
        }

        out
    }

    /// Generates Ratatui Lines for rendering inside TUI Cockpit.
    pub fn to_ratatui_lines(diff: &EventDiffResult) -> Vec<Line<'static>> {
        let mut lines = Vec::new();

        lines.push(Line::from(vec![
            Span::styled(
                "Diff: ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("#{} ({})", diff.event_a_id + 1, diff.comm_a),
                Style::default().fg(Color::Yellow),
            ),
            Span::raw(" vs "),
            Span::styled(
                format!("#{} ({})", diff.event_b_id + 1, diff.comm_b),
                Style::default().fg(Color::Green),
            ),
            Span::raw(" | "),
            Span::styled(
                format!("+{}", diff.total_additions),
                Style::default()
                    .fg(Color::LightGreen)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(
                format!("-{}", diff.total_deletions),
                Style::default()
                    .fg(Color::LightRed)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(Line::from(""));

        lines.push(Line::from(Span::styled(
            "── Headers ──",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )));
        for h in &diff.header_diffs {
            match h.kind {
                DiffKind::Added => {
                    lines.push(Line::from(vec![
                        Span::styled(
                            "+ ",
                            Style::default()
                                .fg(Color::LightGreen)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!("{}: ", h.name),
                            Style::default().fg(Color::LightGreen),
                        ),
                        Span::styled(
                            h.new_val.clone().unwrap_or_default(),
                            Style::default().fg(Color::White),
                        ),
                    ]));
                }
                DiffKind::Removed => {
                    lines.push(Line::from(vec![
                        Span::styled(
                            "- ",
                            Style::default()
                                .fg(Color::LightRed)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!("{}: ", h.name),
                            Style::default().fg(Color::LightRed),
                        ),
                        Span::styled(
                            h.old_val.clone().unwrap_or_default(),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ]));
                }
                DiffKind::Modified => {
                    lines.push(Line::from(vec![
                        Span::styled(
                            "~ ",
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(format!("{}: ", h.name), Style::default().fg(Color::Yellow)),
                        Span::styled(
                            format!("{} ", h.old_val.clone().unwrap_or_default()),
                            Style::default().fg(Color::LightRed),
                        ),
                        Span::raw("-> "),
                        Span::styled(
                            h.new_val.clone().unwrap_or_default(),
                            Style::default().fg(Color::LightGreen),
                        ),
                    ]));
                }
                DiffKind::Equal => {
                    lines.push(Line::from(vec![
                        Span::raw("  "),
                        Span::styled(
                            format!("{}: ", h.name),
                            Style::default().fg(Color::DarkGray),
                        ),
                        Span::styled(
                            h.old_val.clone().unwrap_or_default(),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ]));
                }
            }
        }

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "── Body / Payload ──",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )));
        for b in &diff.body_diffs {
            match b.kind {
                DiffKind::Added => {
                    lines.push(Line::from(vec![
                        Span::styled(
                            "+ ",
                            Style::default()
                                .fg(Color::LightGreen)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(b.content.clone(), Style::default().fg(Color::LightGreen)),
                    ]));
                }
                DiffKind::Removed => {
                    lines.push(Line::from(vec![
                        Span::styled(
                            "- ",
                            Style::default()
                                .fg(Color::LightRed)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(b.content.clone(), Style::default().fg(Color::LightRed)),
                    ]));
                }
                DiffKind::Equal => {
                    lines.push(Line::from(vec![
                        Span::raw("  "),
                        Span::styled(b.content.clone(), Style::default().fg(Color::DarkGray)),
                    ]));
                }
                _ => {}
            }
        }

        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_text_simple() {
        let a = "line1\nline2\nline3";
        let b = "line1\nline2_modified\nline3\nline4";

        let diff = DiffEngine::diff_text(a, b);
        let added: Vec<&DiffLine> = diff.iter().filter(|d| d.kind == DiffKind::Added).collect();
        let removed: Vec<&DiffLine> = diff
            .iter()
            .filter(|d| d.kind == DiffKind::Removed)
            .collect();

        assert_eq!(added.len(), 2); // line2_modified and line4
        assert_eq!(removed.len(), 1); // line2
    }

    #[test]
    fn test_diff_headers() {
        let mut h_a = HashMap::new();
        h_a.insert("host".to_string(), "api.test.com".to_string());
        h_a.insert("authorization".to_string(), "Bearer tokenA".to_string());
        h_a.insert("user-agent".to_string(), "curl/7.88".to_string());

        let mut h_b = HashMap::new();
        h_b.insert("host".to_string(), "api.test.com".to_string());
        h_b.insert("authorization".to_string(), "Bearer tokenB".to_string());
        h_b.insert("x-custom-trace".to_string(), "12345".to_string());

        let diffs = DiffEngine::diff_headers(&h_a, &h_b);

        let modified = diffs.iter().find(|h| h.name == "authorization").unwrap();
        assert_eq!(modified.kind, DiffKind::Modified);

        let removed = diffs.iter().find(|h| h.name == "user-agent").unwrap();
        assert_eq!(removed.kind, DiffKind::Removed);

        let added = diffs.iter().find(|h| h.name == "x-custom-trace").unwrap();
        assert_eq!(added.kind, DiffKind::Added);

        let equal = diffs.iter().find(|h| h.name == "host").unwrap();
        assert_eq!(equal.kind, DiffKind::Equal);
    }
}
