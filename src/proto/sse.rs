//! Server-Sent Events (SSE) & LLM Streaming Dissector (W3C EventSource).
//!
//! Parses real-time `text/event-stream` payloads commonly used by OpenAI, Anthropic,
//! Ollama, and reactive APIs, extracting event types, IDs, and multi-line AI tokens.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub event_type: Option<String>,
    pub id: Option<String>,
    pub retry_ms: Option<u64>,
    pub data: String,
    pub is_json: bool,
}

pub struct SseParser;

impl SseParser {
    /// Heuristic detector to determine if bytes match an SSE event stream.
    pub fn is_probable_sse(data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        let text = String::from_utf8_lossy(data);
        text.starts_with("data:")
            || text.starts_with("event:")
            || text.starts_with(": ")
            || text.contains("\ndata:")
            || text.contains("\r\ndata:")
    }

    /// Parses all complete SSE events from a byte stream.
    pub fn parse_stream(data: &[u8]) -> Vec<SseEvent> {
        let text = String::from_utf8_lossy(data);
        let mut events = Vec::new();

        // Normalized message splitting by double newline (\n\n or \r\n\r\n)
        let blocks = text.split("\n\n");

        for block in blocks {
            let trimmed_block = block.trim();
            if trimmed_block.is_empty() {
                continue;
            }

            let mut current_event_type = None;
            let mut current_id = None;
            let mut current_retry = None;
            let mut data_lines = Vec::new();

            for line in block.lines() {
                let trimmed_line = line.trim_end_matches('\r');
                if trimmed_line.is_empty() || trimmed_line.starts_with(':') {
                    // Comment or blank line
                    continue;
                }

                if let Some(rest) = trimmed_line.strip_prefix("data:") {
                    let d = rest.strip_prefix(' ').unwrap_or(rest);
                    data_lines.push(d);
                } else if let Some(rest) = trimmed_line.strip_prefix("event:") {
                    current_event_type = Some(rest.trim().to_string());
                } else if let Some(rest) = trimmed_line.strip_prefix("id:") {
                    current_id = Some(rest.trim().to_string());
                } else if let Some(rest) = trimmed_line.strip_prefix("retry:") {
                    current_retry = rest.trim().parse::<u64>().ok();
                }
            }

            if !data_lines.is_empty() || current_event_type.is_some() {
                let combined_data = data_lines.join("\n");
                let is_json = (combined_data.starts_with('{') && combined_data.ends_with('}'))
                    || (combined_data.starts_with('[') && combined_data.ends_with(']'));

                events.push(SseEvent {
                    event_type: current_event_type,
                    id: current_id,
                    retry_ms: current_retry,
                    data: combined_data,
                    is_json,
                });
            }
        }

        events
    }

    /// Extracts accumulated AI token text from OpenAI / Claude streaming chunks.
    pub fn extract_ai_stream_text(events: &[SseEvent]) -> String {
        let mut accumulated = String::new();

        for ev in events {
            if ev.data == "[DONE]" {
                break;
            }
            if ev.is_json {
                // Heuristic JSON content extraction: find "content":"..." or "delta":{"content":"..."}
                if let Some(pos) = ev.data.find("\"content\":\"") {
                    let start = pos + 11;
                    if let Some(end) = ev.data[start..].find('"') {
                        let token = &ev.data[start..start + end];
                        // Unescape common json escapes
                        let unescaped = token.replace("\\n", "\n").replace("\\\"", "\"");
                        accumulated.push_str(&unescaped);
                    }
                }
            } else if !ev.data.is_empty() {
                accumulated.push_str(&ev.data);
            }
        }

        accumulated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_standard_sse_events() {
        let raw = b": ping keepalive\nevent: user_login\nid: 42\ndata: {\"user\":\"alice\"}\n\n: another comment\nevent: message\ndata: First line\ndata: Second line\n\n";

        let events = SseParser::parse_stream(raw);
        assert_eq!(events.len(), 2);

        assert_eq!(events[0].event_type.as_deref(), Some("user_login"));
        assert_eq!(events[0].id.as_deref(), Some("42"));
        assert_eq!(events[0].data, "{\"user\":\"alice\"}");
        assert!(events[0].is_json);

        assert_eq!(events[1].event_type.as_deref(), Some("message"));
        assert_eq!(events[1].data, "First line\nSecond line");
        assert!(!events[1].is_json);
    }

    #[test]
    fn test_openai_chatgpt_streaming_token_assembly() {
        let raw = b"data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\ndata: {\"id\":\"chatcmpl-1\",\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n\ndata: {\"id\":\"chatcmpl-1\",\"choices\":[{\"delta\":{\"content\":\"!\"}}]}\n\ndata: [DONE]\n\n";

        let events = SseParser::parse_stream(raw);
        assert_eq!(events.len(), 4);
        assert_eq!(events[3].data, "[DONE]");

        let full_text = SseParser::extract_ai_stream_text(&events);
        assert_eq!(full_text, "Hello world!");
    }
}
