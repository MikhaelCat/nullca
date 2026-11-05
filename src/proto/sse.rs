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

    /// Parses all complete SSE events from a byte stream per W3C EventSource spec.
    /// Correctly handles both CRLF (\r\n\r\n) and LF (\n\n) event delimiters.
    pub fn parse_stream(data: &[u8]) -> Vec<SseEvent> {
        let text = String::from_utf8_lossy(data);
        let mut events = Vec::new();

        let mut current_event_type = None;
        let mut current_id = None;
        let mut current_retry = None;
        let mut data_lines = Vec::new();

        let dispatch_event = |events: &mut Vec<SseEvent>,
                              event_type: &mut Option<String>,
                              id: &mut Option<String>,
                              retry: &mut Option<u64>,
                              data_lines: &mut Vec<String>| {
            if !data_lines.is_empty() || event_type.is_some() {
                let combined_data = data_lines.join("\n");
                let is_json = (combined_data.starts_with('{') && combined_data.ends_with('}'))
                    || (combined_data.starts_with('[') && combined_data.ends_with(']'));

                events.push(SseEvent {
                    event_type: event_type.take(),
                    id: id.take(),
                    retry_ms: *retry,
                    data: combined_data,
                    is_json,
                });
                data_lines.clear();
            }
        };

        for line in text.lines() {
            let trimmed_line = line.trim_end_matches('\r');
            if trimmed_line.is_empty() {
                // Empty line triggers event dispatch
                dispatch_event(
                    &mut events,
                    &mut current_event_type,
                    &mut current_id,
                    &mut current_retry,
                    &mut data_lines,
                );
                continue;
            }

            if trimmed_line.starts_with(':') {
                // Comment line per W3C spec
                continue;
            }

            if let Some(rest) = trimmed_line.strip_prefix("data:") {
                let d = rest.strip_prefix(' ').unwrap_or(rest);
                data_lines.push(d.to_string());
            } else if let Some(rest) = trimmed_line.strip_prefix("event:") {
                current_event_type = Some(rest.trim().to_string());
            } else if let Some(rest) = trimmed_line.strip_prefix("id:") {
                current_id = Some(rest.trim().to_string());
            } else if let Some(rest) = trimmed_line.strip_prefix("retry:") {
                current_retry = rest.trim().parse::<u64>().ok();
            }
        }

        // Flush any trailing event without terminal newline
        dispatch_event(
            &mut events,
            &mut current_event_type,
            &mut current_id,
            &mut current_retry,
            &mut data_lines,
        );

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
                    let bytes = &ev.data.as_bytes()[start..];
                    let mut i = 0;
                    let mut is_escaped = false;
                    while i < bytes.len() {
                        if is_escaped {
                            is_escaped = false;
                        } else if bytes[i] == b'\\' {
                            is_escaped = true;
                        } else if bytes[i] == b'"' {
                            break;
                        }
                        i += 1;
                    }
                    let token = &ev.data[start..start + i];
                    let unescaped = token
                        .replace("\\n", "\n")
                        .replace("\\\"", "\"")
                        .replace("\\\\", "\\")
                        .replace("\\t", "\t");
                    accumulated.push_str(&unescaped);
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

    #[test]
    fn test_openai_streaming_token_with_escaped_quotes() {
        let raw = br#"data: {"choices":[{"delta":{"content":"She said: \"Hello!\"\n"}}]}"#;
        let events = SseParser::parse_stream(raw);
        assert_eq!(events.len(), 1);
        let extracted = SseParser::extract_ai_stream_text(&events);
        assert_eq!(extracted, "She said: \"Hello!\"\n");
    }

    #[test]
    fn test_crlf_delimited_sse_stream() {
        let raw = b": comment\r\ndata: event1\r\n\r\n: comment2\r\nevent: custom\r\ndata: line1\r\ndata: line2\r\n\r\n";
        let events = SseParser::parse_stream(raw);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].data, "event1");
        assert_eq!(events[0].event_type, None);
        assert_eq!(events[1].data, "line1\nline2");
        assert_eq!(events[1].event_type.as_deref(), Some("custom"));
    }
}
