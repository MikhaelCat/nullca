//! Non-HTTP Protocol Dissectors: Redis (RESP), PostgreSQL / MySQL, and SMTP Mail over TLS.
//!
//! Enables zero-CA decrypted inspection of database queries, cache operations, and mail exchanges.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DatabaseProtocol {
    Redis(RedisCommand),
    PostgresQuery(String),
    MysqlQuery(String),
    SmtpCommand(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisCommand {
    pub command: String,
    pub args: Vec<String>,
}

pub struct NonHttpDissector;

impl NonHttpDissector {
    /// Attempts to parse decrypted payload as Redis Serialization Protocol (RESP).
    pub fn parse_redis(data: &[u8]) -> Option<RedisCommand> {
        if data.is_empty() {
            return None;
        }

        let text = std::str::from_utf8(data).ok()?;

        // RESP Array: *<count>\r\n...
        if text.starts_with('*') {
            let mut lines = text.split("\r\n");
            let count_line = lines.next()?;
            let count: usize = count_line[1..].parse().ok()?;

            let mut parts = Vec::new();
            while let Some(line) = lines.next() {
                if line.starts_with('$') {
                    // Next line is bulk string payload
                    if let Some(payload) = lines.next() {
                        parts.push(payload.to_string());
                    }
                } else if !line.is_empty() && !line.starts_with('*') {
                    parts.push(line.to_string());
                }
                if parts.len() >= count {
                    break;
                }
            }

            if !parts.is_empty() {
                let command = parts[0].to_uppercase();
                let args = parts[1..].to_vec();
                return Some(RedisCommand { command, args });
            }
        }

        // Inline Redis command: PING, AUTH, GET, SET...
        let first_line = text.lines().next()?.trim();
        let tokens: Vec<&str> = first_line.split_whitespace().collect();
        if !tokens.is_empty() {
            let cmd = tokens[0].to_uppercase();
            let known_cmds = [
                "PING", "AUTH", "GET", "SET", "DEL", "HGET", "HSET", "INFO", "SELECT", "EXPIRE",
                "TTL", "KEYS", "SUBSCRIBE", "PUBLISH",
            ];
            if known_cmds.contains(&cmd.as_str()) {
                return Some(RedisCommand {
                    command: cmd,
                    args: tokens[1..].iter().map(|s| s.to_string()).collect(),
                });
            }
        }

        None
    }

    /// Attempts to detect and parse PostgreSQL SQL Query frames.
    pub fn parse_postgres(data: &[u8]) -> Option<String> {
        // PostgreSQL frontend 'Q' (Simple Query): 'Q' (0x51) followed by 4-byte length and null-terminated string
        if data.len() >= 6 && data[0] == b'Q' {
            let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            if len >= 4 && data.len() > len {
                let query_bytes = &data[5..1 + len];
                let text = String::from_utf8_lossy(query_bytes)
                    .trim_matches('\0')
                    .trim()
                    .to_string();
                if !text.is_empty() {
                    return Some(text);
                }
            }
        }
        None
    }

    /// Attempts to detect SMTP mail commands over TLS.
    pub fn parse_smtp(data: &[u8]) -> Option<String> {
        let text = std::str::from_utf8(data).ok()?;
        let first_line = text.lines().next()?.trim();
        let upper = first_line.to_uppercase();

        let smtp_prefixes = [
            "EHLO ", "HELO ", "MAIL FROM:", "RCPT TO:", "AUTH LOGIN", "AUTH PLAIN", "DATA",
            "QUIT", "220 ", "250 ", "354 ", "550 ",
        ];

        for prefix in smtp_prefixes {
            if upper.starts_with(prefix) {
                return Some(first_line.to_string());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_redis_resp_array() {
        let resp = b"*3\r\n$3\r\nSET\r\n$8\r\nusername\r\n$5\r\nalice\r\n";
        let cmd = NonHttpDissector::parse_redis(resp).expect("Should parse Redis SET");
        assert_eq!(cmd.command, "SET");
        assert_eq!(cmd.args, vec!["username", "alice"]);
    }

    #[test]
    fn test_parse_postgres_query() {
        let mut pg_wire = vec![b'Q'];
        let query = "SELECT id, email FROM users WHERE active = true;\0";
        let len = (4 + query.len()) as u32;
        pg_wire.extend_from_slice(&len.to_be_bytes());
        pg_wire.extend_from_slice(query.as_bytes());

        let q = NonHttpDissector::parse_postgres(&pg_wire).expect("Should parse Postgres query");
        assert_eq!(q, "SELECT id, email FROM users WHERE active = true;");
    }

    #[test]
    fn test_parse_smtp_command() {
        let smtp = b"EHLO mail.security.corp\r\n";
        let line = NonHttpDissector::parse_smtp(smtp).expect("Should parse SMTP");
        assert_eq!(line, "EHLO mail.security.corp");
    }
}
