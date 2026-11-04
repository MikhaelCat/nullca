//! Packet & Stream Filter Domain-Specific Language (DSL).
//!
//! Evaluates expressions in memory at wire speed:
//! e.g. `proto == "http2" && status >= 400 || body contains "auth"`

use crate::engine::event::TlsEvent;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum FilterError {
    #[error("Unexpected token: {0}")]
    UnexpectedToken(String),
    #[error("Unexpected end of expression")]
    UnexpectedEof,
    #[error("Unmatched parenthesis")]
    UnmatchedParen,
    #[error("Invalid comparison operator: {0}")]
    InvalidOperator(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Ident(String),
    StringLit(String),
    Number(i64),
    Eq,       // ==
    NotEq,    // !=
    Lt,       // <
    Lte,      // <=
    Gt,       // >
    Gte,      // >=
    Contains, // contains
    And,      // &&
    Or,       // ||
    Not,      // !
    LParen,   // (
    RParen,   // )
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Binary(Box<Expr>, BinaryOp, Box<Expr>),
    Unary(UnaryOp, Box<Expr>),
    Comparison(String, CompOp, Value),
    AlwaysTrue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOp {
    And,
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    Not,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompOp {
    Eq,
    NotEq,
    Lt,
    Lte,
    Gt,
    Gte,
    Contains,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    String(String),
    Number(i64),
}

/// Tokenizer for filter query string.
pub fn tokenize(input: &str) -> Result<Vec<Token>, FilterError> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            ' ' | '\t' | '\r' | '\n' => {
                i += 1;
            }
            '(' => {
                tokens.push(Token::LParen);
                i += 1;
            }
            ')' => {
                tokens.push(Token::RParen);
                i += 1;
            }
            '!' => {
                if i + 1 < chars.len() && chars[i + 1] == '=' {
                    tokens.push(Token::NotEq);
                    i += 2;
                } else {
                    tokens.push(Token::Not);
                    i += 1;
                }
            }
            '=' => {
                if i + 1 < chars.len() && chars[i + 1] == '=' {
                    tokens.push(Token::Eq);
                    i += 2;
                } else {
                    return Err(FilterError::InvalidOperator("=".into()));
                }
            }
            '<' => {
                if i + 1 < chars.len() && chars[i + 1] == '=' {
                    tokens.push(Token::Lte);
                    i += 2;
                } else {
                    tokens.push(Token::Lt);
                    i += 1;
                }
            }
            '>' => {
                if i + 1 < chars.len() && chars[i + 1] == '=' {
                    tokens.push(Token::Gte);
                    i += 2;
                } else {
                    tokens.push(Token::Gt);
                    i += 1;
                }
            }
            '&' => {
                if i + 1 < chars.len() && chars[i + 1] == '&' {
                    tokens.push(Token::And);
                    i += 2;
                } else {
                    return Err(FilterError::InvalidOperator("&".into()));
                }
            }
            '|' => {
                if i + 1 < chars.len() && chars[i + 1] == '|' {
                    tokens.push(Token::Or);
                    i += 2;
                } else {
                    return Err(FilterError::InvalidOperator("|".into()));
                }
            }
            '"' | '\'' => {
                let quote = chars[i];
                i += 1;
                let mut s = String::new();
                while i < chars.len() && chars[i] != quote {
                    s.push(chars[i]);
                    i += 1;
                }
                if i < chars.len() {
                    i += 1; // skip closing quote
                }
                tokens.push(Token::StringLit(s));
            }
            c if c.is_ascii_digit() => {
                let mut num_str = String::new();
                while i < chars.len() && chars[i].is_ascii_digit() {
                    num_str.push(chars[i]);
                    i += 1;
                }
                let n: i64 = num_str.parse().unwrap_or(0);
                tokens.push(Token::Number(n));
            }
            c if c.is_alphabetic() || c == '_' => {
                let mut ident = String::new();
                while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == '-') {
                    ident.push(chars[i]);
                    i += 1;
                }
                match ident.as_str() {
                    "and" => tokens.push(Token::And),
                    "or" => tokens.push(Token::Or),
                    "not" => tokens.push(Token::Not),
                    "contains" => tokens.push(Token::Contains),
                    _ => tokens.push(Token::Ident(ident)),
                }
            }
            other => return Err(FilterError::UnexpectedToken(other.to_string())),
        }
    }

    Ok(tokens)
}

/// Recursive descent parser for Filter AST.
pub struct FilterParser {
    tokens: Vec<Token>,
    pos: usize,
}

impl FilterParser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    pub fn parse(&mut self) -> Result<Expr, FilterError> {
        if self.tokens.is_empty() {
            return Ok(Expr::AlwaysTrue);
        }
        self.parse_or()
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<Token> {
        if self.pos < self.tokens.len() {
            let tok = self.tokens[self.pos].clone();
            self.pos += 1;
            Some(tok)
        } else {
            None
        }
    }

    fn parse_or(&mut self) -> Result<Expr, FilterError> {
        let mut left = self.parse_and()?;
        while let Some(Token::Or) = self.peek() {
            self.advance();
            let right = self.parse_and()?;
            left = Expr::Binary(Box::new(left), BinaryOp::Or, Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, FilterError> {
        let mut left = self.parse_primary()?;
        while let Some(Token::And) = self.peek() {
            self.advance();
            let right = self.parse_primary()?;
            left = Expr::Binary(Box::new(left), BinaryOp::And, Box::new(right));
        }
        Ok(left)
    }

    fn parse_primary(&mut self) -> Result<Expr, FilterError> {
        match self.peek() {
            Some(Token::Not) => {
                self.advance();
                let expr = self.parse_primary()?;
                Ok(Expr::Unary(UnaryOp::Not, Box::new(expr)))
            }
            Some(Token::LParen) => {
                self.advance();
                let expr = self.parse_or()?;
                if let Some(Token::RParen) = self.advance() {
                    Ok(expr)
                } else {
                    Err(FilterError::UnmatchedParen)
                }
            }
            Some(Token::Ident(_)) => {
                if let Some(Token::Ident(field)) = self.advance() {
                    let op = match self.advance() {
                        Some(Token::Eq) => CompOp::Eq,
                        Some(Token::NotEq) => CompOp::NotEq,
                        Some(Token::Lt) => CompOp::Lt,
                        Some(Token::Lte) => CompOp::Lte,
                        Some(Token::Gt) => CompOp::Gt,
                        Some(Token::Gte) => CompOp::Gte,
                        Some(Token::Contains) => CompOp::Contains,
                        Some(other) => return Err(FilterError::UnexpectedToken(format!("{:?}", other))),
                        None => return Err(FilterError::UnexpectedEof),
                    };

                    let val = match self.advance() {
                        Some(Token::StringLit(s)) => Value::String(s),
                        Some(Token::Number(n)) => Value::Number(n),
                        Some(Token::Ident(s)) => Value::String(s),
                        Some(other) => return Err(FilterError::UnexpectedToken(format!("{:?}", other))),
                        None => return Err(FilterError::UnexpectedEof),
                    };

                    Ok(Expr::Comparison(field, op, val))
                } else {
                    Err(FilterError::UnexpectedEof)
                }
            }
            Some(other) => Err(FilterError::UnexpectedToken(format!("{:?}", other))),
            None => Err(FilterError::UnexpectedEof),
        }
    }
}

/// Compiled Filter Engine that evaluates events.
#[derive(Debug, Clone)]
pub struct FilterEngine {
    ast: Expr,
}

impl FilterEngine {
    pub fn compile(query: &str) -> Result<Self, FilterError> {
        let trimmed = query.trim();
        if trimmed.is_empty() {
            return Ok(Self {
                ast: Expr::AlwaysTrue,
            });
        }
        let tokens = tokenize(trimmed)?;
        let mut parser = FilterParser::new(tokens);
        let ast = parser.parse()?;
        Ok(Self { ast })
    }

    /// Evaluates whether a captured `TlsEvent` satisfies the filter.
    pub fn matches(&self, event: &TlsEvent) -> bool {
        self.eval_expr(&self.ast, event)
    }

    fn eval_expr(&self, expr: &Expr, event: &TlsEvent) -> bool {
        match expr {
            Expr::AlwaysTrue => true,
            Expr::Unary(UnaryOp::Not, inner) => !self.eval_expr(inner, event),
            Expr::Binary(left, BinaryOp::And, right) => {
                self.eval_expr(left, event) && self.eval_expr(right, event)
            }
            Expr::Binary(left, BinaryOp::Or, right) => {
                self.eval_expr(left, event) || self.eval_expr(right, event)
            }
            Expr::Comparison(field, op, val) => self.eval_comp(field, *op, val, event),
        }
    }

    fn eval_comp(&self, field: &str, op: CompOp, val: &Value, event: &TlsEvent) -> bool {
        match field.to_ascii_lowercase().as_str() {
            "pid" => {
                if let Value::Number(n) = val {
                    compare_num(event.pid as i64, op, *n)
                } else {
                    false
                }
            }
            "fd" => {
                if let Value::Number(n) = val {
                    compare_num(event.fd as i64, op, *n)
                } else {
                    false
                }
            }
            "len" | "size" => {
                if let Value::Number(n) = val {
                    compare_num(event.data.len() as i64, op, *n)
                } else {
                    false
                }
            }
            "proto" | "protocol" => {
                let current_proto = format!("{:?}", event.protocol()).to_ascii_lowercase();
                if let Value::String(s) = val {
                    compare_str(&current_proto, op, &s.to_ascii_lowercase())
                } else {
                    false
                }
            }
            "comm" | "process" => {
                if let Value::String(s) = val {
                    compare_str(&event.comm, op, s)
                } else {
                    false
                }
            }
            "body" | "payload" | "data" => {
                let payload_lossy = String::from_utf8_lossy(&event.data);
                if let Value::String(s) = val {
                    compare_str(&payload_lossy, op, s)
                } else {
                    false
                }
            }
            _ => true,
        }
    }
}

fn compare_num(left: i64, op: CompOp, right: i64) -> bool {
    match op {
        CompOp::Eq => left == right,
        CompOp::NotEq => left != right,
        CompOp::Lt => left < right,
        CompOp::Lte => left <= right,
        CompOp::Gt => left > right,
        CompOp::Gte => left >= right,
        CompOp::Contains => left.to_string().contains(&right.to_string()),
    }
}

fn compare_str(left: &str, op: CompOp, right: &str) -> bool {
    match op {
        CompOp::Eq => left.eq_ignore_ascii_case(right),
        CompOp::NotEq => !left.eq_ignore_ascii_case(right),
        CompOp::Contains => left.to_lowercase().contains(&right.to_lowercase()),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::event::Direction;

    #[test]
    fn test_filter_evaluation() {
        let event = TlsEvent::new(
            1000,
            1420,
            1420,
            3,
            Direction::Ingress,
            "curl".into(),
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x01\x01\x05\x00\x00\x00\x01\x82 users".to_vec(),
            None,
        );

        let f1 = FilterEngine::compile("pid == 1420 && proto == 'http2'").unwrap();
        assert!(f1.matches(&event));

        let f2 = FilterEngine::compile("pid == 9999").unwrap();
        assert!(!f2.matches(&event));

        let f3 = FilterEngine::compile("body contains 'users'").unwrap();
        assert!(f3.matches(&event));

        let f4 = FilterEngine::compile("len > 10 && (comm == 'curl' || comm == 'wget')").unwrap();
        assert!(f4.matches(&event));
    }
}
