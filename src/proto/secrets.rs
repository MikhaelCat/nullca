//! Automated Secret, Credential, JWT & Token Dissector.
//!
//! Scans intercepted request/response headers and body buffers for sensitive tokens,
//! automatically decodes JWT claims, Base64 Basic Auth credentials, API keys, and CTF flags.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretKind {
    JwtToken,
    BasicAuthCredentials,
    AwsAccessKey,
    GitHubToken,
    StripeApiKey,
    SlackToken,
    PrivateKey,
    CtfFlag,
    GenericBearerToken,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedSecret {
    pub kind: SecretKind,
    pub raw_token: String,
    pub decoded_details: Option<String>,
    pub location: String,
}

pub struct SecretDetector {
    jwt_regex: Regex,
    basic_regex: Regex,
    aws_regex: Regex,
    github_regex: Regex,
    stripe_regex: Regex,
    slack_regex: Regex,
    privkey_regex: Regex,
    ctf_flag_regex: Regex,
}

static GLOBAL_SECRET_DETECTOR: std::sync::OnceLock<SecretDetector> = std::sync::OnceLock::new();

impl SecretDetector {
    pub fn new() -> Self {
        Self {
            jwt_regex: Regex::new(
                r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            )
            .unwrap(),
            basic_regex: Regex::new(r"(?i)Basic\s+([A-Za-z0-9+/=]{8,})").unwrap(),
            aws_regex: Regex::new(r"\b(AKIA[0-9A-Z]{16})\b").unwrap(),
            github_regex: Regex::new(r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b")
                .unwrap(),
            stripe_regex: Regex::new(r"\b(sk_live_[0-9a-zA-Z]{24})\b").unwrap(),
            slack_regex: Regex::new(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b").unwrap(),
            privkey_regex: Regex::new(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----").unwrap(),
            ctf_flag_regex: Regex::new(
                r"(?i)(flag\{[^\{\}]{4,64}\}|THEM\{[^\{\}]{4,64}\}|ctf\{[^\{\}]{4,64}\})",
            )
            .unwrap(),
        }
    }
}

impl Default for SecretDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDetector {
    /// Scans a byte payload for all detectable secrets and credentials.
    pub fn scan_payload(&self, data: &[u8]) -> Vec<DetectedSecret> {
        let text = String::from_utf8_lossy(data);
        let mut results = Vec::new();

        // 1. Detect JWT Tokens & decode claims
        for mat in self.jwt_regex.find_iter(&text) {
            let token = mat.as_str();
            let decoded = decode_jwt_payload(token);
            results.push(DetectedSecret {
                kind: SecretKind::JwtToken,
                raw_token: token.to_string(),
                decoded_details: decoded,
                location: format!("Offset: {}", mat.start()),
            });
        }

        // 2. Detect HTTP Basic Auth credentials
        for cap in self.basic_regex.captures_iter(&text) {
            if let Some(m) = cap.get(1) {
                let b64 = m.as_str();
                let decoded = decode_basic_auth(b64);
                results.push(DetectedSecret {
                    kind: SecretKind::BasicAuthCredentials,
                    raw_token: format!("Basic {}", b64),
                    decoded_details: decoded,
                    location: format!("Offset: {}", m.start()),
                });
            }
        }

        // 3. AWS Access Keys
        for mat in self.aws_regex.find_iter(&text) {
            results.push(DetectedSecret {
                kind: SecretKind::AwsAccessKey,
                raw_token: mat.as_str().to_string(),
                decoded_details: Some("AWS IAM Access Key ID".into()),
                location: format!("Offset: {}", mat.start()),
            });
        }

        // 4. GitHub Personal Access Tokens
        for mat in self.github_regex.find_iter(&text) {
            results.push(DetectedSecret {
                kind: SecretKind::GitHubToken,
                raw_token: mat.as_str().to_string(),
                decoded_details: Some("GitHub Personal Access Token".into()),
                location: format!("Offset: {}", mat.start()),
            });
        }

        // 5. Stripe Secret Keys
        for mat in self.stripe_regex.find_iter(&text) {
            results.push(DetectedSecret {
                kind: SecretKind::StripeApiKey,
                raw_token: mat.as_str().to_string(),
                decoded_details: Some("Stripe Live Secret Key".into()),
                location: format!("Offset: {}", mat.start()),
            });
        }

        // 6. Slack Tokens
        for mat in self.slack_regex.find_iter(&text) {
            results.push(DetectedSecret {
                kind: SecretKind::SlackToken,
                raw_token: mat.as_str().to_string(),
                decoded_details: Some("Slack OAuth/Bot Token".into()),
                location: format!("Offset: {}", mat.start()),
            });
        }

        // 7. Private Keys
        for mat in self.privkey_regex.find_iter(&text) {
            results.push(DetectedSecret {
                kind: SecretKind::PrivateKey,
                raw_token: mat.as_str().to_string(),
                decoded_details: Some("Exposed Cryptographic Private Key".into()),
                location: format!("Offset: {}", mat.start()),
            });
        }

        // 8. CTF Flags
        for mat in self.ctf_flag_regex.find_iter(&text) {
            results.push(DetectedSecret {
                kind: SecretKind::CtfFlag,
                raw_token: mat.as_str().to_string(),
                decoded_details: Some("Captured CTF Competition Flag".into()),
                location: format!("Offset: {}", mat.start()),
            });
        }

        results
    }
}

pub fn scan_secrets(data: &[u8]) -> Vec<DetectedSecret> {
    GLOBAL_SECRET_DETECTOR
        .get_or_init(SecretDetector::new)
        .scan_payload(data)
}

/// Decodes header and payload of a JWT without verifying signature.
fn decode_jwt_payload(jwt: &str) -> Option<String> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() < 2 {
        return None;
    }

    let decode_part = |part: &str| -> Option<String> {
        // Pad to multiple of 4 with '='
        let mut padded = part.to_string();
        while !padded.len().is_multiple_of(4) {
            padded.push('=');
        }
        let bytes = URL_SAFE_NO_PAD.decode(part).ok().or_else(|| {
            base64::engine::general_purpose::STANDARD
                .decode(&padded)
                .ok()
        })?;
        String::from_utf8(bytes).ok()
    };

    let header_json = decode_part(parts[0])?;
    let payload_json = decode_part(parts[1])?;

    // Prettify JSON if possible
    let header_pretty = serde_json::from_str::<serde_json::Value>(&header_json)
        .and_then(|v| serde_json::to_string_pretty(&v))
        .unwrap_or(header_json);

    let payload_pretty = serde_json::from_str::<serde_json::Value>(&payload_json)
        .and_then(|v| serde_json::to_string_pretty(&v))
        .unwrap_or(payload_json);

    Some(format!(
        "HEADER:\n{}\n\nCLAIMS (PAYLOAD):\n{}",
        header_pretty, payload_pretty
    ))
}

/// Decodes HTTP Basic Auth base64 string.
fn decode_basic_auth(b64: &str) -> Option<String> {
    let mut padded = b64.to_string();
    while !padded.len().is_multiple_of(4) {
        padded.push('=');
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(padded)
        .ok()?;
    let creds = String::from_utf8(bytes).ok()?;
    if let Some((user, pass)) = creds.split_once(':') {
        Some(format!("Username: '{}', Password: '{}'", user, pass))
    } else {
        Some(creds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_jwt_token() {
        // Sample standard JWT: {"alg":"HS256","typ":"JWT"}.{"sub":"1234567890","name":"Mikhail","admin":true}
        let sample_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ik1pa2hhaWwiLCJhZG1pbiI6dHJ1ZX0.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
        let payload = format!("Authorization: Bearer {}", sample_jwt);

        let secrets = scan_secrets(payload.as_bytes());
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].kind, SecretKind::JwtToken);
        let details = secrets[0].decoded_details.as_ref().unwrap();
        assert!(details.contains("\"name\": \"Mikhail\""));
        assert!(details.contains("\"admin\": true"));
    }

    #[test]
    fn test_detect_basic_auth_and_flag() {
        let payload = b"Authorization: Basic YWRtaW46cGFzc3dvcmQxMjM=\r\nCookie: flag{super_secret_ctf_win_1337}";
        let secrets = scan_secrets(payload);
        assert_eq!(secrets.len(), 2);
        assert!(secrets
            .iter()
            .any(|s| s.kind == SecretKind::BasicAuthCredentials));
        assert!(secrets.iter().any(|s| s.kind == SecretKind::CtfFlag));
    }
}
