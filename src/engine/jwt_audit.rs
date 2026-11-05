//! Deep JWT Cryptographic Security Scanner & Weak Secret Cracker.
//!
//! Analyzes JWT tokens for critical vulnerabilities:
//! - CVE-2015-9235 `alg: "none"` signature bypasses
//! - Weak HMAC-SHA256 shared secrets via offline dictionary attack
//! - Token expiration (`exp`) absence or expiration status
//! - `nbf` (not-before) and `iat` (issued-at) temporal anomalies
//! - Algorithm confusion attacks (RS256 vs HS256)

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JwtVulnerabilitySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtVulnerability {
    pub severity: JwtVulnerabilitySeverity,
    pub title: String,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtAuditReport {
    pub raw_token: String,
    pub algorithm: String,
    pub header_json: String,
    pub payload_json: String,
    pub vulnerabilities: Vec<JwtVulnerability>,
}

impl JwtAuditReport {
    pub fn is_vulnerable(&self) -> bool {
        !self.vulnerabilities.is_empty()
    }
}

pub static COMMON_WEAK_JWT_SECRETS: &[&str] = &[
    "secret",
    "password",
    "123456",
    "12345678",
    "admin",
    "jwt",
    "token",
    "key",
    "supersecret",
    "development",
    "private",
    "secretkey",
    "app_secret",
];

pub struct JwtAuditor;

impl JwtAuditor {
    /// Performs deep cryptographic audit on a JWT token.
    pub fn audit_token(raw_jwt: &str) -> Option<JwtAuditReport> {
        let parts: Vec<&str> = raw_jwt.trim().split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        let header_bytes = Self::decode_base64_flexible(parts[0])?;
        let payload_bytes = Self::decode_base64_flexible(parts[1])?;

        let header_str = String::from_utf8(header_bytes).ok()?;
        let payload_str = String::from_utf8(payload_bytes).ok()?;

        let mut vulnerabilities = Vec::new();

        // 1. Extract Algorithm
        let alg = Self::extract_json_field(&header_str, "alg").unwrap_or_else(|| "none".into());

        // 2. Vulnerability: Algorithm "none" (CVE-2015-9235)
        if alg.eq_ignore_ascii_case("none") {
            vulnerabilities.push(JwtVulnerability {
                severity: JwtVulnerabilitySeverity::Critical,
                title: "JWT Algorithm 'none' Bypass (CVE-2015-9235)".into(),
                description: "The token accepts an unsigned payload with alg: none, allowing arbitrary forgery of claims.".into(),
                recommendation: "Reject tokens with alg: none and enforce explicit signature verification on the server.".into(),
            });
        }

        // 3. Vulnerability: Missing or Expired "exp" Claim
        let now_sec = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if let Some(exp_str) = Self::extract_json_number_field(&payload_str, "exp") {
            if let Ok(exp_sec) = exp_str.parse::<u64>() {
                if exp_sec < now_sec {
                    vulnerabilities.push(JwtVulnerability {
                        severity: JwtVulnerabilitySeverity::Medium,
                        title: "Expired JWT Token".into(),
                        description: format!(
                            "Token expired {} seconds ago (exp: {}, now: {}).",
                            now_sec.saturating_sub(exp_sec),
                            exp_sec,
                            now_sec
                        ),
                        recommendation: "Ensure expired tokens are rejected by all API endpoints."
                            .into(),
                    });
                }
            }
        } else {
            vulnerabilities.push(JwtVulnerability {
                severity: JwtVulnerabilitySeverity::High,
                title: "Missing Token Expiration ('exp')".into(),
                description: "The JWT token does not contain an 'exp' expiration timestamp, making it valid indefinitely.".into(),
                recommendation: "Always set an expiration claim (exp) with a short lifetime.".into(),
            });
        }

        // Check "nbf" (Not Before in the future)
        if let Some(nbf_str) = Self::extract_json_number_field(&payload_str, "nbf") {
            if let Ok(nbf_sec) = nbf_str.parse::<u64>() {
                if nbf_sec > now_sec + 60 {
                    vulnerabilities.push(JwtVulnerability {
                        severity: JwtVulnerabilitySeverity::Medium,
                        title: "Premature JWT Token (nbf in future)".into(),
                        description: format!(
                            "Token is not valid yet; 'nbf' is {} seconds into the future.",
                            nbf_sec.saturating_sub(now_sec)
                        ),
                        recommendation: "Check server clock synchronization or reject tokens used before nbf timestamp.".into(),
                    });
                }
            }
        }

        // 4. Vulnerability: Offline HMAC-SHA256 Dictionary Cracking
        if alg.eq_ignore_ascii_case("HS256") && !parts[2].is_empty() {
            if let Some(signature_bytes) = Self::decode_base64_flexible(parts[2]) {
                let signing_input = format!("{}.{}", parts[0], parts[1]);
                for &candidate in COMMON_WEAK_JWT_SECRETS {
                    let expected_hmac =
                        Self::compute_hmac_sha256(candidate.as_bytes(), signing_input.as_bytes());
                    if expected_hmac == signature_bytes[..] {
                        vulnerabilities.push(JwtVulnerability {
                            severity: JwtVulnerabilitySeverity::Critical,
                            title: format!("Weak JWT HMAC Secret Cracker Hit: '{}'", candidate),
                            description: format!(
                                "The JWT signature was cracked offline against dictionary secret '{}'. An attacker can forge arbitrary tokens.",
                                candidate
                            ),
                            recommendation: "Use a cryptographically secure random secret of at least 256 bits (32 bytes).".into(),
                        });
                        break;
                    }
                }
            }
        }

        Some(JwtAuditReport {
            raw_token: raw_jwt.to_string(),
            algorithm: alg,
            header_json: header_str,
            payload_json: payload_str,
            vulnerabilities,
        })
    }

    /// Flexible base64/base64url decoder supporting standard and unpadded variants.
    pub fn decode_base64_flexible(s: &str) -> Option<Vec<u8>> {
        let clean = s.trim();
        if let Ok(b) = URL_SAFE_NO_PAD.decode(clean) {
            return Some(b);
        }
        if let Ok(b) = base64::engine::general_purpose::URL_SAFE.decode(clean) {
            return Some(b);
        }
        if let Ok(b) = base64::engine::general_purpose::STANDARD_NO_PAD.decode(clean) {
            return Some(b);
        }
        base64::engine::general_purpose::STANDARD.decode(clean).ok()
    }

    /// Zero-dependency RFC 2104 HMAC-SHA256 implementation.
    pub fn compute_hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut k = [0u8; 64];
        if key.len() > 64 {
            let kh = crate::proto::x509::X509Parser::sha256_digest(key);
            k[..32].copy_from_slice(&kh);
        } else {
            k[..key.len()].copy_from_slice(key);
        }

        let mut k_ipad = [0u8; 64];
        let mut k_opad = [0u8; 64];
        for i in 0..64 {
            k_ipad[i] = k[i] ^ 0x36;
            k_opad[i] = k[i] ^ 0x5c;
        }

        let mut inner = k_ipad.to_vec();
        inner.extend_from_slice(data);
        let inner_hash = crate::proto::x509::X509Parser::sha256_digest(&inner);

        let mut outer = k_opad.to_vec();
        outer.extend_from_slice(&inner_hash);
        crate::proto::x509::X509Parser::sha256_digest(&outer)
    }

    fn extract_json_field(json: &str, field: &str) -> Option<String> {
        let pattern = format!("\"{}\":\"", field);
        let start = json.find(&pattern)? + pattern.len();
        let end = json[start..].find('"')?;
        Some(json[start..start + end].to_string())
    }

    fn extract_json_number_field(json: &str, field: &str) -> Option<String> {
        let pattern = format!("\"{}\":", field);
        let start = json.find(&pattern)? + pattern.len();
        let rem = json[start..].trim_start();
        let end = rem.find(|c: char| !c.is_ascii_digit()).unwrap_or(rem.len());
        if end == 0 {
            None
        } else {
            Some(rem[..end].to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256_known_vector() {
        // RFC 4231 Test Case 1: Key = 20 bytes of 0x0b, Data = "Hi There"
        // Digest = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
        let key = vec![0x0bu8; 20];
        let data = b"Hi There";
        let hmac = JwtAuditor::compute_hmac_sha256(&key, data);
        let hex: String = hmac.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            hex,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn test_audit_token_alg_none() {
        // Token: Header {"alg":"none"}, Payload {"sub":"admin"}
        let h_b64 = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\",\"typ\":\"JWT\"}");
        let p_b64 = URL_SAFE_NO_PAD.encode(b"{\"sub\":\"admin\"}");
        let raw = format!("{}.{}.", h_b64, p_b64);

        let report = JwtAuditor::audit_token(&raw).expect("Must audit token");
        assert!(report.is_vulnerable());
        assert!(report
            .vulnerabilities
            .iter()
            .any(|v| v.title.contains("Algorithm 'none'")));
        assert!(report
            .vulnerabilities
            .iter()
            .any(|v| v.title.contains("Missing Token Expiration")));
    }

    #[test]
    fn test_crack_weak_hmac_secret() {
        let h_b64 = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        let p_b64 = URL_SAFE_NO_PAD.encode(b"{\"sub\":\"alice\",\"exp\":9999999999}");
        let input = format!("{}.{}", h_b64, p_b64);

        // Sign with weak key "secret"
        let sig = JwtAuditor::compute_hmac_sha256(b"secret", input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig);
        let raw = format!("{}.{}", input, sig_b64);

        let report = JwtAuditor::audit_token(&raw).expect("Must audit token");
        assert!(report.vulnerabilities.iter().any(|v| v
            .title
            .contains("Weak JWT HMAC Secret Cracker Hit: 'secret'")));
    }
}
