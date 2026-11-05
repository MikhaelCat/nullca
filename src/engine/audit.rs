//! Passive Security Posture & Hygiene Auditor.
//!
//! Analyzes captured HTTP/1.1 and HTTP/2 sessions for security misconfigurations,
//! missing defense-in-depth headers, insecure CORS policies, vulnerable cookies,
//! information leaks, and exposed credentials.

use crate::export::har::HarEntry;
use crate::proto::secrets::scan_secrets;
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuditSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl AuditSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditSeverity::Critical => "CRITICAL",
            AuditSeverity::High => "HIGH",
            AuditSeverity::Medium => "MEDIUM",
            AuditSeverity::Low => "LOW",
            AuditSeverity::Info => "INFO",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditCategory {
    MissingHsts,
    InsecureCors,
    MissingContentTypeOptions,
    MissingCsp,
    MissingClickjackingProtection,
    InsecureCookie,
    ServerInformationLeak,
    SecretLeak,
    JwtVulnerability,
    HttpRequestSmuggling,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFinding {
    pub severity: AuditSeverity,
    pub category: AuditCategory,
    pub title: String,
    pub endpoint: String,
    pub description: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditReport {
    pub total_transactions: usize,
    pub findings: Vec<AuditFinding>,
}

impl AuditReport {
    pub fn critical_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == AuditSeverity::Critical)
            .count()
    }

    pub fn high_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == AuditSeverity::High)
            .count()
    }

    pub fn medium_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == AuditSeverity::Medium)
            .count()
    }

    pub fn low_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == AuditSeverity::Low)
            .count()
    }

    pub fn info_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == AuditSeverity::Info)
            .count()
    }
}

pub struct SecurityAuditor;

impl Default for SecurityAuditor {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityAuditor {
    pub fn new() -> Self {
        Self
    }

    /// Audits a collection of HAR entries.
    pub fn audit_har_entries(&self, entries: &[HarEntry]) -> AuditReport {
        let mut report = AuditReport {
            total_transactions: entries.len(),
            findings: Vec::new(),
        };

        for entry in entries {
            let endpoint = format!("{} {}", entry.request.method, entry.request.url);

            // Build request headers map
            let mut req_headers = HashMap::new();
            for h in &entry.request.headers {
                req_headers.insert(h.name.to_ascii_lowercase(), h.value.clone());
            }

            // Build response headers map
            let mut res_headers = HashMap::new();
            for h in &entry.response.headers {
                res_headers.insert(h.name.to_ascii_lowercase(), h.value.clone());
            }

            let res_body = entry
                .response
                .content
                .text
                .as_deref()
                .unwrap_or("")
                .as_bytes();
            let req_body = entry
                .request
                .post_data
                .as_ref()
                .map(|p| p.text.as_bytes())
                .unwrap_or(b"");

            self.audit_single_exchange(
                &endpoint,
                &req_headers,
                req_body,
                entry.response.status,
                &res_headers,
                res_body,
                &mut report.findings,
            );
        }

        // Sort findings: Critical -> High -> Medium -> Low -> Info
        report
            .findings
            .sort_by_key(|a| std::cmp::Reverse(a.severity));
        report
    }

    /// Audits a single request/response exchange.
    #[allow(clippy::too_many_arguments)]
    pub fn audit_single_exchange(
        &self,
        endpoint: &str,
        req_headers: &HashMap<String, String>,
        req_body: &[u8],
        status_code: u16,
        res_headers: &HashMap<String, String>,
        res_body: &[u8],
        findings: &mut Vec<AuditFinding>,
    ) {
        // Only audit responses for standard HTTP transactions
        if status_code == 0 {
            return;
        }

        // 1. Check Strict-Transport-Security (HSTS)
        if let Some(hsts) = res_headers.get("strict-transport-security") {
            let lower = hsts.to_ascii_lowercase();
            if !lower.contains("max-age=") {
                findings.push(AuditFinding {
                    severity: AuditSeverity::Medium,
                    category: AuditCategory::MissingHsts,
                    title: "Malformed HSTS Header".to_string(),
                    endpoint: endpoint.to_string(),
                    description: format!(
                        "Strict-Transport-Security header is present but lacks 'max-age': '{}'",
                        hsts
                    ),
                    remediation:
                        "Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains'"
                            .to_string(),
                });
            } else if lower.contains("max-age=0") {
                findings.push(AuditFinding {
                    severity: AuditSeverity::High,
                    category: AuditCategory::MissingHsts,
                    title: "Disabled HSTS (max-age=0)".to_string(),
                    endpoint: endpoint.to_string(),
                    description:
                        "HSTS max-age is set to 0, disabling browser transport protection."
                            .to_string(),
                    remediation:
                        "Configure max-age to at least 15768000 (180 days) or 31536000 (1 year)."
                            .to_string(),
                });
            }
        } else {
            findings.push(AuditFinding {
                severity: AuditSeverity::Medium,
                category: AuditCategory::MissingHsts,
                title: "Missing Strict-Transport-Security Header".to_string(),
                endpoint: endpoint.to_string(),
                description: "The response does not enforce HTTPS via HSTS, exposing clients to SSL stripping.".to_string(),
                remediation: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.".to_string(),
            });
        }

        // 2. Insecure CORS Configuration
        if let Some(allow_origin) = res_headers.get("access-control-allow-origin") {
            let allow_creds = res_headers
                .get("access-control-allow-credentials")
                .map(|v| v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);

            if allow_origin == "*" && allow_creds {
                findings.push(AuditFinding {
                    severity: AuditSeverity::Critical,
                    category: AuditCategory::InsecureCors,
                    title: "Critical CORS Misconfiguration (Wildcard with Credentials)".to_string(),
                    endpoint: endpoint.to_string(),
                    description: "Access-Control-Allow-Origin is '*' while Access-Control-Allow-Credentials is true.".to_string(),
                    remediation: "Never allow credentials with a wildcard origin. Validate allowed origins against an explicit allow-list.".to_string(),
                });
            } else if allow_origin == "*" {
                findings.push(AuditFinding {
                    severity: AuditSeverity::Low,
                    category: AuditCategory::InsecureCors,
                    title: "Permissive Wildcard CORS Origin".to_string(),
                    endpoint: endpoint.to_string(),
                    description: "Access-Control-Allow-Origin is set to '*', allowing any external site to read responses.".to_string(),
                    remediation: "If this endpoint serves sensitive data, restrict origin to trusted domains.".to_string(),
                });
            }
        }

        // 3. X-Content-Type-Options
        if let Some(val) = res_headers.get("x-content-type-options") {
            if !val.eq_ignore_ascii_case("nosniff") {
                findings.push(AuditFinding {
                    severity: AuditSeverity::Low,
                    category: AuditCategory::MissingContentTypeOptions,
                    title: "Invalid X-Content-Type-Options Header".to_string(),
                    endpoint: endpoint.to_string(),
                    description: format!("Expected 'nosniff', found '{}'.", val),
                    remediation: "Set 'X-Content-Type-Options: nosniff'.".to_string(),
                });
            }
        } else {
            findings.push(AuditFinding {
                severity: AuditSeverity::Low,
                category: AuditCategory::MissingContentTypeOptions,
                title: "Missing X-Content-Type-Options Header".to_string(),
                endpoint: endpoint.to_string(),
                description: "Missing 'nosniff' directive allows browsers to MIME-sniff responses, potentially causing XSS.".to_string(),
                remediation: "Add 'X-Content-Type-Options: nosniff' to all HTTP responses.".to_string(),
            });
        }

        // 4. Content-Security-Policy (CSP)
        if let Some(csp) = res_headers.get("content-security-policy") {
            if csp.contains("'unsafe-inline'") || csp.contains("'unsafe-eval'") {
                findings.push(AuditFinding {
                    severity: AuditSeverity::Low,
                    category: AuditCategory::MissingCsp,
                    title: "Weak Content-Security-Policy (unsafe directives)".to_string(),
                    endpoint: endpoint.to_string(),
                    description: "CSP contains 'unsafe-inline' or 'unsafe-eval', weakening script execution defense.".to_string(),
                    remediation: "Use nonces or hashes instead of 'unsafe-inline'.".to_string(),
                });
            }
        } else {
            let content_type = res_headers
                .get("content-type")
                .map(|s| s.as_str())
                .unwrap_or("");
            if content_type.contains("text/html") {
                findings.push(AuditFinding {
                    severity: AuditSeverity::Medium,
                    category: AuditCategory::MissingCsp,
                    title: "Missing Content-Security-Policy (CSP)".to_string(),
                    endpoint: endpoint.to_string(),
                    description: "HTML response does not define a Content-Security-Policy, leaving the app vulnerable to XSS.".to_string(),
                    remediation: "Configure a robust CSP header (e.g. 'default-src \\'self\\'').".to_string(),
                });
            }
        }

        // 5. Clickjacking Defense (X-Frame-Options or CSP frame-ancestors)
        let has_frame_options = res_headers.contains_key("x-frame-options");
        let has_csp_frames = res_headers
            .get("content-security-policy")
            .map(|c| c.contains("frame-ancestors"))
            .unwrap_or(false);
        let content_type = res_headers
            .get("content-type")
            .map(|s| s.as_str())
            .unwrap_or("");

        if content_type.contains("text/html") && !has_frame_options && !has_csp_frames {
            findings.push(AuditFinding {
                severity: AuditSeverity::Medium,
                category: AuditCategory::MissingClickjackingProtection,
                title: "Missing Clickjacking Protection".to_string(),
                endpoint: endpoint.to_string(),
                description: "HTML page does not set X-Frame-Options or CSP frame-ancestors, allowing unauthorized framing.".to_string(),
                remediation: "Add 'X-Frame-Options: DENY' or 'Content-Security-Policy: frame-ancestors \\'none\\'.".to_string(),
            });
        }

        // 6. Insecure Cookies (Set-Cookie)
        if let Some(cookie) = res_headers.get("set-cookie") {
            let lower = cookie.to_ascii_lowercase();
            let is_session_cookie = lower.contains("session")
                || lower.contains("auth")
                || lower.contains("token")
                || lower.contains("id");

            if !lower.contains("secure") {
                findings.push(AuditFinding {
                    severity: if is_session_cookie {
                        AuditSeverity::High
                    } else {
                        AuditSeverity::Medium
                    },
                    category: AuditCategory::InsecureCookie,
                    title: "Cookie Missing 'Secure' Attribute".to_string(),
                    endpoint: endpoint.to_string(),
                    description: format!(
                        "Set-Cookie header does not specify the 'Secure' flag: '{}'",
                        cookie
                    ),
                    remediation: "Append '; Secure' to all cookies transmitted over TLS."
                        .to_string(),
                });
            }

            if is_session_cookie && !lower.contains("httponly") {
                findings.push(AuditFinding {
                    severity: AuditSeverity::High,
                    category: AuditCategory::InsecureCookie,
                    title: "Session Cookie Missing 'HttpOnly' Attribute".to_string(),
                    endpoint: endpoint.to_string(),
                    description: "Session identifier cookie can be read by JavaScript via document.cookie, increasing XSS impact.".to_string(),
                    remediation: "Append '; HttpOnly' to all authentication and session cookies.".to_string(),
                });
            }

            if !lower.contains("samesite") {
                findings.push(AuditFinding {
                    severity: AuditSeverity::Low,
                    category: AuditCategory::InsecureCookie,
                    title: "Cookie Missing 'SameSite' Attribute".to_string(),
                    endpoint: endpoint.to_string(),
                    description: "Cookie does not declare SameSite=Lax or SameSite=Strict, increasing CSRF exposure.".to_string(),
                    remediation: "Append '; SameSite=Lax' or '; SameSite=Strict' to cookies.".to_string(),
                });
            }
        }

        // 7. Information Leakage Headers
        if let Some(server) = res_headers.get("server") {
            if server.contains('/') || server.contains('.') {
                findings.push(AuditFinding {
                    severity: AuditSeverity::Info,
                    category: AuditCategory::ServerInformationLeak,
                    title: "Detailed Server Banner Disclosure".to_string(),
                    endpoint: endpoint.to_string(),
                    description: format!(
                        "Server header exposes exact software and version: '{}'",
                        server
                    ),
                    remediation:
                        "Configure the web server to mask or disable banner version details."
                            .to_string(),
                });
            }
        }

        if let Some(xpb) = res_headers.get("x-powered-by") {
            findings.push(AuditFinding {
                severity: AuditSeverity::Low,
                category: AuditCategory::ServerInformationLeak,
                title: "Technology Disclosure via X-Powered-By".to_string(),
                endpoint: endpoint.to_string(),
                description: format!("Header leaks backend technology stack: '{}'", xpb),
                remediation: "Remove 'X-Powered-By' header in framework configuration.".to_string(),
            });
        }

        // 8. Secrets & Credential Detection in Request & Response
        let req_secrets = scan_secrets(req_body);
        for s in &req_secrets {
            findings.push(AuditFinding {
                severity: AuditSeverity::High,
                category: AuditCategory::SecretLeak,
                title: format!("Secret Exposed in Request Payload ({:?})", s.kind),
                endpoint: endpoint.to_string(),
                description: format!("Detected secret token '{}' in request payload.", s.raw_token),
                remediation: "Ensure credentials are not transmitted in plain payload bodies or logged unencrypted.".to_string(),
            });
        }

        let res_secrets = scan_secrets(res_body);
        for s in &res_secrets {
            findings.push(AuditFinding {
                severity: AuditSeverity::Critical,
                category: AuditCategory::SecretLeak,
                title: format!("Secret Leaked in Response Body ({:?})", s.kind),
                endpoint: endpoint.to_string(),
                description: format!(
                    "Detected leaked secret token '{}' in response payload.",
                    s.raw_token
                ),
                remediation: "Immediately sanitize server responses and revoke leaked credentials."
                    .to_string(),
            });
        }

        // 9. Deep JWT Cryptographic Security Scanner & Weak Secret Cracker
        let mut audited_tokens = std::collections::HashSet::new();
        let mut check_jwt_candidate = |candidate: &str| {
            if !candidate.is_empty()
                && candidate.split('.').count() == 3
                && audited_tokens.insert(candidate.to_string())
            {
                if let Some(report) = crate::engine::jwt_audit::JwtAuditor::audit_token(candidate) {
                    for vuln in report.vulnerabilities {
                        let sev = match vuln.severity {
                            crate::engine::jwt_audit::JwtVulnerabilitySeverity::Critical => {
                                AuditSeverity::Critical
                            }
                            crate::engine::jwt_audit::JwtVulnerabilitySeverity::High => {
                                AuditSeverity::High
                            }
                            crate::engine::jwt_audit::JwtVulnerabilitySeverity::Medium => {
                                AuditSeverity::Medium
                            }
                            crate::engine::jwt_audit::JwtVulnerabilitySeverity::Low => {
                                AuditSeverity::Low
                            }
                            crate::engine::jwt_audit::JwtVulnerabilitySeverity::Info => {
                                AuditSeverity::Info
                            }
                        };
                        findings.push(AuditFinding {
                            severity: sev,
                            category: AuditCategory::JwtVulnerability,
                            title: vuln.title,
                            endpoint: endpoint.to_string(),
                            description: vuln.description,
                            remediation: vuln.recommendation,
                        });
                    }
                }
            }
        };

        if let Some(auth) = req_headers.get("authorization") {
            let trimmed = auth.trim();
            if let Some(token) = trimmed.strip_prefix("Bearer ") {
                check_jwt_candidate(token.trim());
            } else if let Some(token) = trimmed.strip_prefix("bearer ") {
                check_jwt_candidate(token.trim());
            } else {
                check_jwt_candidate(trimmed);
            }
        }

        for (h_name, h_val) in req_headers.iter().chain(res_headers.iter()) {
            if h_name.contains("token") || h_name.contains("jwt") || h_name.contains("auth") {
                check_jwt_candidate(h_val.trim());
            }
        }

        for s in req_secrets.iter().chain(res_secrets.iter()) {
            if s.kind == crate::proto::secrets::SecretKind::JwtToken {
                check_jwt_candidate(&s.raw_token);
            }
        }

        // 10. HTTP Request Smuggling & Desync Checks (RFC 7230 §3.3.3 / CWE-444)
        let has_te = req_headers.contains_key("transfer-encoding");
        let has_cl = req_headers.contains_key("content-length");
        if has_te && has_cl {
            findings.push(AuditFinding {
                severity: AuditSeverity::Critical,
                category: AuditCategory::HttpRequestSmuggling,
                title: "HTTP Request Smuggling Risk (TE.CL / CL.TE Desync)".to_string(),
                endpoint: endpoint.to_string(),
                description: "Request specifies both 'Transfer-Encoding' and 'Content-Length' headers, enabling HTTP desynchronization and cache poisoning attacks (RFC 7230 §3.3.3).".to_string(),
                remediation: "Remove either Transfer-Encoding or Content-Length. Reject ambiguous requests at the edge proxy.".to_string(),
            });
        }

        if let Some(risk) = req_headers.get("x-nullca-smuggling-risk") {
            if risk == "conflicting-content-length" {
                findings.push(AuditFinding {
                    severity: AuditSeverity::Critical,
                    category: AuditCategory::HttpRequestSmuggling,
                    title: "Conflicting Content-Length Headers (CL.CL Request Smuggling)".to_string(),
                    endpoint: endpoint.to_string(),
                    description: "Request contains multiple or conflicting 'Content-Length' headers, allowing request smuggling bypass of reverse proxy routing (RFC 7230 §3.3.2).".to_string(),
                    remediation: "Reject requests with multiple Content-Length headers with HTTP 400 Bad Request.".to_string(),
                });
            }
        }

        if let Some(te) = req_headers.get("transfer-encoding") {
            let lower = te.to_ascii_lowercase();
            if lower.contains("chunked") && lower != "chunked" {
                findings.push(AuditFinding {
                    severity: AuditSeverity::High,
                    category: AuditCategory::HttpRequestSmuggling,
                    title: "Obfuscated Transfer-Encoding Header".to_string(),
                    endpoint: endpoint.to_string(),
                    description: format!("Transfer-Encoding value '{}' uses non-standard framing or chaining, often used to bypass WAFs.", te),
                    remediation: "Normalize or reject non-standard Transfer-Encoding headers at the gateway.".to_string(),
                });
            }
        }
    }

    /// Prints a formatted audit report to standard output.
    pub fn print_report(&self, report: &AuditReport) {
        println!(
            "{}",
            "══════════════════════════════════════════════════════════════════════════"
                .cyan()
                .bold()
        );
        println!(
            "{}",
            "            ⚡ NullCA Passive Security & Hygiene Audit Report             "
                .white()
                .bold()
        );
        println!(
            "{}",
            "══════════════════════════════════════════════════════════════════════════"
                .cyan()
                .bold()
        );
        println!(
            "Total Exchanges Audited: {} | {} Critical | {} High | {} Medium | {} Low | {} Info",
            report.total_transactions.to_string().bold(),
            report.critical_count().to_string().red().bold(),
            report.high_count().to_string().bright_red().bold(),
            report.medium_count().to_string().yellow().bold(),
            report.low_count().to_string().blue(),
            report.info_count().to_string().dimmed()
        );
        println!("{}", "─".repeat(74).dimmed());

        if report.findings.is_empty() {
            println!(
                "{}",
                "✅ No security posture or header issues identified!"
                    .green()
                    .bold()
            );
            return;
        }

        for (i, f) in report.findings.iter().enumerate() {
            let sev_badge = match f.severity {
                AuditSeverity::Critical => "[CRITICAL]".on_red().white().bold(),
                AuditSeverity::High => "[HIGH]".red().bold(),
                AuditSeverity::Medium => "[MEDIUM]".yellow().bold(),
                AuditSeverity::Low => "[LOW]".blue().bold(),
                AuditSeverity::Info => "[INFO]".dimmed(),
            };

            println!(
                "{}. {} {} - {}",
                (i + 1).to_string().bold(),
                sev_badge,
                f.title.bold(),
                f.endpoint.dimmed()
            );
            println!("   {}", f.description);
            println!(
                "   {} {}",
                "Remediation:".cyan().bold(),
                f.remediation.dimmed()
            );
            println!();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::har::{HarContent, HarHeader, HarRequest, HarResponse, HarTimings};
    use serde_json::json;

    #[test]
    fn test_audit_missing_hsts_and_content_type_options() {
        let auditor = SecurityAuditor::new();

        let entry = HarEntry {
            started_date_time: "2026-11-04T12:00:00Z".to_string(),
            time: 20.0,
            request: HarRequest {
                method: "GET".to_string(),
                url: "https://example.com/login".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: vec![],
                query_string: vec![],
                post_data: None,
                headers_size: 50,
                body_size: 0,
            },
            response: HarResponse {
                status: 200,
                status_text: "OK".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: vec![
                    HarHeader {
                        name: "Content-Type".to_string(),
                        value: "text/html; charset=utf-8".to_string(),
                    },
                    HarHeader {
                        name: "Server".to_string(),
                        value: "nginx/1.18.0".to_string(),
                    },
                ],
                content: HarContent {
                    size: 100,
                    mime_type: "text/html".to_string(),
                    text: Some("<html><body>Login</body></html>".to_string()),
                    encoding: None,
                },
                redirect_url: "".to_string(),
                headers_size: 100,
                body_size: 100,
            },
            cache: json!({}),
            timings: HarTimings {
                send: 1.0,
                wait: 10.0,
                receive: 9.0,
            },
        };

        let report = auditor.audit_har_entries(&[entry]);
        assert!(!report.findings.is_empty());
        assert!(report
            .findings
            .iter()
            .any(|f| f.category == AuditCategory::MissingHsts));
        assert!(report
            .findings
            .iter()
            .any(|f| f.category == AuditCategory::MissingContentTypeOptions));
        assert!(report
            .findings
            .iter()
            .any(|f| f.category == AuditCategory::MissingClickjackingProtection));
    }

    #[test]
    fn test_audit_insecure_cors_wildcard_credentials() {
        let auditor = SecurityAuditor::new();

        let entry = HarEntry {
            started_date_time: "2026-11-04T12:00:00Z".to_string(),
            time: 10.0,
            request: HarRequest {
                method: "GET".to_string(),
                url: "https://api.example.com/user".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: vec![],
                query_string: vec![],
                post_data: None,
                headers_size: 50,
                body_size: 0,
            },
            response: HarResponse {
                status: 200,
                status_text: "OK".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: vec![
                    HarHeader {
                        name: "Access-Control-Allow-Origin".to_string(),
                        value: "*".to_string(),
                    },
                    HarHeader {
                        name: "Access-Control-Allow-Credentials".to_string(),
                        value: "true".to_string(),
                    },
                ],
                content: HarContent {
                    size: 20,
                    mime_type: "application/json".to_string(),
                    text: Some(r#"{"user": "alice"}"#.to_string()),
                    encoding: None,
                },
                redirect_url: "".to_string(),
                headers_size: 100,
                body_size: 20,
            },
            cache: json!({}),
            timings: HarTimings {
                send: 1.0,
                wait: 5.0,
                receive: 4.0,
            },
        };

        let report = auditor.audit_har_entries(&[entry]);
        assert!(report
            .findings
            .iter()
            .any(|f| f.severity == AuditSeverity::Critical));
    }

    #[test]
    fn test_audit_jwt_vulnerability_in_authorization_header() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let auditor = SecurityAuditor::new();
        let h_b64 = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\",\"typ\":\"JWT\"}");
        let p_b64 = URL_SAFE_NO_PAD.encode(b"{\"sub\":\"admin\"}");
        let raw_jwt = format!("{}.{}.", h_b64, p_b64);

        let entry = HarEntry {
            started_date_time: "2026-11-04T12:00:00Z".to_string(),
            time: 10.0,
            request: HarRequest {
                method: "GET".to_string(),
                url: "https://api.example.com/protected".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: vec![HarHeader {
                    name: "Authorization".to_string(),
                    value: format!("Bearer {}", raw_jwt),
                }],
                query_string: vec![],
                post_data: None,
                headers_size: 50,
                body_size: 0,
            },
            response: HarResponse {
                status: 200,
                status_text: "OK".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: vec![],
                content: HarContent {
                    size: 15,
                    mime_type: "application/json".to_string(),
                    text: Some(r#"{"status":"ok"}"#.to_string()),
                    encoding: None,
                },
                redirect_url: "".to_string(),
                headers_size: 50,
                body_size: 15,
            },
            cache: json!({}),
            timings: HarTimings {
                send: 1.0,
                wait: 5.0,
                receive: 4.0,
            },
        };

        let report = auditor.audit_har_entries(&[entry]);
        assert!(report
            .findings
            .iter()
            .any(|f| f.category == AuditCategory::JwtVulnerability
                && f.severity == AuditSeverity::Critical));
    }
}
