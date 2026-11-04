//! Streaming BOLA / IDOR (Broken Object Level Authorization) Detection Engine.
//!
//! Analyzes multi-user session traffic to identify horizontal authorization bypasses:
//! when Subject A accesses resources previously accessed by Subject B without receiving HTTP 401/403.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdorAlert {
    pub endpoint_template: String,
    pub target_resource_id: String,
    pub original_identity: String,
    pub accessing_identity: String,
    pub status_code: u16,
    pub severity: &'static str,
}

#[derive(Debug, Clone, Default)]
pub struct IdorDetector {
    /// Maps resource ID to the first observed authorized session identity
    resource_ownership: HashMap<String, (String, String)>, // resource_id -> (identity, endpoint_template)
    /// Alerts generated
    pub alerts: Vec<IdorAlert>,
}

impl IdorDetector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Evaluates an observed HTTP transaction for authorization anomalies.
    pub fn inspect_transaction(&mut self, uri: &str, identity: Option<&str>, status_code: u16) {
        let auth_id = match identity {
            Some(id) if !id.trim().is_empty() => id.trim(),
            _ => return, // Unauthenticated or public
        };

        let (template, res_id) = match Self::extract_resource_id(uri) {
            Some((tpl, id)) => (tpl, id),
            None => return,
        };

        if let Some((original_owner, orig_template)) = self.resource_ownership.get(&res_id) {
            if original_owner != auth_id && orig_template == &template && status_code == 200 {
                // Different user succeeded in fetching/modifying the resource
                self.alerts.push(IdorAlert {
                    endpoint_template: template.clone(),
                    target_resource_id: res_id.clone(),
                    original_identity: original_owner.clone(),
                    accessing_identity: auth_id.to_string(),
                    status_code,
                    severity: "CRITICAL",
                });
            }
        } else if status_code == 200 {
            // Register original owner for this resource
            self.resource_ownership
                .insert(res_id, (auth_id.to_string(), template));
        }
    }

    /// Extracts template and resource ID (numeric or UUID) from path or query parameters.
    pub fn extract_resource_id(uri: &str) -> Option<(String, String)> {
        let (path, query) = match uri.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (uri, None),
        };
        let segments: Vec<&str> = path.split('/').collect();

        for (i, seg) in segments.iter().enumerate() {
            if seg.is_empty() {
                continue;
            }
            // Match numeric ID or UUID in path
            if seg.chars().all(|c| c.is_ascii_digit()) || (seg.len() == 36 && seg.contains('-')) {
                let mut tpl_segments = segments.clone();
                tpl_segments[i] = "{id}";
                return Some((tpl_segments.join("/"), seg.to_string()));
            }
        }

        // Also check query parameters (e.g. ?id=1001 or ?user_id=1001)
        if let Some(q) = query {
            for param in q.split('&') {
                if let Some((k, v)) = param.split_once('=') {
                    let k_lower = k.to_lowercase();
                    if (k_lower == "id" || k_lower.ends_with("_id"))
                        && (v.chars().all(|c| c.is_ascii_digit())
                            || (v.len() == 36 && v.contains('-')))
                    {
                        return Some((format!("{}?{}={{id}}", path, k), v.to_string()));
                    }
                }
            }
        }

        None
    }

    /// Extracts auth identity from common request headers (Authorization, X-User-Id, Cookie).
    pub fn extract_identity(headers: &HashMap<String, String>) -> Option<String> {
        for (k, v) in headers {
            let key = k.to_lowercase();
            if key == "authorization"
                || key == "x-user-id"
                || key == "x-auth-token"
                || key == "cookie"
            {
                return Some(v.clone());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_idor_detection_between_two_users() {
        let mut detector = IdorDetector::new();

        // 1. User Alice accesses her order #1001 -> 200 OK
        detector.inspect_transaction("/api/v1/orders/1001", Some("Bearer token_alice"), 200);
        assert!(detector.alerts.is_empty());

        // 2. User Bob accesses order #1001 -> 200 OK (BOLA / IDOR!)
        detector.inspect_transaction("/api/v1/orders/1001", Some("Bearer token_bob"), 200);
        assert_eq!(detector.alerts.len(), 1);

        let alert = &detector.alerts[0];
        assert_eq!(alert.target_resource_id, "1001");
        assert_eq!(alert.original_identity, "Bearer token_alice");
        assert_eq!(alert.accessing_identity, "Bearer token_bob");
        assert_eq!(alert.severity, "CRITICAL");
    }

    #[test]
    fn test_idor_query_parameter_detection() {
        let mut detector = IdorDetector::new();
        detector.inspect_transaction("/api/user?id=42", Some("user_1"), 200);
        assert!(detector.alerts.is_empty());

        detector.inspect_transaction("/api/user?id=42", Some("user_2"), 200);
        assert_eq!(detector.alerts.len(), 1);
        assert_eq!(detector.alerts[0].target_resource_id, "42");
    }
}
