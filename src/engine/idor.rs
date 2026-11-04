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
    pub fn inspect_transaction(
        &mut self,
        uri: &str,
        identity: Option<&str>,
        status_code: u16,
    ) {
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
            self.resource_ownership.insert(res_id, (auth_id.to_string(), template));
        }
    }

    /// Extracts template and resource ID (numeric or UUID).
    fn extract_resource_id(uri: &str) -> Option<(String, String)> {
        let path = uri.split('?').next().unwrap_or(uri);
        let segments: Vec<&str> = path.split('/').collect();

        for (i, seg) in segments.iter().enumerate() {
            if seg.is_empty() {
                continue;
            }
            // Match numeric ID or UUID
            if seg.chars().all(|c| c.is_ascii_digit()) || (seg.len() == 36 && seg.contains('-')) {
                let mut tpl_segments = segments.clone();
                tpl_segments[i] = "{id}";
                return Some((tpl_segments.join("/"), seg.to_string()));
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
}
