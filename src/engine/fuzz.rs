//! High-Throughput Request Fuzzing & Mutation Engine.
//!
//! Generates intelligent input mutations (boundary numbers, format strings, payload polyglots)
//! and evaluates server responses for crashes, status deviations, and latency anomalies.

use crate::engine::replay::{ReplayEngine, ReplayRequest};
use anyhow::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuzzPayload {
    BoundaryNumber(&'static str),
    SpecialString(&'static str),
    InjectionCheck(&'static str),
    Custom(String),
}

impl FuzzPayload {
    pub fn as_str(&self) -> &str {
        match self {
            FuzzPayload::BoundaryNumber(s) => s,
            FuzzPayload::SpecialString(s) => s,
            FuzzPayload::InjectionCheck(s) => s,
            FuzzPayload::Custom(s) => s.as_str(),
        }
    }
}

pub static DEFAULT_FUZZ_DICTIONARY: &[FuzzPayload] = &[
    // 1. Boundary Numbers
    FuzzPayload::BoundaryNumber("0"),
    FuzzPayload::BoundaryNumber("-1"),
    FuzzPayload::BoundaryNumber("2147483647"),
    FuzzPayload::BoundaryNumber("-2147483648"),
    FuzzPayload::BoundaryNumber("9223372036854775807"),
    FuzzPayload::BoundaryNumber("1e309"),
    // 2. Special Null & Encoding values
    FuzzPayload::SpecialString("null"),
    FuzzPayload::SpecialString("undefined"),
    FuzzPayload::SpecialString("NaN"),
    FuzzPayload::SpecialString("%00"),
    FuzzPayload::SpecialString("%0d%0a"),
    FuzzPayload::SpecialString("../../../../../../../etc/passwd"),
    // 3. Format strings & template checks
    FuzzPayload::InjectionCheck("%s%s%s%s%s%n"),
    FuzzPayload::InjectionCheck("{{7*7}}"),
    FuzzPayload::InjectionCheck("${7*7}"),
    FuzzPayload::InjectionCheck("' OR '1'='1"),
    FuzzPayload::InjectionCheck("{\"\"$gt\": \"\"}"),
];

#[derive(Debug, Clone)]
pub struct FuzzResult {
    pub payload: String,
    pub status_code: u16,
    pub body_len: usize,
    pub duration_ms: f64,
    pub is_anomaly: bool,
}

pub struct FuzzEngine;

impl FuzzEngine {
    /// Mutates target parameter in the URL query string with payloads and evaluates responses.
    pub async fn fuzz_parameter(
        base_req: &ReplayRequest,
        param_name: &str,
        payloads: &[FuzzPayload],
    ) -> Result<Vec<FuzzResult>> {
        let mut results = Vec::new();

        // 1. Baseline request
        let baseline = ReplayEngine::execute(base_req).await?;
        let baseline_status = baseline.status_code;
        let baseline_len = baseline.body.len();

        for payload in payloads {
            let mut mutated_req = base_req.clone();
            let p_str = payload.as_str();

            // Mutate path/query parameter
            let new_path = if mutated_req.path.contains(&format!("{}=", param_name)) {
                let re_pattern = format!(r"({}=)[^&]*", regex::escape(param_name));
                let re = regex::Regex::new(&re_pattern).unwrap();
                re.replace(&mutated_req.path, format!("${{1}}{}", p_str))
                    .to_string()
            } else if mutated_req.path.contains('?') {
                format!("{}&{}={}", mutated_req.path, param_name, p_str)
            } else {
                format!("{}?{}={}", mutated_req.path, param_name, p_str)
            };

            mutated_req.path = new_path;

            match ReplayEngine::execute(&mutated_req).await {
                Ok(resp) => {
                    let len_diff = (resp.body.len() as isize - baseline_len as isize).abs();
                    let is_anomaly = resp.status_code != baseline_status
                        || len_diff > 200
                        || resp.status_code >= 500;

                    results.push(FuzzResult {
                        payload: p_str.to_string(),
                        status_code: resp.status_code,
                        body_len: resp.body.len(),
                        duration_ms: resp.metrics.total_duration_ms,
                        is_anomaly,
                    });
                }
                Err(_) => {
                    // Possible crash or server drop
                    results.push(FuzzResult {
                        payload: p_str.to_string(),
                        status_code: 0,
                        body_len: 0,
                        duration_ms: 0.0,
                        is_anomaly: true,
                    });
                }
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzz_dictionary_coverage() {
        assert!(DEFAULT_FUZZ_DICTIONARY.len() >= 10);
        assert!(DEFAULT_FUZZ_DICTIONARY.iter().any(|p| p.as_str() == "0"));
        assert!(DEFAULT_FUZZ_DICTIONARY
            .iter()
            .any(|p| p.as_str() == "{{7*7}}"));
    }
}
