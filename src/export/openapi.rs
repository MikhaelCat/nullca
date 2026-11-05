//! Automated OpenAPI (Swagger 3.0.3) Specification Generator.
//!
//! Synthesizes a valid OpenAPI 3.0 specification from captured HTTP request/response
//! streams (e.g. HAR logs or live events). Automatically clusters dynamic path parameters,
//! infers recursive JSON schemas, query parameters, status codes, and HTTP methods.

use crate::export::har::{HarEntry, HarRoot};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenApiSpec {
    pub openapi: String,
    pub info: OpenApiInfo,
    pub paths: BTreeMap<String, PathItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<Components>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenApiInfo {
    pub title: String,
    pub version: String,
    pub description: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PathItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get: Option<Operation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post: Option<Operation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub put: Option<Operation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete: Option<Operation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch: Option<Operation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head: Option<Operation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Operation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parameters: Vec<Parameter>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parameters: Vec<Parameter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body: Option<RequestBody>,
    pub responses: BTreeMap<String, ResponseObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    #[serde(rename = "in")]
    pub in_location: String, // "path", "query", "header"
    pub required: bool,
    pub schema: SchemaObject,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub required: bool,
    pub content: HashMap<String, MediaTypeObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseObject {
    pub description: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub content: HashMap<String, MediaTypeObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaTypeObject {
    pub schema: SchemaObject,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub example: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaObject {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub schema_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub properties: BTreeMap<String, SchemaObject>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Box<SchemaObject>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Components {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub schemas: BTreeMap<String, SchemaObject>,
}

pub struct OpenApiGenerator {
    uuid_regex: Regex,
    numeric_id_regex: Regex,
    hex_id_regex: Regex,
}

impl Default for OpenApiGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenApiGenerator {
    pub fn new() -> Self {
        Self {
            uuid_regex: Regex::new(
                r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
            )
            .unwrap(),
            numeric_id_regex: Regex::new(r"^\d+$").unwrap(),
            hex_id_regex: Regex::new(r"^[0-9a-fA-F]{16,64}$").unwrap(),
        }
    }

    /// Parameterizes a dynamic path (e.g. `/api/v1/users/1024` -> `/api/v1/users/{id}`)
    pub fn parameterize_path(&self, raw_path: &str) -> (String, Vec<String>) {
        let clean_path = raw_path.split('?').next().unwrap_or(raw_path);
        let segments: Vec<&str> = clean_path.split('/').collect();
        let mut new_segments = Vec::new();
        let mut param_names = Vec::new();

        let mut id_counter = 1;
        for (i, seg) in segments.iter().enumerate() {
            if seg.is_empty() {
                new_segments.push("");
                continue;
            }

            if self.uuid_regex.is_match(seg) || self.numeric_id_regex.is_match(seg) {
                let name = if i > 0 && !segments[i - 1].is_empty() {
                    let prev = segments[i - 1].trim_end_matches('s');
                    format!("{}_id", prev)
                } else {
                    format!("id_{}", id_counter)
                };
                id_counter += 1;
                param_names.push(name.clone());
                new_segments.push(format!("{{{}}}", name).leak());
            } else if self.hex_id_regex.is_match(seg) {
                let name = format!("hash_{}", id_counter);
                id_counter += 1;
                param_names.push(name.clone());
                new_segments.push(format!("{{{}}}", name).leak());
            } else {
                new_segments.push(seg);
            }
        }

        let parameterized = new_segments.join("/");
        let final_path = if parameterized.is_empty() {
            "/".to_string()
        } else {
            parameterized
        };
        (final_path, param_names)
    }

    /// Recursively derives an OpenAPI SchemaObject from a JSON value.
    pub fn infer_schema_from_json(&self, val: &Value) -> SchemaObject {
        match val {
            Value::Null => SchemaObject {
                schema_type: Some("string".to_string()),
                format: Some("nullable".to_string()),
                properties: BTreeMap::new(),
                items: None,
                required: Vec::new(),
            },
            Value::Bool(_) => SchemaObject {
                schema_type: Some("boolean".to_string()),
                format: None,
                properties: BTreeMap::new(),
                items: None,
                required: Vec::new(),
            },
            Value::Number(n) => {
                let schema_type = if n.is_i64() || n.is_u64() {
                    "integer"
                } else {
                    "number"
                };
                SchemaObject {
                    schema_type: Some(schema_type.to_string()),
                    format: None,
                    properties: BTreeMap::new(),
                    items: None,
                    required: Vec::new(),
                }
            }
            Value::String(s) => {
                let format = if self.uuid_regex.is_match(s) {
                    Some("uuid".to_string())
                } else if chrono::DateTime::parse_from_rfc3339(s).is_ok() {
                    Some("date-time".to_string())
                } else {
                    None
                };
                SchemaObject {
                    schema_type: Some("string".to_string()),
                    format,
                    properties: BTreeMap::new(),
                    items: None,
                    required: Vec::new(),
                }
            }
            Value::Array(arr) => {
                let item_schema = if let Some(first) = arr.first() {
                    Some(Box::new(self.infer_schema_from_json(first)))
                } else {
                    Some(Box::new(SchemaObject {
                        schema_type: Some("object".to_string()),
                        format: None,
                        properties: BTreeMap::new(),
                        items: None,
                        required: Vec::new(),
                    }))
                };
                SchemaObject {
                    schema_type: Some("array".to_string()),
                    format: None,
                    properties: BTreeMap::new(),
                    items: item_schema,
                    required: Vec::new(),
                }
            }
            Value::Object(map) => {
                let mut props = BTreeMap::new();
                let mut required = Vec::new();
                for (k, v) in map {
                    props.insert(k.clone(), self.infer_schema_from_json(v));
                    required.push(k.clone());
                }
                SchemaObject {
                    schema_type: Some("object".to_string()),
                    format: None,
                    properties: props,
                    items: None,
                    required,
                }
            }
        }
    }

    /// Generates an OpenAPI 3.0 specification from a list of HAR entries.
    pub fn generate_from_har_entries(
        &self,
        entries: &[HarEntry],
        title: &str,
        version: &str,
    ) -> OpenApiSpec {
        let mut paths: BTreeMap<String, PathItem> = BTreeMap::new();

        for entry in entries {
            let raw_url = &entry.request.url;
            let path_part = if let Some(idx) = raw_url.find("://") {
                let without_scheme = &raw_url[idx + 3..];
                if let Some(slash_idx) = without_scheme.find('/') {
                    let end = without_scheme.find('?').unwrap_or(without_scheme.len());
                    without_scheme[slash_idx..end].to_string()
                } else {
                    "/".to_string()
                }
            } else {
                raw_url.split('?').next().unwrap_or(raw_url).to_string()
            };

            let (templated_path, path_params) = self.parameterize_path(&path_part);
            let path_item = paths.entry(templated_path.clone()).or_default();

            let method = entry.request.method.to_uppercase();

            // Extract query parameters
            let mut parameters = Vec::new();
            for p in &path_params {
                parameters.push(Parameter {
                    name: p.clone(),
                    in_location: "path".to_string(),
                    required: true,
                    schema: SchemaObject {
                        schema_type: Some("string".to_string()),
                        format: None,
                        properties: BTreeMap::new(),
                        items: None,
                        required: Vec::new(),
                    },
                    description: Some("Extracted path parameter".to_string()),
                });
            }

            for qp in &entry.request.query_string {
                parameters.push(Parameter {
                    name: qp.name.clone(),
                    in_location: "query".to_string(),
                    required: false,
                    schema: SchemaObject {
                        schema_type: Some("string".to_string()),
                        format: None,
                        properties: BTreeMap::new(),
                        items: None,
                        required: Vec::new(),
                    },
                    description: None,
                });
            }

            // Extract request body schema if JSON
            let request_body = if let Some(post) = &entry.request.post_data {
                if let Ok(val) = serde_json::from_str::<Value>(&post.text) {
                    let mut content = HashMap::new();
                    content.insert(
                        post.mime_type.clone(),
                        MediaTypeObject {
                            schema: self.infer_schema_from_json(&val),
                            example: Some(val),
                        },
                    );
                    Some(RequestBody {
                        description: Some("Request payload".to_string()),
                        required: true,
                        content,
                    })
                } else {
                    None
                }
            } else {
                None
            };

            // Extract response schema if JSON
            let mut responses = BTreeMap::new();
            let status_str = entry.response.status.to_string();
            let mut res_content = HashMap::new();

            if let Some(text) = &entry.response.content.text {
                if let Ok(val) = serde_json::from_str::<Value>(text) {
                    res_content.insert(
                        entry.response.content.mime_type.clone(),
                        MediaTypeObject {
                            schema: self.infer_schema_from_json(&val),
                            example: Some(val),
                        },
                    );
                }
            }

            responses.insert(
                status_str,
                ResponseObject {
                    description: entry.response.status_text.clone(),
                    content: res_content,
                },
            );

            let operation = Operation {
                summary: format!("{} {}", method, templated_path),
                description: Some(format!("Auto-generated endpoint for {}", path_part)),
                parameters,
                request_body,
                responses,
            };

            match method.as_str() {
                "GET" => path_item.get = Some(operation),
                "POST" => path_item.post = Some(operation),
                "PUT" => path_item.put = Some(operation),
                "DELETE" => path_item.delete = Some(operation),
                "PATCH" => path_item.patch = Some(operation),
                "HEAD" => path_item.head = Some(operation),
                "OPTIONS" => path_item.options = Some(operation),
                _ => {}
            }
        }

        OpenApiSpec {
            openapi: "3.0.3".to_string(),
            info: OpenApiInfo {
                title: title.to_string(),
                version: version.to_string(),
                description:
                    "OpenAPI 3.0.3 specification auto-synthesized by NullCA Zero-CA Engine"
                        .to_string(),
            },
            paths,
            components: Some(Components::default()),
        }
    }

    /// Generates OpenAPI spec directly from a HAR Root object.
    pub fn generate_from_har(&self, har: &HarRoot, title: &str) -> OpenApiSpec {
        self.generate_from_har_entries(&har.log.entries, title, "1.0.0")
    }

    /// Serializes an OpenAPI spec into pretty-printed JSON.
    pub fn to_json_string(&self, spec: &OpenApiSpec) -> anyhow::Result<String> {
        serde_json::to_string_pretty(spec)
            .map_err(|e| anyhow::anyhow!("Failed to serialize OpenAPI spec: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::har::{
        HarContent, HarHeader, HarQueryParam, HarRequest, HarResponse, HarTimings,
    };
    use serde_json::json;

    #[test]
    fn test_parameterize_path_numeric_and_uuid() {
        let generator = OpenApiGenerator::new();
        let (path, params) = generator.parameterize_path("/api/v1/users/1337/orders");
        assert_eq!(path, "/api/v1/users/{user_id}/orders");
        assert_eq!(params, vec!["user_id"]);

        let (uuid_path, uuid_params) =
            generator.parameterize_path("/api/v2/items/550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(uuid_path, "/api/v2/items/{item_id}");
        assert_eq!(uuid_params, vec!["item_id"]);
    }

    #[test]
    fn test_infer_schema_json() {
        let generator = OpenApiGenerator::new();
        let val = json!({
            "id": 42,
            "username": "alice",
            "is_active": true,
            "roles": ["admin", "editor"],
            "profile": {
                "bio": "Security Researcher"
            }
        });

        let schema = generator.infer_schema_from_json(&val);
        assert_eq!(schema.schema_type.as_deref(), Some("object"));
        assert!(schema.properties.contains_key("id"));
        assert_eq!(
            schema.properties.get("id").unwrap().schema_type.as_deref(),
            Some("integer")
        );
        assert!(schema.properties.contains_key("roles"));
        assert_eq!(
            schema
                .properties
                .get("roles")
                .unwrap()
                .schema_type
                .as_deref(),
            Some("array")
        );
    }

    #[test]
    fn test_generate_openapi_spec() {
        let generator = OpenApiGenerator::new();

        let entry = HarEntry {
            started_date_time: "2026-11-04T12:00:00Z".to_string(),
            time: 15.0,
            request: HarRequest {
                method: "GET".to_string(),
                url: "https://api.example.com/api/v1/users/42".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: vec![HarHeader {
                    name: "Host".to_string(),
                    value: "api.example.com".to_string(),
                }],
                query_string: vec![HarQueryParam {
                    name: "details".to_string(),
                    value: "true".to_string(),
                }],
                post_data: None,
                headers_size: 100,
                body_size: 0,
            },
            response: HarResponse {
                status: 200,
                status_text: "OK".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: vec![],
                content: HarContent {
                    size: 45,
                    mime_type: "application/json".to_string(),
                    text: Some(r#"{"id": 42, "name": "Bob"}"#.to_string()),
                    encoding: None,
                },
                redirect_url: "".to_string(),
                headers_size: 80,
                body_size: 45,
            },
            cache: json!({}),
            timings: HarTimings {
                send: 1.0,
                wait: 10.0,
                receive: 4.0,
            },
        };

        let spec = generator.generate_from_har_entries(&[entry], "Test API", "1.0.0");
        assert_eq!(spec.openapi, "3.0.3");
        assert!(spec.paths.contains_key("/api/v1/users/{user_id}"));
        let path_item = spec.paths.get("/api/v1/users/{user_id}").unwrap();
        assert!(path_item.get.is_some());
        let op = path_item.get.as_ref().unwrap();
        assert_eq!(op.parameters.len(), 2); // path param + query param
        assert!(op.responses.contains_key("200"));
    }
}
