//! Postman Collection (v2.1.0) Specification Exporter.
//!
//! Generates a valid Postman Collection v2.1.0 JSON format from intercepted HTTP traffic,
//! HAR logs, or live DecodedEvent streams. Compatible with Postman, Insomnia, Hoppscotch,
//! and Newman CLI test suites.

use crate::engine::event::{Direction, TlsEvent};
use crate::export::har::{HarEntry, HarRoot};
use crate::proto::http1::{Http1Message, Http1Parser};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostmanCollection {
    pub info: PostmanInfo,
    pub item: Vec<PostmanItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostmanInfo {
    pub _postman_id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub schema: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostmanItem {
    pub name: String,
    pub request: PostmanRequest,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostmanRequest {
    pub method: String,
    pub header: Vec<PostmanHeader>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<PostmanBody>,
    pub url: PostmanUrl,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostmanHeader {
    pub key: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostmanBody {
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<PostmanBodyOptions>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostmanBodyOptions {
    pub raw: PostmanRawOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostmanRawOptions {
    pub language: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostmanUrl {
    pub raw: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub query: Vec<PostmanQueryParam>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostmanQueryParam {
    pub key: String,
    pub value: String,
}

pub struct PostmanExporter;

impl PostmanExporter {
    pub const COLLECTION_SCHEMA: &'static str =
        "https://schema.getpostman.com/json/collection/v2.1.0/collection.json";

    /// Generates a Postman Collection from a raw HAR string.
    pub fn from_har_str(
        har_str: &str,
        name: Option<&str>,
    ) -> Result<PostmanCollection, serde_json::Error> {
        let root: HarRoot = serde_json::from_str(har_str)?;
        Ok(Self::from_har_entries(&root.log.entries, name))
    }

    /// Generates a Postman Collection from HAR entries.
    pub fn from_har_entries(entries: &[HarEntry], name: Option<&str>) -> PostmanCollection {
        let collection_name = name.unwrap_or("nullca Captured API Collection");
        let postman_id = format!(
            "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
            entries.len() as u32 ^ 0xa1b2c3d4,
            0x4f59,
            0xcd,
            0x8db2,
            0x11145d98ad00u64
        );

        let mut items = Vec::new();

        for entry in entries {
            let req = &entry.request;
            let method = req.method.to_uppercase();
            let parsed_url = Self::parse_url(&req.url);

            let item_name = format!("{} {}", method, parsed_url.path.join("/"));

            let headers: Vec<PostmanHeader> = req
                .headers
                .iter()
                .filter(|h| !h.name.starts_with(':'))
                .map(|h| PostmanHeader {
                    key: h.name.clone(),
                    value: h.value.clone(),
                    description: None,
                })
                .collect();

            let body = req.post_data.as_ref().and_then(|pd| {
                if pd.text.trim().is_empty() {
                    None
                } else {
                    let is_json = pd.mime_type.contains("json")
                        || pd.text.trim_start().starts_with('{')
                        || pd.text.trim_start().starts_with('[');
                    Some(PostmanBody {
                        mode: "raw".into(),
                        raw: Some(pd.text.clone()),
                        options: if is_json {
                            Some(PostmanBodyOptions {
                                raw: PostmanRawOptions {
                                    language: "json".into(),
                                },
                            })
                        } else {
                            None
                        },
                    })
                }
            });

            items.push(PostmanItem {
                name: if item_name.trim().is_empty() {
                    format!("{} /", method)
                } else {
                    item_name
                },
                request: PostmanRequest {
                    method,
                    header: headers,
                    body,
                    url: parsed_url,
                    description: None,
                },
                response: Vec::new(),
            });
        }

        PostmanCollection {
            info: PostmanInfo {
                _postman_id: postman_id,
                name: collection_name.to_string(),
                description: Some("Exported automatically by nullca network analyzer".into()),
                schema: Self::COLLECTION_SCHEMA.into(),
            },
            item: items,
        }
    }

    /// Generates a Postman Collection from decoded egress events.
    pub fn from_events(events: &[TlsEvent], name: Option<&str>) -> PostmanCollection {
        let mut entries = Vec::new();

        for ev in events {
            if ev.direction != Direction::Egress {
                continue;
            }

            if let Some(Http1Message::Request {
                headers,
                body,
                method,
                uri,
                ..
            }) = Http1Parser::parse(&ev.data)
            {
                let host = headers
                    .get("host")
                    .cloned()
                    .unwrap_or_else(|| "localhost".into());
                let full_url = if uri.starts_with("http://") || uri.starts_with("https://") {
                    uri.clone()
                } else {
                    format!("https://{}{}", host, uri)
                };

                let har_headers = headers
                    .into_iter()
                    .map(|(name, value)| crate::export::har::HarHeader { name, value })
                    .collect();

                let post_data = if !body.is_empty() {
                    Some(crate::export::har::HarPostData {
                        mime_type: "application/json".into(),
                        text: String::from_utf8_lossy(&body).into_owned(),
                    })
                } else {
                    None
                };

                entries.push(HarEntry {
                    started_date_time: "2026-11-05T00:00:00.000Z".into(),
                    time: 0.0,
                    request: crate::export::har::HarRequest {
                        method,
                        url: full_url,
                        http_version: "HTTP/1.1".into(),
                        headers: har_headers,
                        query_string: Vec::new(),
                        post_data,
                        headers_size: 0,
                        body_size: body.len() as i64,
                    },
                    response: crate::export::har::HarResponse {
                        status: 200,
                        status_text: "OK".into(),
                        http_version: "HTTP/1.1".into(),
                        headers: Vec::new(),
                        content: crate::export::har::HarContent {
                            size: 0,
                            mime_type: "text/plain".into(),
                            text: None,
                        },
                        redirect_url: String::new(),
                        headers_size: 0,
                        body_size: 0,
                    },
                    cache: serde_json::json!({}),
                    timings: crate::export::har::HarTimings {
                        send: 0.0,
                        wait: 0.0,
                        receive: 0.0,
                    },
                });
            }
        }

        Self::from_har_entries(&entries, name)
    }

    /// Saves collection to a JSON file.
    pub fn save_to_file<P: AsRef<Path>>(
        collection: &PostmanCollection,
        path: P,
    ) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(collection)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let mut f = File::create(path)?;
        f.write_all(json.as_bytes())?;
        f.flush()
    }

    fn parse_url(raw_url: &str) -> PostmanUrl {
        let (protocol, rest) = if let Some((proto, r)) = raw_url.split_once("://") {
            (Some(proto.to_string()), r)
        } else {
            (None, raw_url)
        };

        let (host_and_path, query_str) = if let Some((hp, q)) = rest.split_once('?') {
            (hp, Some(q))
        } else {
            (rest, None)
        };

        let (host_str, path_str) = if let Some((h, p)) = host_and_path.split_once('/') {
            (h, Some(p))
        } else {
            (host_and_path, None)
        };

        let host = if host_str.is_empty() {
            Vec::new()
        } else {
            host_str.split('.').map(|s| s.to_string()).collect()
        };

        let path = if let Some(p) = path_str {
            p.split('/')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect()
        } else {
            Vec::new()
        };

        let mut query = Vec::new();
        if let Some(qs) = query_str {
            for param in qs.split('&') {
                if param.is_empty() {
                    continue;
                }
                if let Some((k, v)) = param.split_once('=') {
                    query.push(PostmanQueryParam {
                        key: k.to_string(),
                        value: v.to_string(),
                    });
                } else {
                    query.push(PostmanQueryParam {
                        key: param.to_string(),
                        value: String::new(),
                    });
                }
            }
        }

        PostmanUrl {
            raw: raw_url.to_string(),
            protocol,
            host,
            path,
            query,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_postman_collection_generation_from_har() {
        let har_json = r#"{
            "log": {
                "version": "1.2",
                "creator": { "name": "nullca", "version": "0.1.0" },
                "entries": [
                    {
                        "startedDateTime": "2026-11-05T00:00:00Z",
                        "time": 25.0,
                        "request": {
                            "method": "POST",
                            "url": "https://api.example.com/v1/auth/login?ref=portal",
                            "httpVersion": "HTTP/1.1",
                            "headers": [
                                { "name": "Content-Type", "value": "application/json" },
                                { "name": "User-Agent", "value": "nullca/0.1.0" }
                            ],
                            "queryString": [],
                            "postData": {
                                "mimeType": "application/json",
                                "text": "{\"username\":\"admin\",\"password\":\"supersecret\"}"
                            },
                            "headersSize": 128,
                            "bodySize": 46
                        },
                        "response": {
                            "status": 200,
                            "statusText": "OK",
                            "httpVersion": "HTTP/1.1",
                            "headers": [],
                            "content": { "size": 0, "mimeType": "application/json" },
                            "redirectURL": "",
                            "headersSize": 64,
                            "bodySize": 0
                        },
                        "cache": {},
                        "timings": { "send": 1.0, "wait": 15.0, "receive": 9.0 }
                    }
                ]
            }
        }"#;

        let col = PostmanExporter::from_har_str(har_json, Some("Auth Service Tests"))
            .expect("Must parse HAR into Postman Collection");

        assert_eq!(col.info.name, "Auth Service Tests");
        assert_eq!(col.info.schema, PostmanExporter::COLLECTION_SCHEMA);
        assert_eq!(col.item.len(), 1);

        let item = &col.item[0];
        assert_eq!(item.request.method, "POST");
        assert_eq!(item.request.url.protocol.as_deref(), Some("https"));
        assert_eq!(item.request.url.host, vec!["api", "example", "com"]);
        assert_eq!(item.request.url.path, vec!["v1", "auth", "login"]);
        assert_eq!(item.request.url.query.len(), 1);
        assert_eq!(item.request.url.query[0].key, "ref");
        assert_eq!(item.request.url.query[0].value, "portal");

        let body = item.request.body.as_ref().expect("Body must be present");
        assert_eq!(body.mode, "raw");
        assert!(body.raw.as_deref().unwrap().contains("admin"));

        let serialized = serde_json::to_string_pretty(&col).expect("Must serialize to JSON");
        assert!(serialized
            .contains("https://schema.getpostman.com/json/collection/v2.1.0/collection.json"));
    }

    #[test]
    fn test_postman_collection_generation_from_events() {
        let raw_req = b"GET /api/v2/items?category=books&limit=20 HTTP/1.1\r\nHost: store.internal\r\nAccept: application/json\r\n\r\n";
        let ev = TlsEvent::new(
            1000,
            123,
            123,
            4,
            Direction::Egress,
            "curl".into(),
            raw_req.to_vec(),
            None,
        );

        let col = PostmanExporter::from_events(&[ev], None);
        assert_eq!(col.item.len(), 1);
        let req = &col.item[0].request;
        assert_eq!(req.method, "GET");
        assert_eq!(req.url.host, vec!["store", "internal"]);
        assert_eq!(req.url.path, vec!["api", "v2", "items"]);
        assert_eq!(req.url.query.len(), 2);
        assert_eq!(req.url.query[0].key, "category");
        assert_eq!(req.url.query[0].value, "books");
        assert_eq!(req.url.query[1].key, "limit");
        assert_eq!(req.url.query[1].value, "20");
    }
}
