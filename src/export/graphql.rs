//! Automated GraphQL AST & Schema (.graphqls) Synthesizer.
//!
//! Reconstructs GraphQL Type Definitions, Queries, and Mutations from
//! intercepted HTTP transactions without needing access to backend source code.

use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GqlFieldType {
    Id,
    String,
    Int,
    Float,
    Boolean,
    Object(String),
    List(Box<GqlFieldType>),
}

impl GqlFieldType {
    pub fn to_graphql_string(&self) -> String {
        match self {
            GqlFieldType::Id => "ID".to_string(),
            GqlFieldType::String => "String".to_string(),
            GqlFieldType::Int => "Int".to_string(),
            GqlFieldType::Float => "Float".to_string(),
            GqlFieldType::Boolean => "Boolean".to_string(),
            GqlFieldType::Object(name) => name.clone(),
            GqlFieldType::List(inner) => format!("[{}]", inner.to_graphql_string()),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct GqlObjectType {
    pub name: String,
    pub fields: BTreeMap<String, GqlFieldType>,
}

#[derive(Debug, Clone, Default)]
pub struct GraphQLSchema {
    pub query_fields: BTreeMap<String, GqlFieldType>,
    pub mutation_fields: BTreeMap<String, GqlFieldType>,
    pub types: BTreeMap<String, GqlObjectType>,
}

impl GraphQLSchema {
    /// Serializes schema into standard GraphQL Schema Definition Language (SDL).
    pub fn to_sdl_string(&self) -> String {
        let mut out = String::new();
        out.push_str("# GraphQL Schema automatically synthesized by NullCA Zero-CA Engine\n\n");

        if !self.query_fields.is_empty() {
            out.push_str("type Query {\n");
            for (f_name, f_type) in &self.query_fields {
                out.push_str(&format!("  {}: {}\n", f_name, f_type.to_graphql_string()));
            }
            out.push_str("}\n\n");
        }

        if !self.mutation_fields.is_empty() {
            out.push_str("type Mutation {\n");
            for (f_name, f_type) in &self.mutation_fields {
                out.push_str(&format!("  {}: {}\n", f_name, f_type.to_graphql_string()));
            }
            out.push_str("}\n\n");
        }

        for (type_name, obj_type) in &self.types {
            out.push_str(&format!("type {} {{\n", type_name));
            for (field, field_type) in &obj_type.fields {
                out.push_str(&format!(
                    "  {}: {}\n",
                    field,
                    field_type.to_graphql_string()
                ));
            }
            out.push_str("}\n\n");
        }

        out
    }
}

pub struct GraphQLSynthesizer;

impl GraphQLSynthesizer {
    /// Ingests request payload and response JSON to update the inferred schema.
    pub fn ingest_exchange(schema: &mut GraphQLSchema, request_body: &[u8], response_body: &[u8]) {
        let req_json: Value = match serde_json::from_slice(request_body) {
            Ok(v) => v,
            Err(_) => return,
        };

        let res_json: Value = match serde_json::from_slice(response_body) {
            Ok(v) => v,
            Err(_) => return,
        };

        let query_str = match req_json.get("query").and_then(|q| q.as_str()) {
            Some(q) => q,
            None => return,
        };

        let is_mutation = query_str.trim_start().starts_with("mutation");

        // Infer fields from response "data" object
        if let Some(data) = res_json.get("data").and_then(|d| d.as_object()) {
            for (root_field, val) in data {
                let inferred_type = Self::infer_type(schema, root_field, val, 0);
                if is_mutation {
                    schema
                        .mutation_fields
                        .insert(root_field.clone(), inferred_type);
                } else {
                    schema
                        .query_fields
                        .insert(root_field.clone(), inferred_type);
                }
            }
        }
    }

    pub const MAX_GQL_DEPTH: usize = 32;

    fn infer_type(
        schema: &mut GraphQLSchema,
        field_name: &str,
        val: &Value,
        depth: usize,
    ) -> GqlFieldType {
        if depth >= Self::MAX_GQL_DEPTH {
            return GqlFieldType::String;
        }

        match val {
            Value::Null => GqlFieldType::String,
            Value::Bool(_) => GqlFieldType::Boolean,
            Value::Number(n) => {
                if n.is_i64() || n.is_u64() {
                    if field_name.eq_ignore_ascii_case("id")
                        || field_name.ends_with("_id")
                        || field_name.ends_with("Id")
                    {
                        GqlFieldType::Id
                    } else {
                        GqlFieldType::Int
                    }
                } else {
                    GqlFieldType::Float
                }
            }
            Value::String(_) => {
                if field_name.eq_ignore_ascii_case("id")
                    || field_name.ends_with("_id")
                    || field_name.ends_with("Id")
                {
                    GqlFieldType::Id
                } else {
                    GqlFieldType::String
                }
            }
            Value::Array(arr) => {
                let inner = if let Some(first) = arr.first() {
                    Self::infer_type(schema, field_name, first, depth + 1)
                } else {
                    GqlFieldType::String
                };
                GqlFieldType::List(Box::new(inner))
            }
            Value::Object(map) => {
                // Capitalize field name as Type Name (e.g. user -> User)
                let type_name = Self::to_pascal_case(field_name);
                let mut fields = BTreeMap::new();
                for (k, v) in map {
                    let field_type = Self::infer_type(schema, k, v, depth + 1);
                    fields.insert(k.clone(), field_type);
                }

                let obj = schema
                    .types
                    .entry(type_name.clone())
                    .or_insert_with(|| GqlObjectType {
                        name: type_name.clone(),
                        fields: BTreeMap::new(),
                    });

                for (k, v) in fields {
                    obj.fields.insert(k, v);
                }

                GqlFieldType::Object(type_name)
            }
        }
    }

    fn to_pascal_case(s: &str) -> String {
        let mut out = String::new();
        let mut cap = true;
        for c in s.chars() {
            if c == '_' || c == '-' {
                cap = true;
            } else if cap {
                out.extend(c.to_uppercase());
                cap = false;
            } else {
                out.push(c);
            }
        }
        if out.is_empty() {
            "Item".to_string()
        } else {
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_graphql_schema_inference() {
        let mut schema = GraphQLSchema::default();

        let req = json!({
            "query": "query GetUserProfile { user(id: 1) { id username email score roles } }"
        })
        .to_string();

        let res = json!({
            "data": {
                "user": {
                    "id": "usr_998811",
                    "username": "mikhael",
                    "email": "mikhail@nullca.org",
                    "score": 42.5,
                    "roles": ["admin", "researcher"]
                }
            }
        })
        .to_string();

        GraphQLSynthesizer::ingest_exchange(&mut schema, req.as_bytes(), res.as_bytes());

        assert!(schema.query_fields.contains_key("user"));
        assert!(schema.types.contains_key("User"));

        let user_type = schema.types.get("User").unwrap();
        assert_eq!(user_type.fields.get("id"), Some(&GqlFieldType::Id));
        assert_eq!(
            user_type.fields.get("username"),
            Some(&GqlFieldType::String)
        );
        assert_eq!(user_type.fields.get("score"), Some(&GqlFieldType::Float));

        let sdl = schema.to_sdl_string();
        assert!(sdl.contains("type Query"));
        assert!(sdl.contains("user: User"));
        assert!(sdl.contains("type User {"));
    }
}
