use super::*;

#[cfg(test)]
mod test_resource_kind {
    use super::*;

    #[test]
    fn definition_config_bucket() {
        assert_eq!(
            ResourceKind::Definition.config_bucket(),
            "definition-configurations"
        );
    }

    #[test]
    fn module_config_bucket() {
        assert_eq!(
            ResourceKind::Module.config_bucket(),
            "module-configurations"
        );
    }

    #[test]
    fn definition_secrets_bucket() {
        assert_eq!(
            ResourceKind::Definition.secrets_bucket(),
            "definition-secrets"
        );
    }

    #[test]
    fn module_secrets_bucket() {
        assert_eq!(ResourceKind::Module.secrets_bucket(), "module-secrets");
    }
}

#[cfg(test)]
mod test_validate_schema {
    use super::*;
    use serde_json::json;

    fn required_object_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" },
                "port": { "type": "integer" }
            },
            "required": ["name", "port"]
        })
    }

    #[test]
    fn valid_data_reports_valid_true() {
        let data = json!({ "name": "myapp", "port": 8080 });
        let output =
            validate_schema(&required_object_schema(), &data).expect("should produce output");
        assert_eq!(output["valid"], json!(true));
        assert!(output.get("details").is_some());
    }

    #[test]
    fn type_mismatch_reports_valid_false_with_details() {
        let data = json!({ "name": 123, "port": "not-a-number" });
        let output =
            validate_schema(&required_object_schema(), &data).expect("should produce output");
        assert_eq!(output["valid"], json!(false));
        let details = output["details"]
            .as_array()
            .expect("details should be an array");
        assert!(!details.is_empty());
        let first = &details[0];
        assert!(first.get("valid").is_some());
        assert!(first.get("evaluationPath").is_some());
        assert!(first.get("instanceLocation").is_some());
        assert!(first.get("schemaLocation").is_some());
    }

    #[test]
    fn missing_required_field_reports_valid_false() {
        let data = json!({ "name": "myapp" }); // port missing
        let output =
            validate_schema(&required_object_schema(), &data).expect("should produce output");
        assert_eq!(output["valid"], json!(false));
    }

    #[test]
    fn additional_properties_rejected_when_blocked() {
        let schema = json!({
            "type": "object",
            "properties": { "name": { "type": "string" } },
            "additionalProperties": false
        });
        let data = json!({ "name": "ok", "extra": "not-allowed" });
        let output = validate_schema(&schema, &data).expect("should produce output");
        assert_eq!(output["valid"], json!(false));
    }

    #[test]
    fn empty_object_valid_when_no_required_fields() {
        let schema = json!({
            "type": "object",
            "properties": { "name": { "type": "string" } }
        });
        let output = validate_schema(&schema, &json!({})).expect("should produce output");
        assert_eq!(output["valid"], json!(true));
    }

    #[test]
    fn malformed_schema_returns_err() {
        let bad_schema = json!({ "type": "not-a-real-type-xyz" });
        let result = validate_schema(&bad_schema, &json!({}));
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod test_filter {
    use super::*;

    #[test]
    fn default_all_none() {
        let f: Filter<String> = Filter::default();
        assert!(f.query.is_none());
        assert!(f.is_enabled.is_none());
        assert!(f.r#type.is_none());
        assert!(f.limit.is_none());
        assert!(f.offset.is_none());
        assert!(f.sort_by.is_none());
        assert!(f.sort_order.is_none());
    }

    #[test]
    fn deserializes_from_json() {
        let json = serde_json::json!({
            "query": "foo",
            "is_enabled": true,
            "limit": 10,
            "offset": 5,
            "sort_by": "Name",
            "sort_order": "Asc"
        });
        let f: Filter<String> = serde_json::from_value(json).unwrap();
        assert_eq!(f.query.unwrap(), "foo");
        assert_eq!(f.is_enabled.unwrap(), true);
        assert_eq!(f.limit.unwrap(), 10);
        assert_eq!(f.offset.unwrap(), 5);
    }
}

#[cfg(test)]
mod test_payload {
    use super::*;
    use serde_json::json;

    #[test]
    fn roundtrip_serialize_deserialize() {
        let p = Payload::<String> {
            id: "id-1".into(),
            name: "my-payload".into(),
            r#type: "kind-a".into(),
            description: "a test payload".into(),
            file_url: "https://example.com/file".into(),
            digest: "sha256:abc123".into(),
            source_url: Some("https://example.com/source".into()),
        };
        let serialized = serde_json::to_string(&p).unwrap();
        let deserialized: Payload<String> = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.id, p.id);
        assert_eq!(deserialized.name, p.name);
        assert_eq!(deserialized.source_url, p.source_url);
    }

    #[test]
    fn source_url_can_be_none() {
        let json = json!({
            "id": "x",
            "name": "y",
            "type": "z",
            "description": "d",
            "file_url": "https://example.com",
            "digest": "abc"
        });
        let p: Payload<String> = serde_json::from_value(json).unwrap();
        assert!(p.source_url.is_none());
    }
}

#[cfg(test)]
mod test_fetch_payload {
    use super::*;
    use crate::utils::source::Source;
    use serde::{Deserialize, Serialize};
    use std::path::PathBuf;
    use tokio::fs;
    use wiremock::{
        matchers::{header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[derive(Debug, Deserialize, Serialize, PartialEq)]
    struct TestPayload {
        id: String,
        value: u32,
    }

    fn test_payload() -> TestPayload {
        TestPayload {
            id: "abc".into(),
            value: 42,
        }
    }

    fn http_client() -> reqwest::Client {
        reqwest::Client::new()
    }

    #[tokio::test]
    async fn http_fetches_and_deserializes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/payload"))
            .and(header("User-Agent", "MCI/1.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&test_payload()))
            .mount(&server)
            .await;

        let url = format!("{}/payload", server.uri());
        let source = Source::Http(url);
        let result: anyhow::Result<TestPayload> =
            fetch_payload(&http_client(), &source, "test").await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), test_payload());
    }

    #[tokio::test]
    async fn http_non_2xx_returns_err() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/payload"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let url = format!("{}/payload", server.uri());
        let source = Source::Http(url);
        let result: anyhow::Result<TestPayload> =
            fetch_payload(&http_client(), &source, "test").await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn http_invalid_json_returns_err() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/payload"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;

        let url = format!("{}/payload", server.uri());
        let source = Source::Http(url);
        let result: anyhow::Result<TestPayload> =
            fetch_payload(&http_client(), &source, "test").await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn file_reads_and_deserializes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.json");
        fs::write(&path, serde_json::to_string(&test_payload()).unwrap())
            .await
            .unwrap();

        let source = Source::File(path);
        let result: anyhow::Result<TestPayload> =
            fetch_payload(&http_client(), &source, "test").await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), test_payload());
    }

    #[tokio::test]
    async fn file_missing_returns_err() {
        let source = Source::File(PathBuf::from("/nonexistent/path/payload.json"));
        let result: anyhow::Result<TestPayload> =
            fetch_payload(&http_client(), &source, "test").await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn file_invalid_json_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.json");
        fs::write(&path, "this is not json").await.unwrap();

        let source = Source::File(path);
        let result: anyhow::Result<TestPayload> =
            fetch_payload(&http_client(), &source, "test").await;

        assert!(result.is_err());
    }
}

#[cfg(test)]
mod test_sort_enums {
    use super::*;

    #[test]
    fn sort_by_deserializes() {
        let id: SortBy = serde_json::from_str("\"Id\"").unwrap();
        let name: SortBy = serde_json::from_str("\"Name\"").unwrap();
        let kind: SortBy = serde_json::from_str("\"Type\"").unwrap();
        assert!(matches!(id, SortBy::Id));
        assert!(matches!(name, SortBy::Name));
        assert!(matches!(kind, SortBy::Type));
    }

    #[test]
    fn sort_order_deserializes() {
        let asc: SortOrder = serde_json::from_str("\"Asc\"").unwrap();
        let desc: SortOrder = serde_json::from_str("\"Desc\"").unwrap();
        assert!(matches!(asc, SortOrder::Asc));
        assert!(matches!(desc, SortOrder::Desc));
    }

    #[test]
    fn sort_by_invalid_returns_err() {
        let result: Result<SortBy, _> = serde_json::from_str("\"Invalid\"");
        assert!(result.is_err());
    }
}
