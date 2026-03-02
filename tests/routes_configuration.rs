mod common;

use anyhow::Result;
use aws_smithy_types::byte_stream::ByteStream;
use axum::{
    body::Body,
    http::{self, Request, StatusCode},
};
use serde_json::{json, Value as JsonValue};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use common::{read_body, setup_app};

#[tokio::test]
async fn definition_configuration_schema_get() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let schema = json!({
        "type": "object",
        "properties": { "enabled": { "type": "boolean" } },
        "required": ["enabled"],
        "additionalProperties": false
    });

    s3_client
        .put_object()
        .bucket("definition-configurations")
        .key("cfg-def-1/configuration.schema.json")
        .body(ByteStream::from(serde_json::to_vec(&schema)?))
        .send()
        .await?;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/definitions/cfg-def-1/configuration/schema")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);

    let body = read_body(resp).await?;
    let returned: JsonValue = serde_json::from_slice(&body)?;
    assert_eq!(returned, schema);

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();
    Ok(())
}

#[tokio::test]
async fn definition_configuration_put_and_get_flow() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let schema = json!({
        "type": "object",
        "properties": {
            "enabled": { "type": "boolean" },
            "name": { "type": "string" }
        },
        "required": ["enabled"],
        "additionalProperties": false
    });

    s3_client
        .put_object()
        .bucket("definition-configurations")
        .key("cfg-def-2/configuration.schema.json")
        .body(ByteStream::from(serde_json::to_vec(&schema)?))
        .send()
        .await?;

    let config = json!({ "enabled": true, "name": "hello" });

    let put_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/definitions/cfg-def-2/configuration")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&config)?))
                .unwrap(),
        )
        .await?;

    assert_eq!(put_resp.status(), StatusCode::NO_CONTENT);

    let get_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/definitions/cfg-def-2/configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;

    assert_eq!(get_resp.status(), StatusCode::OK);

    let get_body = read_body(get_resp).await?;
    let result: JsonValue = serde_json::from_slice(&get_body)?;

    assert_eq!(result["configuration"], config);
    assert_eq!(result["validation"]["valid"], json!(true));

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();
    Ok(())
}

/// Verifies that putting an invalid configuration against a definition is rejected and not stored.
///
/// This test uploads a JSON Schema requiring a boolean `enabled` property, attempts to PUT a
/// configuration where `enabled` is a string, asserts the handler responds with HTTP 400, and
/// confirms no configuration object was written to S3.
#[tokio::test]
async fn definition_configuration_put_rejects_invalid() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let schema = json!({
        "type": "object",
        "properties": { "enabled": { "type": "boolean" } },
        "required": ["enabled"],
        "additionalProperties": false
    });

    s3_client
        .put_object()
        .bucket("definition-configurations")
        .key("cfg-def-3/configuration.schema.json")
        .body(ByteStream::from(serde_json::to_vec(&schema)?))
        .send()
        .await?;

    let invalid_config = json!({ "enabled": "not-a-bool" });

    let put_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/definitions/cfg-def-3/configuration")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&invalid_config)?))
                .unwrap(),
        )
        .await?;

    assert_eq!(put_resp.status(), StatusCode::BAD_REQUEST);

    let listing = s3_client
        .list_objects_v2()
        .bucket("definition-configurations")
        .prefix("cfg-def-3/configuration.json")
        .send()
        .await?;
    assert!(listing.contents().is_empty());

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();
    Ok(())
}

/// Verifies that retrieving a definition's configuration returns the stored configuration along
/// with validation results when the configuration violates its schema.
#[tokio::test]
async fn definition_configuration_get_returns_validation_errors() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let schema = json!({
        "type": "object",
        "properties": { "enabled": { "type": "boolean" } },
        "required": ["enabled"],
        "additionalProperties": false
    });

    let bad_config = json!({ "enabled": 42 });

    s3_client
        .put_object()
        .bucket("definition-configurations")
        .key("cfg-def-4/configuration.schema.json")
        .body(ByteStream::from(serde_json::to_vec(&schema)?))
        .send()
        .await?;

    s3_client
        .put_object()
        .bucket("definition-configurations")
        .key("cfg-def-4/configuration.json")
        .body(ByteStream::from(serde_json::to_vec(&bad_config)?))
        .send()
        .await?;

    let get_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/definitions/cfg-def-4/configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;

    assert_eq!(get_resp.status(), StatusCode::OK);

    let body = read_body(get_resp).await?;
    let result: JsonValue = serde_json::from_slice(&body)?;

    assert_eq!(result["configuration"], bad_config);
    assert_eq!(result["validation"]["valid"], json!(false));

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();
    Ok(())
}

#[tokio::test]
async fn definition_configuration_patch_applies_operations() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let schema = json!({
        "type": "object",
        "properties": {
            "enabled": { "type": "boolean" },
            "name": { "type": "string" },
            "count": { "type": "integer" }
        },
        "additionalProperties": false
    });

    let config = json!({ "enabled": true, "name": "hello" });

    s3_client
        .put_object()
        .bucket("definition-configurations")
        .key("cfg-def-patch-1/configuration.schema.json")
        .body(ByteStream::from(serde_json::to_vec(&schema)?))
        .send()
        .await?;

    s3_client
        .put_object()
        .bucket("definition-configurations")
        .key("cfg-def-patch-1/configuration.json")
        .body(ByteStream::from(serde_json::to_vec(&config)?))
        .send()
        .await?;

    let patch_ops = json!([
        { "op": "replace", "path": "/name", "value": "world" },
        { "op": "add", "path": "/count", "value": 42 }
    ]);

    let patch_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/definitions/cfg-def-patch-1/configuration")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&patch_ops)?))
                .unwrap(),
        )
        .await?;

    assert_eq!(patch_resp.status(), StatusCode::OK);

    let body = read_body(patch_resp).await?;
    let result: JsonValue = serde_json::from_slice(&body)?;

    assert_eq!(
        result,
        json!({ "enabled": true, "name": "world", "count": 42 })
    );

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();
    Ok(())
}

#[tokio::test]
async fn definition_configuration_patch_defaults_to_empty_object() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let schema = json!({
        "type": "object",
        "properties": {
            "enabled": { "type": "boolean" }
        },
        "additionalProperties": false
    });

    s3_client
        .put_object()
        .bucket("definition-configurations")
        .key("cfg-def-patch-2/configuration.schema.json")
        .body(ByteStream::from(serde_json::to_vec(&schema)?))
        .send()
        .await?;

    let patch_ops = json!([
        { "op": "add", "path": "/enabled", "value": true }
    ]);

    let patch_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/definitions/cfg-def-patch-2/configuration")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&patch_ops)?))
                .unwrap(),
        )
        .await?;

    assert_eq!(patch_resp.status(), StatusCode::OK);

    let body = read_body(patch_resp).await?;
    let result: JsonValue = serde_json::from_slice(&body)?;

    assert_eq!(result, json!({ "enabled": true }));

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();
    Ok(())
}

#[tokio::test]
async fn definition_configuration_patch_rejects_invalid_result() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let schema = json!({
        "type": "object",
        "properties": {
            "enabled": { "type": "boolean" }
        },
        "additionalProperties": false
    });

    let config = json!({ "enabled": true });

    s3_client
        .put_object()
        .bucket("definition-configurations")
        .key("cfg-def-patch-3/configuration.schema.json")
        .body(ByteStream::from(serde_json::to_vec(&schema)?))
        .send()
        .await?;

    s3_client
        .put_object()
        .bucket("definition-configurations")
        .key("cfg-def-patch-3/configuration.json")
        .body(ByteStream::from(serde_json::to_vec(&config)?))
        .send()
        .await?;

    let patch_ops = json!([
        { "op": "add", "path": "/extra", "value": "not allowed" }
    ]);

    let patch_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/definitions/cfg-def-patch-3/configuration")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&patch_ops)?))
                .unwrap(),
        )
        .await?;

    assert_eq!(patch_resp.status(), StatusCode::BAD_REQUEST);

    let get_obj = s3_client
        .get_object()
        .bucket("definition-configurations")
        .key("cfg-def-patch-3/configuration.json")
        .send()
        .await?;
    let stored_bytes = get_obj.body.collect().await?.into_bytes();
    let stored: JsonValue = serde_json::from_slice(&stored_bytes)?;
    assert_eq!(stored, json!({ "enabled": true }));

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();
    Ok(())
}

#[tokio::test]
async fn definition_configuration_patch_test_op_failure() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let schema = json!({
        "type": "object",
        "properties": {
            "enabled": { "type": "boolean" }
        },
        "additionalProperties": false
    });

    let config = json!({ "enabled": true });

    s3_client
        .put_object()
        .bucket("definition-configurations")
        .key("cfg-def-patch-4/configuration.schema.json")
        .body(ByteStream::from(serde_json::to_vec(&schema)?))
        .send()
        .await?;

    s3_client
        .put_object()
        .bucket("definition-configurations")
        .key("cfg-def-patch-4/configuration.json")
        .body(ByteStream::from(serde_json::to_vec(&config)?))
        .send()
        .await?;

    let patch_ops = json!([
        { "op": "test", "path": "/enabled", "value": false },
        { "op": "replace", "path": "/enabled", "value": false }
    ]);

    let patch_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/definitions/cfg-def-patch-4/configuration")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&patch_ops)?))
                .unwrap(),
        )
        .await?;

    assert_eq!(patch_resp.status(), StatusCode::BAD_REQUEST);

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();
    Ok(())
}

// --- Module configurations ---

#[tokio::test]
async fn module_configuration_schema_get() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let schema = json!({
        "type": "object",
        "properties": { "port": { "type": "integer" } },
        "required": ["port"]
    });

    s3_client
        .put_object()
        .bucket("module-configurations")
        .key("cfg-mod-1/configuration.schema.json")
        .body(ByteStream::from(serde_json::to_vec(&schema)?))
        .send()
        .await?;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/modules/cfg-mod-1/configuration/schema")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);

    let body = read_body(resp).await?;
    let returned: JsonValue = serde_json::from_slice(&body)?;
    assert_eq!(returned, schema);

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();
    Ok(())
}

/// Verifies that putting a valid module configuration stores it and that it can be retrieved
/// with successful schema validation.
#[tokio::test]
async fn module_configuration_put_and_get_flow() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let schema = json!({
        "type": "object",
        "properties": {
            "port": { "type": "integer" },
            "host": { "type": "string" }
        },
        "required": ["port"],
        "additionalProperties": false
    });

    s3_client
        .put_object()
        .bucket("module-configurations")
        .key("cfg-mod-2/configuration.schema.json")
        .body(ByteStream::from(serde_json::to_vec(&schema)?))
        .send()
        .await?;

    let config = json!({ "port": 8080, "host": "localhost" });

    let put_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/modules/cfg-mod-2/configuration")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&config)?))
                .unwrap(),
        )
        .await?;

    assert_eq!(put_resp.status(), StatusCode::NO_CONTENT);

    let get_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/modules/cfg-mod-2/configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;

    assert_eq!(get_resp.status(), StatusCode::OK);

    let get_body = read_body(get_resp).await?;
    let result: JsonValue = serde_json::from_slice(&get_body)?;

    assert_eq!(result["configuration"], config);
    assert_eq!(result["validation"]["valid"], json!(true));

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();
    Ok(())
}

#[tokio::test]
async fn module_configuration_put_rejects_invalid() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let schema = json!({
        "type": "object",
        "properties": { "port": { "type": "integer" } },
        "required": ["port"],
        "additionalProperties": false
    });

    s3_client
        .put_object()
        .bucket("module-configurations")
        .key("cfg-mod-3/configuration.schema.json")
        .body(ByteStream::from(serde_json::to_vec(&schema)?))
        .send()
        .await?;

    let invalid_config = json!({ "port": "not-a-number" });

    let put_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/modules/cfg-mod-3/configuration")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&invalid_config)?))
                .unwrap(),
        )
        .await?;

    assert_eq!(put_resp.status(), StatusCode::BAD_REQUEST);

    let listing = s3_client
        .list_objects_v2()
        .bucket("module-configurations")
        .prefix("cfg-mod-3/configuration.json")
        .send()
        .await?;
    assert!(listing.contents().is_empty());

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();
    Ok(())
}

#[tokio::test]
async fn module_configuration_get_returns_validation_errors() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let schema = json!({
        "type": "object",
        "properties": { "port": { "type": "integer" } },
        "required": ["port"],
        "additionalProperties": false
    });

    let bad_config = json!({ "port": "wrong" });

    s3_client
        .put_object()
        .bucket("module-configurations")
        .key("cfg-mod-4/configuration.schema.json")
        .body(ByteStream::from(serde_json::to_vec(&schema)?))
        .send()
        .await?;

    s3_client
        .put_object()
        .bucket("module-configurations")
        .key("cfg-mod-4/configuration.json")
        .body(ByteStream::from(serde_json::to_vec(&bad_config)?))
        .send()
        .await?;

    let get_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/modules/cfg-mod-4/configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;

    assert_eq!(get_resp.status(), StatusCode::OK);

    let body = read_body(get_resp).await?;
    let result: JsonValue = serde_json::from_slice(&body)?;

    assert_eq!(result["configuration"], bad_config);
    assert_eq!(result["validation"]["valid"], json!(false));

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();
    Ok(())
}

#[tokio::test]
async fn module_configuration_patch_applies_operations() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let schema = json!({
        "type": "object",
        "properties": {
            "host": { "type": "string" },
            "port": { "type": "integer" }
        },
        "additionalProperties": false
    });

    let config = json!({ "host": "localhost", "port": 8080 });

    s3_client
        .put_object()
        .bucket("module-configurations")
        .key("cfg-mod-patch-1/configuration.schema.json")
        .body(ByteStream::from(serde_json::to_vec(&schema)?))
        .send()
        .await?;

    s3_client
        .put_object()
        .bucket("module-configurations")
        .key("cfg-mod-patch-1/configuration.json")
        .body(ByteStream::from(serde_json::to_vec(&config)?))
        .send()
        .await?;

    let patch_ops = json!([
        { "op": "replace", "path": "/port", "value": 9090 },
        { "op": "remove", "path": "/host" }
    ]);

    let patch_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/modules/cfg-mod-patch-1/configuration")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&patch_ops)?))
                .unwrap(),
        )
        .await?;

    assert_eq!(patch_resp.status(), StatusCode::OK);

    let body = read_body(patch_resp).await?;
    let result: JsonValue = serde_json::from_slice(&body)?;

    assert_eq!(result, json!({ "port": 9090 }));

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();
    Ok(())
}

#[tokio::test]
async fn module_configuration_patch_rejects_invalid_result() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let schema = json!({
        "type": "object",
        "properties": {
            "port": { "type": "integer" }
        },
        "required": ["port"],
        "additionalProperties": false
    });

    let config = json!({ "port": 8080 });

    s3_client
        .put_object()
        .bucket("module-configurations")
        .key("cfg-mod-patch-2/configuration.schema.json")
        .body(ByteStream::from(serde_json::to_vec(&schema)?))
        .send()
        .await?;

    s3_client
        .put_object()
        .bucket("module-configurations")
        .key("cfg-mod-patch-2/configuration.json")
        .body(ByteStream::from(serde_json::to_vec(&config)?))
        .send()
        .await?;

    let patch_ops = json!([
        { "op": "remove", "path": "/port" }
    ]);

    let patch_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/modules/cfg-mod-patch-2/configuration")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&patch_ops)?))
                .unwrap(),
        )
        .await?;

    assert_eq!(patch_resp.status(), StatusCode::BAD_REQUEST);

    let get_obj = s3_client
        .get_object()
        .bucket("module-configurations")
        .key("cfg-mod-patch-2/configuration.json")
        .send()
        .await?;
    let stored_bytes = get_obj.body.collect().await?.into_bytes();
    let stored: JsonValue = serde_json::from_slice(&stored_bytes)?;
    assert_eq!(stored, json!({ "port": 8080 }));

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();
    Ok(())
}

// --- Delete cascade ---

/// Verifies that deleting a definition also removes its configuration from S3.
#[tokio::test]
async fn delete_definition_also_deletes_configuration() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let temp_dir = tempfile::TempDir::new()?;
    let file_path = temp_dir.path().join("def.json");
    let file_body = br#"{"hello":"world"}"#;
    std::fs::write(&file_path, file_body)?;
    let digest = format!("sha256:{:x}", Sha256::digest(file_body));

    let create_payload = json!({
        "id": "cfg-def-del",
        "name": "Def With Config",
        "type": "test-type",
        "description": "Will be deleted",
        "file_url": file_path.to_string_lossy(),
        "digest": digest,
    });

    let create_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/definitions")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&create_payload)?))
                .unwrap(),
        )
        .await?;
    assert_eq!(create_resp.status(), StatusCode::CREATED);

    let schema = json!({ "type": "object", "properties": { "enabled": { "type": "boolean" } } });
    let config = json!({ "enabled": true });

    s3_client
        .put_object()
        .bucket("definition-configurations")
        .key("cfg-def-del/configuration.schema.json")
        .body(ByteStream::from(serde_json::to_vec(&schema)?))
        .send()
        .await?;

    s3_client
        .put_object()
        .bucket("definition-configurations")
        .key("cfg-def-del/configuration.json")
        .body(ByteStream::from(serde_json::to_vec(&config)?))
        .send()
        .await?;

    let del_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/definitions/cfg-def-del")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    assert_eq!(del_resp.status(), StatusCode::NO_CONTENT);

    let listing = s3_client
        .list_objects_v2()
        .bucket("definition-configurations")
        .prefix("cfg-def-del/")
        .send()
        .await?;
    assert!(listing.contents().is_empty());

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();
    Ok(())
}

/// Verifies that deleting a module also removes its configuration from S3.
#[tokio::test]
async fn delete_module_also_deletes_configuration() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let temp_dir = tempfile::TempDir::new()?;
    let file_path = temp_dir.path().join("module.wasm");
    let file_body = b"\0asm\x01\0\0\0";
    std::fs::write(&file_path, file_body)?;
    let digest = format!("sha256:{:x}", Sha256::digest(file_body));

    let create_payload = json!({
        "id": "cfg-mod-del",
        "name": "Module With Config",
        "type": "proxy",
        "description": "Will be deleted",
        "file_url": file_path.to_string_lossy(),
        "digest": digest,
    });

    let create_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/modules")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&create_payload)?))
                .unwrap(),
        )
        .await?;
    assert_eq!(create_resp.status(), StatusCode::CREATED);

    let schema = json!({ "type": "object", "properties": { "port": { "type": "integer" } } });
    let config = json!({ "port": 8080 });

    s3_client
        .put_object()
        .bucket("module-configurations")
        .key("cfg-mod-del/configuration.schema.json")
        .body(ByteStream::from(serde_json::to_vec(&schema)?))
        .send()
        .await?;

    s3_client
        .put_object()
        .bucket("module-configurations")
        .key("cfg-mod-del/configuration.json")
        .body(ByteStream::from(serde_json::to_vec(&config)?))
        .send()
        .await?;

    let del_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/modules/cfg-mod-del")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    assert_eq!(del_resp.status(), StatusCode::NO_CONTENT);

    let listing = s3_client
        .list_objects_v2()
        .bucket("module-configurations")
        .prefix("cfg-mod-del/")
        .send()
        .await?;
    assert!(listing.contents().is_empty());

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();
    Ok(())
}
