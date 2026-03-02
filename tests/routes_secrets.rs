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
async fn get_definition_secrets_schema_returns_schema() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let schema = json!({
        "type": "object",
        "properties": {
            "api_key": { "type": "string" }
        },
        "required": ["api_key"]
    });

    s3_client
        .put_object()
        .bucket("definition-secrets")
        .key("sec-def-schema-1/secrets.schema.json")
        .body(ByteStream::from(serde_json::to_vec(&schema)?))
        .send()
        .await?;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/definitions/sec-def-schema-1/secrets/schema")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let body = read_body(response).await?;
    let returned: JsonValue = serde_json::from_slice(&body)?;
    assert_eq!(returned, schema);

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();
    Ok(())
}

/// Verifies that applying a JSON Patch to a definition's secrets stores the merged secrets and
/// returns 204 No Content.
#[tokio::test]
async fn patch_definition_secrets_applies_and_returns_no_content() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let schema = json!({
        "type": "object",
        "properties": {
            "api_key": { "type": "string" },
            "db_password": { "type": "string" }
        },
        "required": ["api_key"]
    });

    s3_client
        .put_object()
        .bucket("definition-secrets")
        .key("sec-def-patch-1/secrets.schema.json")
        .body(ByteStream::from(serde_json::to_vec(&schema)?))
        .send()
        .await?;

    let patch_ops = json!([
        { "op": "add", "path": "/api_key", "value": "sk-secret-123" }
    ]);

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/definitions/sec-def-patch-1/secrets")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&patch_ops)?))
                .unwrap(),
        )
        .await?;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let body = read_body(response).await?;
    assert!(body.is_empty());

    let get_obj = s3_client
        .get_object()
        .bucket("definition-secrets")
        .key("sec-def-patch-1/secrets.json")
        .send()
        .await?;
    let stored_bytes = get_obj.body.collect().await?.into_bytes();
    let stored: JsonValue = serde_json::from_slice(&stored_bytes)?;
    assert_eq!(stored, json!({ "api_key": "sk-secret-123" }));

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();
    Ok(())
}

#[tokio::test]
async fn patch_definition_secrets_defaults_to_empty_object() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let schema = json!({
        "type": "object",
        "properties": {
            "token": { "type": "string" }
        }
    });

    s3_client
        .put_object()
        .bucket("definition-secrets")
        .key("sec-def-patch-2/secrets.schema.json")
        .body(ByteStream::from(serde_json::to_vec(&schema)?))
        .send()
        .await?;

    let patch_ops = json!([
        { "op": "add", "path": "/token", "value": "tok-abc" }
    ]);

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/definitions/sec-def-patch-2/secrets")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&patch_ops)?))
                .unwrap(),
        )
        .await?;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let get_obj = s3_client
        .get_object()
        .bucket("definition-secrets")
        .key("sec-def-patch-2/secrets.json")
        .send()
        .await?;
    let stored_bytes = get_obj.body.collect().await?.into_bytes();
    let stored: JsonValue = serde_json::from_slice(&stored_bytes)?;
    assert_eq!(stored, json!({ "token": "tok-abc" }));

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();
    Ok(())
}

#[tokio::test]
async fn patch_definition_secrets_rejects_invalid_result() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let schema = json!({
        "type": "object",
        "properties": {
            "api_key": { "type": "string" }
        },
        "required": ["api_key"]
    });

    s3_client
        .put_object()
        .bucket("definition-secrets")
        .key("sec-def-patch-3/secrets.schema.json")
        .body(ByteStream::from(serde_json::to_vec(&schema)?))
        .send()
        .await?;

    s3_client
        .put_object()
        .bucket("definition-secrets")
        .key("sec-def-patch-3/secrets.json")
        .body(ByteStream::from(serde_json::to_vec(
            &json!({ "api_key": "sk-123" }),
        )?))
        .send()
        .await?;

    let patch_ops = json!([
        { "op": "remove", "path": "/api_key" }
    ]);

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/definitions/sec-def-patch-3/secrets")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&patch_ops)?))
                .unwrap(),
        )
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let get_obj = s3_client
        .get_object()
        .bucket("definition-secrets")
        .key("sec-def-patch-3/secrets.json")
        .send()
        .await?;
    let stored_bytes = get_obj.body.collect().await?.into_bytes();
    let stored: JsonValue = serde_json::from_slice(&stored_bytes)?;
    assert_eq!(stored, json!({ "api_key": "sk-123" }));

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();
    Ok(())
}

/// Verifies that deleting a definition also removes its secrets from S3.
#[tokio::test]
async fn delete_definition_also_deletes_secrets() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let temp_dir = tempfile::TempDir::new()?;
    let file_path = temp_dir.path().join("def.json");
    let file_body = br#"{"hello":"world"}"#;
    std::fs::write(&file_path, file_body)?;
    let digest = format!("sha256:{:x}", Sha256::digest(file_body));

    let create_payload = json!({
        "id": "sec-def-del",
        "name": "Def With Secrets",
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

    let schema = json!({
        "type": "object",
        "properties": { "api_key": { "type": "string" } },
        "required": ["api_key"]
    });
    let secrets = json!({ "api_key": "sk-secret-123" });

    s3_client
        .put_object()
        .bucket("definition-secrets")
        .key("sec-def-del/secrets.schema.json")
        .body(ByteStream::from(serde_json::to_vec(&schema)?))
        .send()
        .await?;

    s3_client
        .put_object()
        .bucket("definition-secrets")
        .key("sec-def-del/secrets.json")
        .body(ByteStream::from(serde_json::to_vec(&secrets)?))
        .send()
        .await?;

    let del_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/definitions/sec-def-del")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    assert_eq!(del_resp.status(), StatusCode::NO_CONTENT);

    let listing = s3_client
        .list_objects_v2()
        .bucket("definition-secrets")
        .prefix("sec-def-del/")
        .send()
        .await?;
    assert!(listing.contents().is_empty());

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();
    Ok(())
}

// --- Module secrets ---

#[tokio::test]
async fn get_module_secrets_schema_returns_schema() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let schema = json!({
        "type": "object",
        "properties": {
            "connection_string": { "type": "string" }
        },
        "required": ["connection_string"]
    });

    s3_client
        .put_object()
        .bucket("module-secrets")
        .key("sec-mod-schema-1/secrets.schema.json")
        .body(ByteStream::from(serde_json::to_vec(&schema)?))
        .send()
        .await?;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/modules/sec-mod-schema-1/secrets/schema")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let body = read_body(response).await?;
    let returned: JsonValue = serde_json::from_slice(&body)?;
    assert_eq!(returned, schema);

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();
    Ok(())
}

#[tokio::test]
async fn patch_module_secrets_applies_and_returns_no_content() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let schema = json!({
        "type": "object",
        "properties": {
            "connection_string": { "type": "string" }
        },
        "required": ["connection_string"]
    });

    s3_client
        .put_object()
        .bucket("module-secrets")
        .key("sec-mod-patch-1/secrets.schema.json")
        .body(ByteStream::from(serde_json::to_vec(&schema)?))
        .send()
        .await?;

    let patch_ops = json!([
        { "op": "add", "path": "/connection_string", "value": "postgres://secret@db/prod" }
    ]);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/modules/sec-mod-patch-1/secrets")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&patch_ops)?))
                .unwrap(),
        )
        .await?;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let body = read_body(response).await?;
    assert!(body.is_empty());

    let get_obj = s3_client
        .get_object()
        .bucket("module-secrets")
        .key("sec-mod-patch-1/secrets.json")
        .send()
        .await?;
    let stored_bytes = get_obj.body.collect().await?.into_bytes();
    let stored: JsonValue = serde_json::from_slice(&stored_bytes)?;
    assert_eq!(
        stored,
        json!({ "connection_string": "postgres://secret@db/prod" })
    );

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();
    Ok(())
}

/// Verifies that patching a module's secrets which produces an invalid document is rejected
/// and that the original secrets remain unchanged in S3.
#[tokio::test]
async fn patch_module_secrets_rejects_invalid_result() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let schema = json!({
        "type": "object",
        "properties": {
            "connection_string": { "type": "string" }
        },
        "required": ["connection_string"]
    });

    s3_client
        .put_object()
        .bucket("module-secrets")
        .key("sec-mod-patch-2/secrets.schema.json")
        .body(ByteStream::from(serde_json::to_vec(&schema)?))
        .send()
        .await?;

    s3_client
        .put_object()
        .bucket("module-secrets")
        .key("sec-mod-patch-2/secrets.json")
        .body(ByteStream::from(serde_json::to_vec(
            &json!({ "connection_string": "postgres://secret@db/prod" }),
        )?))
        .send()
        .await?;

    let patch_ops = json!([
        { "op": "remove", "path": "/connection_string" }
    ]);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/modules/sec-mod-patch-2/secrets")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&patch_ops)?))
                .unwrap(),
        )
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let get_obj = s3_client
        .get_object()
        .bucket("module-secrets")
        .key("sec-mod-patch-2/secrets.json")
        .send()
        .await?;
    let stored_bytes = get_obj.body.collect().await?.into_bytes();
    let stored: JsonValue = serde_json::from_slice(&stored_bytes)?;
    assert_eq!(
        stored,
        json!({ "connection_string": "postgres://secret@db/prod" })
    );

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();
    Ok(())
}

/// Verifies that deleting a module also removes its secrets from S3.
#[tokio::test]
async fn delete_module_also_deletes_secrets() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let temp_dir = tempfile::TempDir::new()?;
    let file_path = temp_dir.path().join("module.wasm");
    let file_body = b"\0asm\x01\0\0\0";
    std::fs::write(&file_path, file_body)?;
    let digest = format!("sha256:{:x}", Sha256::digest(file_body));

    let create_payload = json!({
        "id": "sec-mod-del",
        "name": "Module With Secrets",
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

    let schema = json!({
        "type": "object",
        "properties": { "connection_string": { "type": "string" } },
        "required": ["connection_string"]
    });
    let secrets = json!({ "connection_string": "postgres://secret@db/prod" });

    s3_client
        .put_object()
        .bucket("module-secrets")
        .key("sec-mod-del/secrets.schema.json")
        .body(ByteStream::from(serde_json::to_vec(&schema)?))
        .send()
        .await?;

    s3_client
        .put_object()
        .bucket("module-secrets")
        .key("sec-mod-del/secrets.json")
        .body(ByteStream::from(serde_json::to_vec(&secrets)?))
        .send()
        .await?;

    let del_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/modules/sec-mod-del")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    assert_eq!(del_resp.status(), StatusCode::NO_CONTENT);

    let listing = s3_client
        .list_objects_v2()
        .bucket("module-secrets")
        .prefix("sec-mod-del/")
        .send()
        .await?;
    assert!(listing.contents().is_empty());

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();
    Ok(())
}
