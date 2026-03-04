mod common;

use anyhow::Result;
use axum::http::StatusCode;
use common::{
    delete_request, get_request, patch_request, post_request, put_request, read_body, seed_config,
    seed_raw, seed_schema, setup_app,
};
use serde_json::{json, Value as JsonValue};
use sha2::{Digest, Sha256};

#[tokio::test]
async fn definition_configuration_schema_get() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let schema = json!({
        "type": "object",
        "properties": { "enabled": { "type": "boolean" } },
        "required": ["enabled"],
        "additionalProperties": false
    });

    seed_schema(&s3_client, "definition-configurations", "cfg-def-1", &schema).await?;

    let resp = get_request(&app, "/definitions/cfg-def-1/configuration/schema").await?;

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

    seed_schema(&s3_client, "definition-configurations", "cfg-def-2", &schema).await?;

    let config = json!({ "enabled": true, "name": "hello" });

    let put_resp = put_request(&app, "/definitions/cfg-def-2/configuration", &config).await?;
    assert_eq!(put_resp.status(), StatusCode::NO_CONTENT);

    let get_resp = get_request(&app, "/definitions/cfg-def-2/configuration").await?;

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
async fn definition_configuration_put_rejects_invalid() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let schema = json!({
        "type": "object",
        "properties": { "enabled": { "type": "boolean" } },
        "required": ["enabled"],
        "additionalProperties": false
    });

    seed_schema(&s3_client, "definition-configurations", "cfg-def-3", &schema).await?;

    let invalid_config = json!({ "enabled": "not-a-bool" });

    let put_resp =
        put_request(&app, "/definitions/cfg-def-3/configuration", &invalid_config).await?;
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

    seed_schema(&s3_client, "definition-configurations", "cfg-def-4", &schema).await?;
    seed_config(&s3_client, "definition-configurations", "cfg-def-4", &bad_config).await?;

    let get_resp = get_request(&app, "/definitions/cfg-def-4/configuration").await?;

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

    seed_schema(&s3_client, "definition-configurations", "cfg-def-patch-1", &schema).await?;
    seed_config(&s3_client, "definition-configurations", "cfg-def-patch-1", &config).await?;

    let patch_ops = json!([
        { "op": "replace", "path": "/name", "value": "world" },
        { "op": "add", "path": "/count", "value": 42 }
    ]);

    let patch_resp =
        patch_request(&app, "/definitions/cfg-def-patch-1/configuration", &patch_ops).await?;
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

    seed_schema(&s3_client, "definition-configurations", "cfg-def-patch-2", &schema).await?;

    let patch_ops = json!([
        { "op": "add", "path": "/enabled", "value": true }
    ]);

    let patch_resp =
        patch_request(&app, "/definitions/cfg-def-patch-2/configuration", &patch_ops).await?;
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

    seed_schema(&s3_client, "definition-configurations", "cfg-def-patch-3", &schema).await?;
    seed_config(&s3_client, "definition-configurations", "cfg-def-patch-3", &config).await?;

    let patch_ops = json!([
        { "op": "add", "path": "/extra", "value": "not allowed" }
    ]);

    let patch_resp =
        patch_request(&app, "/definitions/cfg-def-patch-3/configuration", &patch_ops).await?;
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

    seed_schema(&s3_client, "definition-configurations", "cfg-def-patch-4", &schema).await?;
    seed_config(&s3_client, "definition-configurations", "cfg-def-patch-4", &config).await?;

    let patch_ops = json!([
        { "op": "test", "path": "/enabled", "value": false },
        { "op": "replace", "path": "/enabled", "value": false }
    ]);

    let patch_resp =
        patch_request(&app, "/definitions/cfg-def-patch-4/configuration", &patch_ops).await?;
    assert_eq!(patch_resp.status(), StatusCode::BAD_REQUEST);

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();
    Ok(())
}

#[tokio::test]
async fn module_configuration_schema_get() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let schema = json!({
        "type": "object",
        "properties": { "port": { "type": "integer" } },
        "required": ["port"]
    });

    seed_schema(&s3_client, "module-configurations", "cfg-mod-1", &schema).await?;

    let resp = get_request(&app, "/modules/cfg-mod-1/configuration/schema").await?;

    assert_eq!(resp.status(), StatusCode::OK);

    let body = read_body(resp).await?;
    let returned: JsonValue = serde_json::from_slice(&body)?;
    assert_eq!(returned, schema);

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();
    Ok(())
}

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

    seed_schema(&s3_client, "module-configurations", "cfg-mod-2", &schema).await?;

    let config = json!({ "port": 8080, "host": "localhost" });

    let put_resp = put_request(&app, "/modules/cfg-mod-2/configuration", &config).await?;
    assert_eq!(put_resp.status(), StatusCode::NO_CONTENT);

    let get_resp = get_request(&app, "/modules/cfg-mod-2/configuration").await?;

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

    seed_schema(&s3_client, "module-configurations", "cfg-mod-3", &schema).await?;

    let invalid_config = json!({ "port": "not-a-number" });

    let put_resp =
        put_request(&app, "/modules/cfg-mod-3/configuration", &invalid_config).await?;
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

    seed_schema(&s3_client, "module-configurations", "cfg-mod-4", &schema).await?;
    seed_config(&s3_client, "module-configurations", "cfg-mod-4", &bad_config).await?;

    let get_resp = get_request(&app, "/modules/cfg-mod-4/configuration").await?;

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

    seed_schema(&s3_client, "module-configurations", "cfg-mod-patch-1", &schema).await?;
    seed_config(&s3_client, "module-configurations", "cfg-mod-patch-1", &config).await?;

    let patch_ops = json!([
        { "op": "replace", "path": "/port", "value": 9090 },
        { "op": "remove", "path": "/host" }
    ]);

    let patch_resp =
        patch_request(&app, "/modules/cfg-mod-patch-1/configuration", &patch_ops).await?;
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

    seed_schema(&s3_client, "module-configurations", "cfg-mod-patch-2", &schema).await?;
    seed_config(&s3_client, "module-configurations", "cfg-mod-patch-2", &config).await?;

    let patch_ops = json!([
        { "op": "remove", "path": "/port" }
    ]);

    let patch_resp =
        patch_request(&app, "/modules/cfg-mod-patch-2/configuration", &patch_ops).await?;
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

    let create_resp = post_request(&app, "/definitions", &create_payload).await?;
    assert_eq!(create_resp.status(), StatusCode::CREATED);

    let schema = json!({ "type": "object", "properties": { "enabled": { "type": "boolean" } } });
    let config = json!({ "enabled": true });

    seed_schema(&s3_client, "definition-configurations", "cfg-def-del", &schema).await?;
    seed_config(&s3_client, "definition-configurations", "cfg-def-del", &config).await?;

    let del_resp = delete_request(&app, "/definitions/cfg-def-del").await?;
    assert_eq!(del_resp.status(), StatusCode::NO_CONTENT);

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

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

    let create_resp = post_request(&app, "/modules", &create_payload).await?;
    assert_eq!(create_resp.status(), StatusCode::CREATED);

    let schema = json!({ "type": "object", "properties": { "port": { "type": "integer" } } });
    let config = json!({ "port": 8080 });

    seed_schema(&s3_client, "module-configurations", "cfg-mod-del", &schema).await?;
    seed_config(&s3_client, "module-configurations", "cfg-mod-del", &config).await?;

    let del_resp = delete_request(&app, "/modules/cfg-mod-del").await?;
    assert_eq!(del_resp.status(), StatusCode::NO_CONTENT);

    // Cleanup runs in a background task; yield to let it complete.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

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
#[tokio::test]
async fn definition_configuration_patch_propagates_corrupt_config_error() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let schema = json!({
        "type": "object",
        "properties": { "enabled": { "type": "boolean" } },
        "additionalProperties": false
    });

    seed_schema(
        &s3_client,
        "definition-configurations",
        "cfg-def-patch-corrupt",
        &schema,
    )
    .await?;
    seed_raw(
        &s3_client,
        "definition-configurations",
        "cfg-def-patch-corrupt/configuration.json",
        b"this is not json {{{",
    )
    .await?;

    let patch_ops = json!([
        { "op": "add", "path": "/enabled", "value": true }
    ]);

    let patch_resp = patch_request(
        &app,
        "/definitions/cfg-def-patch-corrupt/configuration",
        &patch_ops,
    )
    .await?;
    assert_eq!(patch_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();

    Ok(())
}

#[tokio::test]
async fn module_configuration_patch_propagates_corrupt_config_error() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let schema = json!({
        "type": "object",
        "properties": { "port": { "type": "integer" } },
        "additionalProperties": false
    });

    seed_schema(
        &s3_client,
        "module-configurations",
        "cfg-mod-patch-corrupt",
        &schema,
    )
    .await?;
    seed_raw(
        &s3_client,
        "module-configurations",
        "cfg-mod-patch-corrupt/configuration.json",
        b"this is not json {{{",
    )
    .await?;

    let patch_ops = json!([
        { "op": "add", "path": "/port", "value": 9090 }
    ]);

    let patch_resp = patch_request(
        &app,
        "/modules/cfg-mod-patch-corrupt/configuration",
        &patch_ops,
    )
    .await?;
    assert_eq!(patch_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();

    Ok(())
}