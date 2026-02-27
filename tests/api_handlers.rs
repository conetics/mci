use anyhow::Result;
use aws_smithy_types::byte_stream::ByteStream;
use axum::{
    body::Body,
    http::{self, Request, StatusCode},
    Router,
};
use bytes::Bytes;
use http_body_util::BodyExt as _;
use mci::{
    app,
    models::{Definition, Module, ModuleType},
    AppState,
};
use serde_json::{json, Value as JsonValue};
use sha2::{Digest, Sha256};
use testcontainers_modules::{minio, postgres, testcontainers::ContainerAsync};
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

mod common;

/// Sets up the integration test application environment by starting PostgreSQL and MinIO containers, creating required S3 buckets, and returning the containers, router, and S3 client.
///
/// This starts test PostgreSQL and MinIO containers, creates the buckets:
/// `definitions`, `modules`, `definition-configurations`, `module-configurations`, `definition-secrets`, and `module-secrets`, constructs an AppState with the DB pool, HTTP client, S3 client (no KMS key), and builds the application Router.
///
/// # Examples
///
/// ```no_run
/// # async fn example() -> anyhow::Result<()> {
/// let (pg_container, s3_container, router, s3_client) = setup_app().await?;
/// // use `router` to drive integration requests and `s3_client` to inspect S3 state
/// # Ok(()) }
/// ```
async fn setup_app() -> Result<(
    ContainerAsync<postgres::Postgres>,
    ContainerAsync<minio::MinIO>,
    Router,
    aws_sdk_s3::Client,
)> {
    let (pg_container, pool) = common::initialize_pg().await?;
    let (s3_container, s3_client) = common::initialize_s3().await?;

    s3_client
        .create_bucket()
        .bucket("definitions")
        .send()
        .await?;
    s3_client.create_bucket().bucket("modules").send().await?;
    s3_client
        .create_bucket()
        .bucket("definition-configurations")
        .send()
        .await?;
    s3_client
        .create_bucket()
        .bucket("module-configurations")
        .send()
        .await?;
    s3_client
        .create_bucket()
        .bucket("definition-secrets")
        .send()
        .await?;
    s3_client
        .create_bucket()
        .bucket("module-secrets")
        .send()
        .await?;

    let state = AppState {
        db_pool: pool,
        http_client: reqwest::Client::new(),
        s3_client: s3_client.clone(),
        s3_kms_key_id: None,
    };
    let router = app(state);

    Ok((pg_container, s3_container, router, s3_client))
}

async fn read_body(response: axum::response::Response) -> Result<Bytes> {
    let collected = response.into_body().collect().await?;
    Ok(collected.to_bytes())
}

#[tokio::test]
async fn get_definitions_returns_empty_list() -> Result<()> {
    let (pg_container, s3_container, app, _) = setup_app().await?;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/definitions")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let body = read_body(response).await?;
    let defs: Vec<Definition> = serde_json::from_slice(&body)?;

    assert!(defs.is_empty());

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();

    Ok(())
}

#[tokio::test]
async fn create_get_update_delete_definition_flow() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let temp_dir = tempfile::TempDir::new()?;
    let file_path = temp_dir.path().join("def.json");
    let file_body = br#"{\"hello\":\"world\"}"#;

    std::fs::write(&file_path, file_body)?;

    let digest = format!("sha256:{:x}", Sha256::digest(file_body));

    let payload = json!({
        "id": "api-def-1",
        "name": "API Name",
        "type": "api-type",
        "description": "Created via API test",
        "file_url": file_path.to_string_lossy(),
        "digest": digest,
        "source_url": null
    });

    let create_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/definitions")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&payload)?))
                .unwrap(),
        )
        .await?;

    assert_eq!(create_resp.status(), StatusCode::CREATED);

    let created_body = read_body(create_resp).await?;
    let created: Definition = serde_json::from_slice(&created_body)?;

    assert_eq!(created.id, "api-def-1");
    assert_eq!(created.name, "API Name");

    let get_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/definitions/api-def-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;

    assert_eq!(get_resp.status(), StatusCode::OK);

    let get_body = read_body(get_resp).await?;
    let fetched: Definition = serde_json::from_slice(&get_body)?;

    assert_eq!(fetched.description, "Created via API test");

    let update_payload = json!({
        "name": "API Name Updated",
        "description": "Updated description",
    });

    let patch_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/definitions/api-def-1")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&update_payload)?))
                .unwrap(),
        )
        .await?;

    assert_eq!(patch_resp.status(), StatusCode::OK);

    let patch_body = read_body(patch_resp).await?;
    let updated: Definition = serde_json::from_slice(&patch_body)?;

    assert_eq!(updated.name, "API Name Updated");
    assert_eq!(updated.description, "Updated description");

    let delete_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/definitions/api-def-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;

    assert_eq!(delete_resp.status(), StatusCode::NO_CONTENT);

    let gone_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/definitions/api-def-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    assert_eq!(gone_resp.status(), StatusCode::NOT_FOUND);

    let objects = s3_client
        .list_objects_v2()
        .bucket("definitions")
        .prefix("api-def-1/")
        .send()
        .await?;

    assert!(objects.contents().is_empty());

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();

    Ok(())
}

#[tokio::test]
async fn update_definition_rejects_digest() -> Result<()> {
    let (pg_container, s3_container, app, _) = setup_app().await?;

    let mock = MockServer::start().await;
    let file_body = b"some-content";
    let digest = format!("sha256:{:x}", Sha256::digest(file_body));

    Mock::given(method("GET"))
        .and(path("/file.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(file_body, "application/json"))
        .mount(&mock)
        .await;

    let create_payload = json!({
        "id": "upd-test",
        "name": "Update Test",
        "type": "test-type",
        "description": "For update validation",
        "file_url": format!("{}/file.json", mock.uri()),
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

    let digest_patch = json!({
        "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    });

    let digest_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/definitions/upd-test")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&digest_patch)?))
                .unwrap(),
        )
        .await?;

    assert_eq!(digest_resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let new_body = b"new-content";
    let new_digest = format!("sha256:{:x}", Sha256::digest(new_body));

    Mock::given(method("GET"))
        .and(path("/file2.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(new_body, "application/json"))
        .mount(&mock)
        .await;

    let file_url_patch = json!({
        "file_url": format!("{}/file2.json", mock.uri()),
        "digest": new_digest,
    });

    let file_url_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/definitions/upd-test")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&file_url_patch)?))
                .unwrap(),
        )
        .await?;

    assert_eq!(file_url_resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();

    Ok(())
}

#[tokio::test]
async fn install_and_upgrade_definition_from_http_registry() -> Result<()> {
    let (pg_container, s3_container, app, _) = setup_app().await?;

    let mock = MockServer::start().await;
    let def_v1_body = b"definition-v1-content";
    let digest_v1 = format!("sha256:{:x}", Sha256::digest(def_v1_body));

    Mock::given(method("GET"))
        .and(path("/def_v1.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(def_v1_body, "application/json"))
        .mount(&mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/registry.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "api-def-2",
            "name": "Registry Name",
            "type": "reg-type",
            "description": "From registry",
            "file_url": format!("{}/def_v1.json", mock.uri()),
            "digest": digest_v1,
            "source_url": null,
        })))
        .mount(&mock)
        .await;

    let registry_url = format!("{}/registry.json", mock.uri());

    let install_payload = json!({ "source": registry_url });
    let install_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/definitions/install")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&install_payload)?))
                .unwrap(),
        )
        .await?;

    assert_eq!(install_resp.status(), StatusCode::CREATED);

    let install_body = read_body(install_resp).await?;
    let installed: Definition = serde_json::from_slice(&install_body)?;

    assert_eq!(installed.id, "api-def-2");
    assert_eq!(installed.source_url.as_deref(), Some(registry_url.as_str()));

    let def_v2_body = b"definition-v2-content";
    let digest_v2 = format!("sha256:{:x}", Sha256::digest(def_v2_body));

    mock.reset().await;

    Mock::given(method("GET"))
        .and(path("/def_v2.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(def_v2_body, "application/json"))
        .mount(&mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/registry.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "api-def-2",
            "name": "Registry Name v2",
            "type": "reg-type",
            "description": "From registry v2",
            "file_url": format!("{}/def_v2.json", mock.uri()),
            "digest": digest_v2.clone(),
            "source_url": null,
        })))
        .mount(&mock)
        .await;

    let upgrade_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/definitions/api-def-2/update")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;

    assert_eq!(upgrade_resp.status(), StatusCode::OK);

    let upgrade_body = read_body(upgrade_resp).await?;
    let upgraded: Definition = serde_json::from_slice(&upgrade_body)?;

    assert_eq!(upgraded.digest, digest_v2);
    assert_eq!(upgraded.name, "Registry Name");
    assert_eq!(upgraded.description, "From registry");

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();

    Ok(())
}

#[tokio::test]
async fn get_modules_returns_empty_list() -> Result<()> {
    let (pg_container, s3_container, app, _) = setup_app().await?;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/modules")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let body = read_body(response).await?;
    let modules: Vec<Module> = serde_json::from_slice(&body)?;

    assert!(modules.is_empty());

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();

    Ok(())
}

#[tokio::test]
async fn create_get_update_delete_module_flow() -> Result<()> {
    let (pg_container, s3_container, app, s3_client) = setup_app().await?;

    let temp_dir = tempfile::TempDir::new()?;
    let file_path = temp_dir.path().join("module.wasm");
    let file_body = b"\0asm\x01\0\0\0";

    std::fs::write(&file_path, file_body)?;

    let digest = format!("sha256:{:x}", Sha256::digest(file_body));

    let payload = json!({
        "id": "api-mod-1",
        "name": "API Module",
        "type": "language",
        "description": "Module via API test",
        "file_url": file_path.to_string_lossy(),
        "digest": digest,
        "source_url": null
    });

    let create_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/modules")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&payload)?))
                .unwrap(),
        )
        .await?;

    assert_eq!(create_resp.status(), StatusCode::CREATED);

    let created_body = read_body(create_resp).await?;
    let created: Module = serde_json::from_slice(&created_body)?;

    assert_eq!(created.id, "api-mod-1");
    assert!(matches!(created.type_, ModuleType::Language));

    let get_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/modules/api-mod-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;

    assert_eq!(get_resp.status(), StatusCode::OK);

    let get_body = read_body(get_resp).await?;
    let fetched: Module = serde_json::from_slice(&get_body)?;

    assert_eq!(fetched.description, "Module via API test");

    let update_payload = json!({
        "name": "API Module Updated",
        "description": "Updated module description",
    });

    let patch_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/modules/api-mod-1")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&update_payload)?))
                .unwrap(),
        )
        .await?;

    assert_eq!(patch_resp.status(), StatusCode::OK);

    let patch_body = read_body(patch_resp).await?;
    let updated: Module = serde_json::from_slice(&patch_body)?;

    assert_eq!(updated.name, "API Module Updated");
    assert_eq!(updated.description, "Updated module description");

    let delete_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/modules/api-mod-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;

    assert_eq!(delete_resp.status(), StatusCode::NO_CONTENT);

    let gone_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/modules/api-mod-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;

    assert_eq!(gone_resp.status(), StatusCode::NOT_FOUND);

    let objects = s3_client
        .list_objects_v2()
        .bucket("definitions")
        .prefix("api-def-1/")
        .send()
        .await?;

    assert!(objects.contents().is_empty());

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();

    Ok(())
}

#[tokio::test]
async fn update_module_rejects_digest() -> Result<()> {
    let (pg_container, s3_container, app, _) = setup_app().await?;

    let mock = MockServer::start().await;
    let file_body = b"\0asm\x01\0\0\0module";
    let digest = format!("sha256:{:x}", Sha256::digest(file_body));

    Mock::given(method("GET"))
        .and(path("/module.wasm"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(file_body, "application/json"))
        .mount(&mock)
        .await;

    let create_payload = json!({
        "id": "mod-upd",
        "name": "Module Update Test",
        "type": "sandbox",
        "description": "For module update validation",
        "file_url": format!("{}/module.wasm", mock.uri()),
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

    let digest_patch = json!({
        "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    });

    let digest_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/modules/mod-upd")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&digest_patch)?))
                .unwrap(),
        )
        .await?;

    assert_eq!(digest_resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let new_body = b"\0asm\x01\0\0\0module2";
    let new_digest = format!("sha256:{:x}", Sha256::digest(new_body));

    Mock::given(method("GET"))
        .and(path("/module2.wasm"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(new_body, "application/json"))
        .mount(&mock)
        .await;

    let file_url_patch = json!({
        "file_url": format!("{}/module2.wasm", mock.uri()),
        "digest": new_digest,
    });

    let file_url_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/modules/mod-upd")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&file_url_patch)?))
                .unwrap(),
        )
        .await?;

    assert_eq!(file_url_resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();

    Ok(())
}

/// Installs a module from an HTTP registry, then upgrades it when the registry content changes.
///
/// This integration test verifies that installing a module from a registry URL fetches the registry
/// metadata and artifact, stores the module with the expected source URL and digest, and that a
/// subsequent registry update followed by an update request causes the module to be upgraded
/// (digest updated and type resolved) while preserving expected name/description semantics.
///
/// # Examples
///
/// ```
/// #[tokio::test]
/// async fn run() -> anyhow::Result<()> {
///     install_and_upgrade_module_from_http_registry().await
/// }
/// ```
#[tokio::test]
async fn install_and_upgrade_module_from_http_registry() -> Result<()> {
    let (pg_container, s3_container, app, _) = setup_app().await?;

    let mock = MockServer::start().await;
    let mod_v1_body = b"\0asm\x01\0\0\0v1";
    let digest_v1 = format!("sha256:{:x}", Sha256::digest(mod_v1_body));

    Mock::given(method("GET"))
        .and(path("/mod_v1.wasm"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(mod_v1_body, "application/json"))
        .mount(&mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/registry.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "api-mod-2",
            "name": "Registry Module",
            "type": "interceptor",
            "description": "Module from registry",
            "file_url": format!("{}/mod_v1.wasm", mock.uri()),
            "digest": digest_v1,
            "source_url": null,
        })))
        .mount(&mock)
        .await;

    let registry_url = format!("{}/registry.json", mock.uri());

    let install_payload = json!({ "source": registry_url });
    let install_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/modules/install")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&install_payload)?))
                .unwrap(),
        )
        .await?;

    assert_eq!(install_resp.status(), StatusCode::CREATED);

    let install_body = read_body(install_resp).await?;
    let installed: Module = serde_json::from_slice(&install_body)?;

    assert_eq!(installed.id, "api-mod-2");
    assert_eq!(installed.source_url.as_deref(), Some(registry_url.as_str()));

    let mod_v2_body = b"\0asm\x01\0\0\0v2";
    let digest_v2 = format!("sha256:{:x}", Sha256::digest(mod_v2_body));

    mock.reset().await;

    Mock::given(method("GET"))
        .and(path("/mod_v2.wasm"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(mod_v2_body, "application/json"))
        .mount(&mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/registry.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "api-mod-2",
            "name": "Registry Module v2",
            "type": "proxy",
            "description": "Module from registry v2",
            "file_url": format!("{}/mod_v2.wasm", mock.uri()),
            "digest": digest_v2.clone(),
            "source_url": null,
        })))
        .mount(&mock)
        .await;

    let upgrade_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/modules/api-mod-2/update")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;

    assert_eq!(upgrade_resp.status(), StatusCode::OK);

    let upgrade_body = read_body(upgrade_resp).await?;
    let upgraded: Module = serde_json::from_slice(&upgrade_body)?;

    assert_eq!(upgraded.digest, digest_v2);
    assert_eq!(upgraded.name, "Registry Module");
    assert_eq!(upgraded.description, "Module from registry");
    assert!(matches!(upgraded.type_, ModuleType::Interceptor));

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();

    Ok(())
}

/// Verifies that the configuration schema for a definition can be retrieved from S3 via the HTTP API.
///
/// Stores a JSON schema in the `definition-configurations` bucket and asserts that a GET to
/// `/definitions/{id}/configuration/schema` returns the same schema.
///
/// # Examples
///
/// ```no_run
/// // store schema under definition-configurations/cfg-def-1/configuration.schema.json
/// // then:
/// let resp = app
///     .oneshot(Request::builder()
///         .method("GET")
///         .uri("/definitions/cfg-def-1/configuration/schema")
///         .body(Body::empty())
///         .unwrap())
///     .await?;
/// assert_eq!(resp.status(), StatusCode::OK);
/// let body = read_body(resp).await?;
/// let returned: serde_json::Value = serde_json::from_slice(&body)?;
/// assert_eq!(returned, schema);
/// ```
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

/// Verifies that storing a configuration that does not match its JSON Schema is rejected and not persisted.
///
/// The test uploads a schema requiring `enabled` to be a boolean, attempts to PUT a configuration where
/// `enabled` is a string, and asserts the service responds with 500 Internal Server Error and that no
/// configuration object was written to the `definition-configurations` bucket.
///
/// # Examples
///
/// ```ignore
/// // This test is executed with #[tokio::test] in the test suite.
/// // It demonstrates the expected behavior: invalid config is rejected and not stored.
/// ```
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

    assert_eq!(put_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

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

/// Ensures deleting a module also removes its configuration and schema objects from S3.
///
/// Creates a module with an artifact, stores a configuration schema and configuration under
/// the module's key in the `module-configurations` bucket, deletes the module via the API,
/// and verifies the S3 bucket contains no objects for that module afterwards.
///
/// # Examples
///
/// ```no_run
/// // This is an integration test; run with `cargo test` (may require test containers).
/// ```
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

    assert_eq!(put_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

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

/// Verifies that PATCHing a definition configuration applies to an initially empty object when no prior configuration exists.
///
/// This test stores a JSON Schema for a definition configuration that accepts a boolean `enabled` property,
/// sends a JSON Patch that adds `enabled: true` to the configuration, and asserts the stored result equals the patched object.
///
/// # Examples
///
/// ```
/// // Arrange: ensure a configuration schema exists for `cfg-def-patch-2` allowing a boolean `enabled`
/// // Act: send a JSON Patch `[{"op":"add","path":"/enabled","value": true}]` to
/// // `/definitions/cfg-def-patch-2/configuration`
/// // Assert: the endpoint responds OK and the resulting configuration equals `{ "enabled": true }`
/// ```
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

    assert_eq!(patch_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

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

    assert_eq!(patch_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

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

    assert_eq!(patch_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

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
async fn get_definition_secrets_schema_returns_schema() -> Result<()> {
    let (_pg_container, _s3_container, app, s3_client) = setup_app().await?;

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

    _pg_container.stop().await.ok();
    _s3_container.stop().await.ok();
    Ok(())
}

#[tokio::test]
async fn patch_definition_secrets_applies_and_returns_no_content() -> Result<()> {
    let (_pg_container, _s3_container, app, s3_client) = setup_app().await?;

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

    _pg_container.stop().await.ok();
    _s3_container.stop().await.ok();
    Ok(())
}

#[tokio::test]
async fn patch_definition_secrets_defaults_to_empty_object() -> Result<()> {
    let (_pg_container, _s3_container, app, s3_client) = setup_app().await?;

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

    _pg_container.stop().await.ok();
    _s3_container.stop().await.ok();
    Ok(())
}

/// Verifies that removing a required secret property via JSON Patch is rejected and does not modify stored secrets.
///
/// The test stores a secrets schema requiring `api_key` and an existing `secrets.json` containing `api_key`,
/// then sends a PATCH that removes `/api_key`. The request must fail with an internal server error and the
/// persisted `secrets.json` must remain unchanged.
///
/// # Examples
///
/// ```
/// // Stores a schema requiring `api_key`, seeds secrets.json with {"api_key": "sk-123"},
/// // sends a PATCH that removes `/api_key`, expects failure and unchanged stored secrets.
/// ```
#[tokio::test]
async fn patch_definition_secrets_rejects_invalid_result() -> Result<()> {
    let (_pg_container, _s3_container, app, s3_client) = setup_app().await?;

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

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let get_obj = s3_client
        .get_object()
        .bucket("definition-secrets")
        .key("sec-def-patch-3/secrets.json")
        .send()
        .await?;
    let stored_bytes = get_obj.body.collect().await?.into_bytes();
    let stored: JsonValue = serde_json::from_slice(&stored_bytes)?;
    assert_eq!(stored, json!({ "api_key": "sk-123" }));

    _pg_container.stop().await.ok();
    _s3_container.stop().await.ok();
    Ok(())
}

#[tokio::test]
async fn get_module_secrets_schema_returns_schema() -> Result<()> {
    let (_pg_container, _s3_container, app, s3_client) = setup_app().await?;

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

    _pg_container.stop().await.ok();
    _s3_container.stop().await.ok();
    Ok(())
}

/// Applies a JSON Patch to a module's secrets, asserts the handler responds with 204 No Content,
/// and verifies the patched secrets are persisted to S3.
///
/// # Examples
///
/// ```
/// # use serde_json::json;
/// # async fn example() -> anyhow::Result<()> {
/// let (_pg, _s3, app, s3_client) = setup_app().await?;
///
/// // store schema
/// let schema = json!({
///     "type": "object",
///     "properties": { "connection_string": { "type": "string" } },
///     "required": ["connection_string"]
/// });
/// s3_client
///     .put_object()
///     .bucket("module-secrets")
///     .key("sec-mod-patch-1/secrets.schema.json")
///     .body(ByteStream::from(serde_json::to_vec(&schema)?))
///     .send()
///     .await?;
///
/// // apply patch
/// let patch_ops = json!([ { "op": "add", "path": "/connection_string", "value": "postgres://secret@db/prod" } ]);
/// let response = app
///     .clone()
///     .oneshot(
///         Request::builder()
///             .method("PATCH")
///             .uri("/modules/sec-mod-patch-1/secrets")
///             .header(http::header::CONTENT_TYPE, "application/json")
///             .body(Body::from(serde_json::to_vec(&patch_ops)?))
///             .unwrap(),
///     )
///     .await?;
///
/// assert_eq!(response.status(), StatusCode::NO_CONTENT);
/// # Ok(())
/// # }
/// ```
#[tokio::test]
async fn patch_module_secrets_applies_and_returns_no_content() -> Result<()> {
    let (_pg_container, _s3_container, app, s3_client) = setup_app().await?;

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

    _pg_container.stop().await.ok();
    _s3_container.stop().await.ok();
    Ok(())
}

#[tokio::test]
async fn patch_module_secrets_rejects_invalid_result() -> Result<()> {
    let (_pg_container, _s3_container, app, s3_client) = setup_app().await?;

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

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

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

    _pg_container.stop().await.ok();
    _s3_container.stop().await.ok();
    Ok(())
}
