mod common;

use anyhow::Result;
use axum::{
    body::Body,
    http::{self, Request, StatusCode},
};
use mci::models::{Module, ModuleType};
use serde_json::json;
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use common::{read_body, setup_app};

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
        .bucket("modules")
        .prefix("api-mod-1/")
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

/// Installs a module from an HTTP registry, then simulates a registry upgrade and verifies
/// the module is updated.
///
/// This test exercises the install-from-registry flow (POST /modules/install) and the update
/// flow (POST /modules/{id}/update), asserting that the installed module records the registry
/// source and that an upgrade replaces the stored module artifact while preserving the original
/// registry-provided metadata where expected.
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
