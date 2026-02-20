use anyhow::Result;
use axum::{
    body::Body,
    http::{self, Request, StatusCode},
    Router,
};
use bytes::Bytes;
use http_body_util::BodyExt as _;
use mci::{app, models::Definition, AppState};
use serde_json::json;
use sha2::{Digest, Sha256};
use testcontainers_modules::{minio, postgres, testcontainers::ContainerAsync};
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

mod common;

async fn setup_app() -> Result<(
    ContainerAsync<postgres::Postgres>,
    ContainerAsync<minio::MinIO>,
    Router,
)> {
    let (pg_container, pool) = common::initialize_pg().await?;
    let (s3_container, s3_client) = common::initialize_s3().await?;

    s3_client
        .create_bucket()
        .bucket("definitions")
        .send()
        .await?;

    let state = AppState {
        db_pool: pool,
        http_client: reqwest::Client::new(),
        s3_client,
    };
    let router = app(state);

    Ok((pg_container, s3_container, router))
}

async fn read_body(response: axum::response::Response) -> Result<Bytes> {
    let collected = response.into_body().collect().await?;
    Ok(collected.to_bytes())
}

#[tokio::test]
async fn get_definitions_returns_empty_list() -> Result<()> {
    let (pg_container, s3_container, app) = setup_app().await?;

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
    let (pg_container, s3_container, app) = setup_app().await?;

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

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();

    Ok(())
}

#[tokio::test]
async fn update_definition_rejects_digest_without_file_url() -> Result<()> {
    let (pg_container, s3_container, app) = setup_app().await?;

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

    let bad_patch = json!({
        "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    });

    let bad_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/definitions/upd-test")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&bad_patch)?))
                .unwrap(),
        )
        .await?;

    assert_eq!(bad_resp.status(), StatusCode::BAD_REQUEST);

    let new_body = b"new-content";
    let new_digest = format!("sha256:{:x}", Sha256::digest(new_body));

    Mock::given(method("GET"))
        .and(path("/file2.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(new_body, "application/json"))
        .mount(&mock)
        .await;

    let good_patch = json!({
        "file_url": format!("{}/file2.json", mock.uri()),
        "digest": new_digest,
    });

    let good_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/definitions/upd-test")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&good_patch)?))
                .unwrap(),
        )
        .await?;

    assert_eq!(good_resp.status(), StatusCode::OK);

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();

    Ok(())
}

#[tokio::test]
async fn install_and_upgrade_definition_from_http_registry() -> Result<()> {
    let (pg_container, s3_container, app) = setup_app().await?;

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
    assert_eq!(upgraded.name, "Registry Name v2");
    assert_eq!(upgraded.description, "From registry v2");

    pg_container.stop().await.ok();
    s3_container.stop().await.ok();

    Ok(())
}
