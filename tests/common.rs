use anyhow::Result;
use aws_smithy_types::byte_stream::ByteStream;
use axum::{
    body::Body,
    http::{self, Request},
    response::Response,
    Router,
};
use bytes::Bytes;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use http_body_util::BodyExt as _;
use mci::{config, database, router, s3, AppState};
use serde_json::Value as JsonValue;
use testcontainers_modules::{
    minio, postgres,
    testcontainers::{runners::AsyncRunner, ContainerAsync},
};
use tower::ServiceExt as _;

#[allow(dead_code)]
const MIGRATIONS: EmbeddedMigrations = embed_migrations!();

#[allow(dead_code)]
pub async fn initialize_s3() -> Result<(ContainerAsync<minio::MinIO>, aws_sdk_s3::Client)> {
    let container = minio::MinIO::default().start().await?;

    let host = container.get_host().await?;
    let port = container.get_host_port_ipv4(9000).await?;

    let endpoint = format!("http://{host}:{port}");
    let client = s3::create_client(&endpoint, "minioadmin", "minioadmin", "us-east-1").await;

    Ok((container, client))
}

#[allow(dead_code)]
pub async fn initialize_pg() -> Result<(ContainerAsync<postgres::Postgres>, database::PgPool)> {
    let container = postgres::Postgres::default().start().await?;

    let host = container.get_host().await?;
    let port = container.get_host_port_ipv4(5432).await?;

    let conn_str = format!("postgres://postgres:postgres@{host}:{port}/postgres");
    let pool = tokio::task::spawn_blocking(move || database::create_pool(&conn_str, 5)).await??;
    let migration_pool = pool.clone();

    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut conn = migration_pool.get()?;
        conn.run_pending_migrations(MIGRATIONS)
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    })
    .await??;

    Ok((container, pool))
}

#[allow(dead_code)]
pub async fn setup_app() -> Result<(
    ContainerAsync<postgres::Postgres>,
    ContainerAsync<minio::MinIO>,
    Router,
    aws_sdk_s3::Client,
)> {
    let (pg_container, pool) = initialize_pg().await?;
    let (s3_container, s3_client) = initialize_s3().await?;

    for bucket in [
        "definitions",
        "modules",
        "definition-configurations",
        "module-configurations",
        "definition-secrets",
        "module-secrets",
    ] {
        s3_client.create_bucket().bucket(bucket).send().await?;
    }

    let pg_host = pg_container.get_host().await?;
    let pg_port = pg_container.get_host_port_ipv4(5432).await?;
    let database_url = format!("postgres://postgres:postgres@{pg_host}:{pg_port}/postgres");

    let s3_host = s3_container.get_host().await?;
    let s3_port = s3_container.get_host_port_ipv4(9000).await?;
    let s3_url = format!("http://{s3_host}:{s3_port}");

    let config = config::Config {
        log_level: "info".into(),
        address: "127.0.0.1:0".into(),
        key_path: None,
        cert_path: None,
        database_url,
        db_pool_size: 10,
        s3_url,
        s3_region: "us-east-1".into(),
        s3_access_key: "minioadmin".into(),
        s3_secret_key: "minioadmin".into(),
        s3_kms_key_id: None,
        allowed_origins: None,
    };

    let state = AppState {
        config,
        db_pool: pool.clone(),
        http_client: reqwest::Client::new(),
        s3_client: s3_client.clone(),
    };

    let router = router::create_router(state);

    Ok((pg_container, s3_container, router, s3_client))
}

#[allow(dead_code)]
pub async fn read_body(response: Response) -> Result<Bytes> {
    let collected = response.into_body().collect().await?;
    Ok(collected.to_bytes())
}

#[allow(dead_code)]
pub async fn seed_s3(
    s3_client: &aws_sdk_s3::Client,
    bucket: &str,
    key: &str,
    body: Vec<u8>,
) -> Result<()> {
    s3_client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from(body))
        .send()
        .await?;
    Ok(())
}

#[allow(dead_code)]
pub async fn seed_schema(
    s3_client: &aws_sdk_s3::Client,
    bucket: &str,
    key_prefix: &str,
    schema: &JsonValue,
) -> Result<()> {
    seed_s3(
        s3_client,
        bucket,
        &format!("{key_prefix}/configuration.schema.json"),
        serde_json::to_vec(schema)?,
    )
    .await
}

#[allow(dead_code)]
pub async fn seed_config(
    s3_client: &aws_sdk_s3::Client,
    bucket: &str,
    key_prefix: &str,
    config: &JsonValue,
) -> Result<()> {
    seed_s3(
        s3_client,
        bucket,
        &format!("{key_prefix}/configuration.json"),
        serde_json::to_vec(config)?,
    )
    .await
}

#[allow(dead_code)]
pub async fn seed_raw(
    s3_client: &aws_sdk_s3::Client,
    bucket: &str,
    key: &str,
    bytes: &'static [u8],
) -> Result<()> {
    s3_client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from_static(bytes))
        .send()
        .await?;
    Ok(())
}

#[allow(dead_code)]
pub async fn get_request(app: &Router, uri: &str) -> Result<Response> {
    Ok(app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await?)
}

#[allow(dead_code)]
pub async fn post_request(app: &Router, uri: &str, body: &JsonValue) -> Result<Response> {
    Ok(app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(body)?))
                .unwrap(),
        )
        .await?)
}

#[allow(dead_code)]
pub async fn put_request(app: &Router, uri: &str, body: &JsonValue) -> Result<Response> {
    Ok(app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(uri)
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(body)?))
                .unwrap(),
        )
        .await?)
}

#[allow(dead_code)]
pub async fn patch_request(app: &Router, uri: &str, body: &JsonValue) -> Result<Response> {
    Ok(app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(uri)
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(body)?))
                .unwrap(),
        )
        .await?)
}

#[allow(dead_code)]
pub async fn delete_request(app: &Router, uri: &str) -> Result<Response> {
    Ok(app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await?)
}
