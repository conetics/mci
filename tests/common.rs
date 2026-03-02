use anyhow::Result;
use axum::response::Response;
use axum::Router;
use bytes::Bytes;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use http_body_util::BodyExt as _;
use mci::{config, database, router, s3, AppState};
use testcontainers_modules::{
    minio, postgres,
    testcontainers::{runners::AsyncRunner, ContainerAsync},
};

#![allow(dead_code)]
const MIGRATIONS: EmbeddedMigrations = embed_migrations!();

#![allow(dead_code)]
pub async fn initialize_s3() -> Result<(ContainerAsync<minio::MinIO>, aws_sdk_s3::Client)> {
    let container = minio::MinIO::default().start().await?;

    let host = container.get_host().await?;
    let port = container.get_host_port_ipv4(9000).await?;

    let endpoint = format!("http://{host}:{port}");
    let client = s3::create_client(&endpoint, "minioadmin", "minioadmin", "us-east-1").await;

    Ok((container, client))
}

#![allow(dead_code)]
pub async fn initialize_pg() -> Result<(ContainerAsync<postgres::Postgres>, database::PgPool)> {
    let container = postgres::Postgres::default().start().await?;

    let host = container.get_host().await?;
    let port = container.get_host_port_ipv4(5432).await?;

    let conn_str = format!("postgres://postgres:postgres@{host}:{port}/postgres");
    let pool = tokio::task::spawn_blocking(move || database::create_pool(&conn_str)).await?;
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

#![allow(dead_code)]
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

    let config = config::Config {
        log_level: "info".into(),
        address: "127.0.0.1:0".into(),
        key_path: None,
        cert_path: None,
        database_url: "postgres://localhost:5432/postgres".into(),
        s3_url: "http://localhost:9000".into(),
        s3_region: "us-east-1".into(),
        s3_access_key: "minioadmin".into(),
        s3_secret_key: "minioadmin".into(),
        s3_kms_key_id: None,
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

#![allow(dead_code)]
pub async fn read_body(response: Response) -> Result<Bytes> {
    let collected = response.into_body().collect().await?;
    Ok(collected.to_bytes())
}
