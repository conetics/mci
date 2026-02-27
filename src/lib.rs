use axum::Router;
use axum_server::{tls_rustls::RustlsConfig, Handle};
use futures::Future;
use std::{net::SocketAddr, path::PathBuf};
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

pub mod api;
pub mod config;
pub mod db;
pub mod errors;
pub mod http;
pub mod models;
pub mod s3;
pub mod schema;
pub mod services;
pub mod utils;

#[derive(Clone)]
pub struct AppState {
    pub db_pool: db::PgPool,
    pub http_client: reqwest::Client,
    pub s3_client: aws_sdk_s3::Client,
    pub s3_kms_key_id: Option<String>,
}

/// Builds the Axum router with API routes, an HTTP tracing layer, and the provided shared application state.
///
/// # Examples
///
/// ```no_run
/// use crate::{app, AppState};
/// use reqwest::Client;
/// use aws_sdk_s3::Client as S3Client;
///
/// // Construct an AppState with real values in application code.
/// let state = AppState {
///     db_pool: /* db::PgPool */ unimplemented!(),
///     http_client: Client::new(),
///     s3_client: /* S3Client */ unimplemented!(),
///     s3_kms_key_id: None,
/// };
///
/// let router = app(state);
/// ```
pub fn app(app_state: AppState) -> Router {
    Router::new()
        .merge(api::routes::routes())
        .layer(TraceLayer::new_for_http())
        .with_state(app_state)
}

/// Starts the HTTP(S) server and returns a future that drives it along with the bound socket address.
///
/// Builds application state (database pool, HTTP client, S3 client and optional S3 KMS key id),
/// binds a TCP listener to the configured address, and constructs either a TLS-enabled server
/// when certificate and key paths are provided or an insecure HTTP server otherwise.
///
/// # Returns
///
/// A tuple containing:
/// - a future that, when awaited, runs the selected server until completion or error; and
/// - the actual `SocketAddr` the server bound to.
///
/// # Examples
///
/// ```no_run
/// # use tokio::runtime::Runtime;
/// # use axum_server::Handle;
/// # use std::net::SocketAddr;
/// # use crate::config;
/// let rt = Runtime::new().unwrap();
/// let config = config::Config::load_from_env().unwrap();
/// let handle = Handle::new();
///
/// rt.block_on(async {
///     let (server_future, addr): (_, SocketAddr) = serve(&config, handle).await.unwrap();
///     println!("Server listening on {}", addr);
///     // Run server (this will block until the server stops)
///     server_future.await.unwrap();
/// });
/// ```
pub async fn serve(
    config: &config::Config,
    handle: Handle<std::net::SocketAddr>,
) -> Result<
    (impl Future<Output = Result<(), std::io::Error>>, SocketAddr),
    Box<dyn std::error::Error>,
> {
    let db_pool = db::create_pool(&config.database_url);
    let http_client = http::create_client(30)?;
    let s3_client = s3::create_client(
        &config.s3_url,
        &config.s3_access_key,
        &config.s3_secret_key,
        &config.s3_region,
    )
    .await;

    if config.s3_kms_key_id.is_none() {
        warn!("S3_KMS_KEY_ID is not set. Secrets will be stored without server-side encryption.");
    }

    let app = app(AppState {
        db_pool,
        http_client,
        s3_client,
        s3_kms_key_id: config.s3_kms_key_id.clone(),
    });

    let addr: SocketAddr = config
        .address
        .parse()
        .map_err(|e| format!("Invalid address '{}': {}", config.address, e))?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("Failed to bind to {}: {}", addr, e))?;
    let actual_addr = listener.local_addr()?;
    let std_listener = listener.into_std()?;
    let cert_path = config.cert_path.clone();
    let key_path = config.key_path.clone();

    let server_future = async move {
        if let (Some(cert_path), Some(key_path)) = (cert_path, key_path) {
            info!("Starting TLS server on {}", actual_addr);

            let tls_config =
                RustlsConfig::from_pem_file(PathBuf::from(cert_path), PathBuf::from(key_path))
                    .await
                    .map_err(std::io::Error::other)?;

            axum_server::from_tcp_rustls(std_listener, tls_config)
                .map_err(std::io::Error::other)?
                .handle(handle)
                .serve(app.into_make_service())
                .await
        } else {
            warn!("TLS certificates not provided. Starting insecure HTTP server.");
            info!("Starting HTTP server on {}", actual_addr);

            axum_server::from_tcp(std_listener)
                .map_err(std::io::Error::other)?
                .handle(handle)
                .serve(app.into_make_service())
                .await
        }
    };

    Ok((server_future, actual_addr))
}
