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

/// Builds the HTTP router with API routes, tracing, and the provided shared application state.
///
/// The returned `Router` includes the API route set, a `TraceLayer` for request tracing, and the given `AppState` attached as shared state.
///
/// # Parameters
///
/// - `app_state`: Shared application state (database pool, HTTP/S3 clients, optional S3 KMS key) to be made available to route handlers.
///
/// # Returns
///
/// A `Router` configured with the API routes, tracing middleware, and the provided shared state.
pub fn app(app_state: AppState) -> Router {
    Router::new()
        .merge(api::routes::routes())
        .layer(TraceLayer::new_for_http())
        .with_state(app_state)
}

/// Starts and prepares the HTTP(S) server from the supplied configuration and handle.
///
/// Creates the database pool and HTTP/S3 clients, logs S3 KMS configuration, constructs the application router, binds to the configured address, and returns a future that runs the server plus the resolved socket address.
///
/// # Returns
///
/// A tuple where the first element is a future that runs the server and yields `Result<(), std::io::Error>` when the server stops, and the second element is the bound `SocketAddr`.
///
/// # Examples
///
/// ```ignore
/// # async fn run_example() -> Result<(), Box<dyn std::error::Error>> {
/// let cfg = mci::config::Config::default();
/// let handle = axum_server::Handle::new();
/// let (server_future, addr) = mci::serve(&cfg, handle).await?;
/// tokio::spawn(server_future);
/// println!("Server listening on {}", addr);
/// # Ok(())
/// # }
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
