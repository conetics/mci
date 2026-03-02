pub mod config;
pub mod database;
pub mod errors;
pub mod http;
pub mod models;
pub mod router;
pub mod routes;
pub mod s3;
pub mod schema;
pub mod services;
pub mod state;
pub mod utils;

pub use state::AppState;

use axum_server::{from_tcp, from_tcp_rustls, tls_rustls, Handle};
use futures::Future;
use std::{error, io, net, path};
use tracing::{info, warn};

/// Starts and prepares the HTTP(S) server from the supplied configuration and
/// handle.
///
/// Creates the database pool and HTTP/S3 clients, logs S3 KMS configuration,
/// constructs the application router, binds to the configured address, and
/// returns a future that runs the server and the resolved socket address.
pub async fn serve(
    config: &config::Config,
    handle: Handle<net::SocketAddr>,
) -> Result<(impl Future<Output = Result<(), io::Error>>, net::SocketAddr), Box<dyn error::Error>> {
    let db_pool = database::create_pool(&config.database_url);
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

    let app = router::create_router(AppState {
        config: config.clone(),
        db_pool,
        http_client,
        s3_client,
    });
    let addr: net::SocketAddr = config
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

            let tls_config = tls_rustls::RustlsConfig::from_pem_file(
                path::PathBuf::from(cert_path),
                path::PathBuf::from(key_path),
            )
            .await
            .map_err(io::Error::other)?;

            from_tcp_rustls(std_listener, tls_config)
                .map_err(io::Error::other)?
                .handle(handle)
                .serve(app.into_make_service())
                .await
        } else {
            warn!("TLS certificates not provided. Starting insecure HTTP server.");
            info!("Starting HTTP server on {}", actual_addr);

            from_tcp(std_listener)
                .map_err(io::Error::other)?
                .handle(handle)
                .serve(app.into_make_service())
                .await
        }
    };

    Ok((server_future, actual_addr))
}
