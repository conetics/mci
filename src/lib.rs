use aws_sdk_s3::Client;
use axum::Router;
use axum_server::{tls_rustls::RustlsConfig, Handle};
use deadpool_postgres::Pool;
use futures::Future;
use std::{net::SocketAddr, path::PathBuf};
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

pub mod api;
pub mod config;
pub mod db;
pub mod domains;
pub mod errors;
pub mod s3;

#[derive(Clone)]
pub struct AppState {
    pub db_pool: Pool,
    pub s3_client: Client,
}

pub fn app(app_state: AppState) -> Router {
    Router::new()
        .merge(api::routes::routes())
        .layer(TraceLayer::new_for_http())
        .with_state(app_state)
}

pub async fn serve(
    config: &config::Config,
    handle: Handle<std::net::SocketAddr>,
) -> (impl Future<Output = Result<(), std::io::Error>>, SocketAddr) {
    let db_pool = db::create_pool(&config.database_url);
    let s3_client =
        s3::create_s3_client(&config.s3_url, &config.s3_access_key, &config.s3_secret_key).await;

    db::init_db(&db_pool).await.unwrap();

    let app = app(AppState { db_pool, s3_client });
    let addr: SocketAddr = config.address.parse().unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let std_listener = listener.into_std().unwrap();
    let cert_path = config.cert_path.clone();
    let key_path = config.key_path.clone();

    let server_future = async move {
        if let (Some(cert_path), Some(key_path)) = (cert_path, key_path) {
            let tls_config =
                RustlsConfig::from_pem_file(PathBuf::from(cert_path), PathBuf::from(key_path))
                    .await
                    .unwrap();

            info!("Server listening on {}", addr);

            axum_server::from_tcp_rustls(std_listener, tls_config)
                .unwrap()
                .handle(handle)
                .serve(app.into_make_service())
                .await
        } else {
            warn!("TLS certificates not provided. Starting insecure HTTP server.");
            info!("Server listening on {}", addr);

            axum_server::from_tcp(std_listener)
                .unwrap()
                .handle(handle)
                .serve(app.into_make_service())
                .await
        }
    };

    (server_future, addr)
}
