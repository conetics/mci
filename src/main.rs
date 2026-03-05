use mci::{config, serve};
use tracing::info;

#[tokio::main]
async fn main() {
    let config = config::Config::from_env().expect("Failed to load configuration from environment");

    let _ = mci::telemetry::init(&config.log_level);

    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();

    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for Ctrl+C");

        info!("Shutdown signal received. Closing server gracefully...");

        shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
    });

    let (server_future, addr) = serve(&config, handle)
        .await
        .expect("Failed to start server");

    info!("Server running on {}", addr);

    server_future.await.expect("Server failed to run");
}
