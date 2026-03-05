use tracing_subscriber::{fmt, EnvFilter};

pub fn init(log_level: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    fmt()
        .with_target(false)
        .with_env_filter(EnvFilter::new(log_level))
        .try_init()
}
