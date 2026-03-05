use crate::{config, database};

#[derive(Clone)]
pub struct AppState {
    pub config: config::Config,
    pub db_pool: database::PgPool,
    pub http_client: reqwest::Client,
    pub s3_client: aws_sdk_s3::Client,
}
