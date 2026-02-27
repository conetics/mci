use config::{ConfigError, Environment};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct Config {
    pub log_level: String,
    pub address: String,
    pub key_path: Option<String>,
    pub cert_path: Option<String>,
    pub database_url: String,
    pub s3_url: String,
    pub s3_region: String,
    pub s3_access_key: String,
    pub s3_secret_key: String,
    pub s3_kms_key_id: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_builder(config::Config::builder())
    }

    fn from_builder(
        builder: config::ConfigBuilder<config::builder::DefaultState>,
    ) -> Result<Self, ConfigError> {
        let s = builder
            .set_default("log_level", "info")?
            .set_default("address", "0.0.0.0:7687")?
            .set_default("s3_region", "us-east-1")?
            .set_default("s3_access_key", "none")?
            .set_default("s3_secret_key", "none")?
            .add_source(Environment::with_prefix("MCI"))
            .build()?;

        s.try_deserialize()
    }
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
