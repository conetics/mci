use super::*;
use std::collections::HashMap;

pub trait ConfigTestExt {
    fn from_map(values: HashMap<&str, &str>) -> Result<Self, ConfigError>
    where
        Self: Sized;
}

impl ConfigTestExt for Config {
    fn from_map(values: HashMap<&str, &str>) -> Result<Self, ConfigError> {
        let mut builder = config::Config::builder()
            .set_default("log_level", "info")?
            .set_default("address", "0.0.0.0:7687")?
            .set_default("s3_region", "us-east-1")?
            .set_default("s3_access_key", "none")?
            .set_default("s3_secret_key", "none")?;

        for (key, value) in values {
            builder = builder.set_override(key, value)?;
        }

        builder.build()?.try_deserialize()
    }
}

fn minimal_config() -> HashMap<&'static str, &'static str> {
    let mut map = HashMap::new();

    map.insert("database_url", "postgres://localhost/test");
    map.insert("s3_url", "http://localhost:9000");

    map
}

#[test]
fn test_minimal_valid_configuration() {
    let config = Config::from_map(minimal_config()).expect("Failed to load config");

    assert_eq!(config.database_url, "postgres://localhost/test");
    assert_eq!(config.s3_url, "http://localhost:9000");
    assert_eq!(config.log_level, "info");
    assert_eq!(config.address, "0.0.0.0:7687");
    assert_eq!(config.s3_region, "us-east-1");
    assert_eq!(config.s3_access_key, "none");
    assert_eq!(config.s3_secret_key, "none");
    assert_eq!(config.key_path, None);
    assert_eq!(config.cert_path, None);
    assert_eq!(config.s3_kms_key_id, None);
}

#[test]
fn test_full_configuration() {
    let mut map = HashMap::new();

    map.insert("log_level", "debug");
    map.insert("address", "127.0.0.1:8080");
    map.insert("key_path", "/path/to/key.pem");
    map.insert("cert_path", "/path/to/cert.pem");
    map.insert("database_url", "postgres://localhost/test");
    map.insert("s3_url", "http://localhost:9000");
    map.insert("s3_region", "eu-west-1");
    map.insert("s3_access_key", "test_access_key");
    map.insert("s3_secret_key", "test_secret_key");
    map.insert(
        "s3_kms_key_id",
        "arn:aws:kms:us-east-1:123456789:key/test-key-id",
    );

    let config = Config::from_map(map).expect("Failed to load config");

    assert_eq!(config.log_level, "debug");
    assert_eq!(config.address, "127.0.0.1:8080");
    assert_eq!(config.key_path, Some("/path/to/key.pem".to_string()));
    assert_eq!(config.cert_path, Some("/path/to/cert.pem".to_string()));
    assert_eq!(config.database_url, "postgres://localhost/test");
    assert_eq!(config.s3_url, "http://localhost:9000");
    assert_eq!(config.s3_region, "eu-west-1");
    assert_eq!(config.s3_access_key, "test_access_key");
    assert_eq!(config.s3_secret_key, "test_secret_key");
    assert_eq!(
        config.s3_kms_key_id,
        Some("arn:aws:kms:us-east-1:123456789:key/test-key-id".to_string())
    );
}

#[test]
fn test_production_like_config() {
    let mut map = HashMap::new();

    map.insert("log_level", "warn");
    map.insert("address", "0.0.0.0:443");
    map.insert("key_path", "/etc/letsencrypt/live/example.com/privkey.pem");
    map.insert(
        "cert_path",
        "/etc/letsencrypt/live/example.com/fullchain.pem",
    );
    map.insert(
        "database_url",
        "postgres://user:password@db.example.com:5432/production",
    );
    map.insert("s3_url", "https://s3.us-west-2.amazonaws.com");
    map.insert("s3_region", "us-west-2");
    map.insert("s3_access_key", "AKIAIOSFODNN7EXAMPLE");
    map.insert("s3_secret_key", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    map.insert(
        "s3_kms_key_id",
        "arn:aws:kms:us-west-2:123456789:key/prod-key-id",
    );

    let config = Config::from_map(map).expect("Failed to load config");

    assert_eq!(config.log_level, "warn");
    assert_eq!(config.address, "0.0.0.0:443");
    assert_eq!(
        config.key_path,
        Some("/etc/letsencrypt/live/example.com/privkey.pem".to_string())
    );
    assert_eq!(
        config.cert_path,
        Some("/etc/letsencrypt/live/example.com/fullchain.pem".to_string())
    );
    assert_eq!(
        config.database_url,
        "postgres://user:password@db.example.com:5432/production"
    );
    assert_eq!(config.s3_url, "https://s3.us-west-2.amazonaws.com");
    assert_eq!(config.s3_region, "us-west-2");
    assert_eq!(config.s3_access_key, "AKIAIOSFODNN7EXAMPLE");
    assert_eq!(
        config.s3_secret_key,
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    );
    assert_eq!(
        config.s3_kms_key_id,
        Some("arn:aws:kms:us-west-2:123456789:key/prod-key-id".to_string())
    );
}

#[test]
fn test_defaults() {
    let config = Config::from_map(minimal_config()).expect("Failed to load config");

    assert_eq!(config.log_level, "info");
    assert_eq!(config.address, "0.0.0.0:7687");
    assert_eq!(config.s3_region, "us-east-1");
    assert_eq!(config.s3_access_key, "none");
    assert_eq!(config.s3_secret_key, "none");
}

#[test]
fn test_default_overrides() {
    let mut map = minimal_config();

    map.insert("log_level", "debug");
    map.insert("address", "127.0.0.1:8080");
    map.insert("s3_region", "ap-southeast-1");
    map.insert("s3_access_key", "my_access_key");
    map.insert("s3_secret_key", "my_secret_key");

    let config = Config::from_map(map).expect("Failed to load config");

    assert_eq!(config.log_level, "debug");
    assert_eq!(config.address, "127.0.0.1:8080");
    assert_eq!(config.s3_region, "ap-southeast-1");
    assert_eq!(config.s3_access_key, "my_access_key");
    assert_eq!(config.s3_secret_key, "my_secret_key");
}

#[test]
fn test_missing_requires_fields() {
    let mut map1 = HashMap::new();
    let mut map2 = HashMap::new();

    map2.insert("s3_url", "http://localhost:9000");
    map1.insert("database_url", "postgres://localhost/test");

    assert!(
        Config::from_map(map1).is_err(),
        "Expected error when s3_url is missing"
    );
    assert!(
        Config::from_map(map2).is_err(),
        "Expected error when database_url is missing"
    );
    assert!(
        Config::from_map(HashMap::new()).is_err(),
        "Expected error when all required fields are missing"
    );
}

#[test]
fn test_unset_optional_is_none() {
    let config = Config::from_map(minimal_config()).expect("Failed to load config");

    assert_eq!(config.key_path, None);
    assert_eq!(config.cert_path, None);
    assert_eq!(config.s3_kms_key_id, None);
}

#[test]
fn test_set_optional_is_some() {
    let mut map = minimal_config();

    map.insert("key_path", "/path/to/key.pem");
    map.insert("cert_path", "/path/to/cert.pem");

    let config = Config::from_map(map).expect("Failed to load config");

    assert_eq!(config.key_path, Some("/path/to/key.pem".to_string()));
    assert_eq!(config.cert_path, Some("/path/to/cert.pem".to_string()));
}

#[test]
fn test_empty_string_values() {
    let mut map = minimal_config();

    map.insert("log_level", "");

    let config = Config::from_map(map).expect("Failed to load config");

    assert_eq!(config.log_level, "");
}

#[test]
fn test_special_characters_in_values() {
    let mut map = minimal_config();

    map.insert("database_url", "postgres://user:p@ss!w0rd@host:5432/db");

    let config = Config::from_map(map).expect("Failed to load config");

    assert_eq!(
        config.database_url,
        "postgres://user:p@ss!w0rd@host:5432/db"
    );
}

#[test]
fn test_very_long_values() {
    let long_value = "a".repeat(1000);
    let mut map = minimal_config();

    map.insert("database_url", &long_value);

    let config = Config::from_map(map).expect("Failed to load config");

    assert_eq!(config.database_url, long_value);
}

#[test]
fn test_multiple_load_calls_are_consistent() {
    let mut map = minimal_config();

    map.insert("log_level", "debug");
    map.insert("address", "127.0.0.1:8080");

    let config1 = Config::from_map(map.clone()).expect("Failed to load config");
    let config2 = Config::from_map(map).expect("Failed to load config");

    assert_eq!(config1.log_level, config2.log_level);
    assert_eq!(config1.address, config2.address);
    assert_eq!(config1.database_url, config2.database_url);
    assert_eq!(config1.s3_url, config2.s3_url);
}
