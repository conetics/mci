use super::*;

#[test]
fn config_from_env_with_defaults() {
    temp_env::with_vars_unset(
        vec![
            "MCI_LOG_LEVEL",
            "MCI_ADDRESS",
            "MCI_DB_POOL_SIZE",
            "MCI_DATABASE_URL",
            "MCI_S3_URL",
            "MCI_S3_REGION",
            "MCI_S3_ACCESS_KEY",
            "MCI_S3_SECRET_KEY",
            "MCI_KEY_PATH",
            "MCI_CERT_PATH",
            "MCI_ALLOWED_ORIGINS",
            "MCI_S3_KMS_KEY_ID",
        ],
        || {
            temp_env::with_vars(
                vec![
                    ("MCI_DATABASE_URL", Some("postgres://localhost/test")),
                    ("MCI_S3_URL", Some("http://localhost:9000")),
                ],
                || {
                    let config = Config::from_env().expect("Failed to load config");
                    assert_eq!(config.log_level, "info");
                    assert_eq!(config.address, "0.0.0.0:7687");
                    assert_eq!(config.db_pool_size, 10);
                    assert_eq!(config.database_url, "postgres://localhost/test");
                    assert_eq!(config.s3_url, "http://localhost:9000");
                    assert_eq!(config.s3_region, "us-east-1");
                    assert_eq!(config.s3_access_key, "none");
                    assert_eq!(config.s3_secret_key, "none");
                    assert_eq!(config.key_path, None);
                    assert_eq!(config.cert_path, None);
                    assert_eq!(config.allowed_origins, None);
                    assert_eq!(config.s3_kms_key_id, None);
                },
            );
        },
    );
}

#[test]
fn config_from_env_with_custom_values() {
    temp_env::with_vars_unset(
        vec![
            "MCI_LOG_LEVEL",
            "MCI_ADDRESS",
            "MCI_DB_POOL_SIZE",
            "MCI_DATABASE_URL",
            "MCI_S3_URL",
            "MCI_S3_REGION",
            "MCI_S3_ACCESS_KEY",
            "MCI_S3_SECRET_KEY",
            "MCI_KEY_PATH",
            "MCI_CERT_PATH",
            "MCI_ALLOWED_ORIGINS",
            "MCI_S3_KMS_KEY_ID",
        ],
        || {
            temp_env::with_vars(
                vec![
                    ("MCI_LOG_LEVEL", Some("debug")),
                    ("MCI_ADDRESS", Some("127.0.0.1:8080")),
                    ("MCI_DB_POOL_SIZE", Some("20")),
                    ("MCI_DATABASE_URL", Some("postgres://user:pass@host/db")),
                    ("MCI_S3_URL", Some("https://s3.amazonaws.com")),
                    ("MCI_S3_REGION", Some("us-west-2")),
                    ("MCI_S3_ACCESS_KEY", Some("my-access-key")),
                    ("MCI_S3_SECRET_KEY", Some("my-secret-key")),
                    ("MCI_KEY_PATH", Some("/path/to/key.pem")),
                    ("MCI_CERT_PATH", Some("/path/to/cert.pem")),
                    ("MCI_ALLOWED_ORIGINS", Some("https://example.com")),
                    ("MCI_S3_KMS_KEY_ID", Some("kms-key-123")),
                ],
                || {
                    let config = Config::from_env().expect("Failed to load config");
                    assert_eq!(config.log_level, "debug");
                    assert_eq!(config.address, "127.0.0.1:8080");
                    assert_eq!(config.db_pool_size, 20);
                    assert_eq!(config.database_url, "postgres://user:pass@host/db");
                    assert_eq!(config.s3_url, "https://s3.amazonaws.com");
                    assert_eq!(config.s3_region, "us-west-2");
                    assert_eq!(config.s3_access_key, "my-access-key");
                    assert_eq!(config.s3_secret_key, "my-secret-key");
                    assert_eq!(config.key_path, Some("/path/to/key.pem".to_string()));
                    assert_eq!(config.cert_path, Some("/path/to/cert.pem".to_string()));
                    assert_eq!(
                        config.allowed_origins,
                        Some("https://example.com".to_string())
                    );
                    assert_eq!(config.s3_kms_key_id, Some("kms-key-123".to_string()));
                },
            );
        },
    );
}

#[test]
fn config_from_env_missing_required_database_url() {
    temp_env::with_vars_unset(
        vec![
            "MCI_LOG_LEVEL",
            "MCI_ADDRESS",
            "MCI_DB_POOL_SIZE",
            "MCI_DATABASE_URL",
            "MCI_S3_URL",
            "MCI_S3_REGION",
            "MCI_S3_ACCESS_KEY",
            "MCI_S3_SECRET_KEY",
        ],
        || {
            temp_env::with_vars(
                vec![("MCI_S3_URL", Some("http://localhost:9000"))],
                || {
                    let result = Config::from_env();
                    assert!(result.is_err());
                },
            );
        },
    );
}

#[test]
fn config_from_env_missing_required_s3_url() {
    temp_env::with_vars_unset(
        vec![
            "MCI_LOG_LEVEL",
            "MCI_ADDRESS",
            "MCI_DB_POOL_SIZE",
            "MCI_DATABASE_URL",
            "MCI_S3_URL",
            "MCI_S3_REGION",
            "MCI_S3_ACCESS_KEY",
            "MCI_S3_SECRET_KEY",
        ],
        || {
            temp_env::with_vars(
                vec![("MCI_DATABASE_URL", Some("postgres://localhost/test"))],
                || {
                    let result = Config::from_env();
                    assert!(result.is_err());
                },
            );
        },
    );
}

#[test]
fn config_clone_and_partial_eq() {
    let config1 = Config {
        log_level: "info".to_string(),
        address: "0.0.0.0:7687".to_string(),
        key_path: None,
        cert_path: None,
        database_url: "postgres://localhost/test".to_string(),
        db_pool_size: 10,
        s3_url: "http://localhost:9000".to_string(),
        s3_region: "us-east-1".to_string(),
        s3_access_key: "access".to_string(),
        s3_secret_key: "secret".to_string(),
        s3_kms_key_id: None,
        allowed_origins: None,
    };

    let config2 = config1.clone();
    assert_eq!(config1, config2);
}

#[test]
fn config_partial_eq_different_values() {
    let config1 = Config {
        log_level: "info".to_string(),
        address: "0.0.0.0:7687".to_string(),
        key_path: None,
        cert_path: None,
        database_url: "postgres://localhost/test".to_string(),
        db_pool_size: 10,
        s3_url: "http://localhost:9000".to_string(),
        s3_region: "us-east-1".to_string(),
        s3_access_key: "access".to_string(),
        s3_secret_key: "secret".to_string(),
        s3_kms_key_id: None,
        allowed_origins: None,
    };

    let config2 = Config {
        log_level: "debug".to_string(),
        ..config1.clone()
    };

    assert_ne!(config1, config2);
}

#[test]
fn config_debug_format() {
    let config = Config {
        log_level: "info".to_string(),
        address: "0.0.0.0:7687".to_string(),
        key_path: None,
        cert_path: None,
        database_url: "postgres://localhost/test".to_string(),
        db_pool_size: 10,
        s3_url: "http://localhost:9000".to_string(),
        s3_region: "us-east-1".to_string(),
        s3_access_key: "access".to_string(),
        s3_secret_key: "secret".to_string(),
        s3_kms_key_id: None,
        allowed_origins: None,
    };

    let debug_str = format!("{:?}", config);
    assert!(debug_str.contains("log_level"));
    assert!(debug_str.contains("address"));
    assert!(debug_str.contains("database_url"));
}

#[test]
fn config_invalid_db_pool_size_type() {
    temp_env::with_vars_unset(
        vec![
            "MCI_LOG_LEVEL",
            "MCI_ADDRESS",
            "MCI_DB_POOL_SIZE",
            "MCI_DATABASE_URL",
            "MCI_S3_URL",
            "MCI_S3_REGION",
        ],
        || {
            temp_env::with_vars(
                vec![
                    ("MCI_DATABASE_URL", Some("postgres://localhost/test")),
                    ("MCI_S3_URL", Some("http://localhost:9000")),
                    ("MCI_DB_POOL_SIZE", Some("not-a-number")),
                ],
                || {
                    let result = Config::from_env();
                    assert!(result.is_err());
                },
            );
        },
    );
}
