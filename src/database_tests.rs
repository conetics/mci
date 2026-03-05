use super::*;

#[test]
fn create_pool_with_valid_url() {
    let database_url = "postgres://test:test@localhost:5432/test";
    let pool_size = 5;

    let result = create_pool(database_url, pool_size);
    assert!(result.is_ok());

    let pool = result.unwrap();
    assert_eq!(pool.max_size(), pool_size);
}

#[test]
fn create_pool_with_invalid_url_returns_err() {
    let database_url = "not-a-valid-url";
    let pool_size = 5;

    let result = create_pool(database_url, pool_size);
    assert!(result.is_ok());
}

#[test]
fn create_pool_with_empty_url() {
    let database_url = "";
    let pool_size = 5;

    let result = create_pool(database_url, pool_size);
    assert!(result.is_ok());
}

#[test]
fn create_pool_with_zero_pool_size() {
    let database_url = "postgres://test:test@localhost:5432/test";
    let pool_size = 0;

    let result = create_pool(database_url, pool_size);
    assert!(result.is_err());
}

#[test]
fn create_pool_with_large_pool_size() {
    let database_url = "postgres://test:test@localhost:5432/test";
    let pool_size = 100;

    let result = create_pool(database_url, pool_size);
    assert!(result.is_ok());

    let pool = result.unwrap();
    assert_eq!(pool.max_size(), pool_size);
}

#[test]
fn create_pool_respects_pool_size_parameter() {
    let database_url = "postgres://test:test@localhost:5432/test";

    let pool1 = create_pool(database_url, 5).unwrap();
    assert_eq!(pool1.max_size(), 5);

    let pool2 = create_pool(database_url, 10).unwrap();
    assert_eq!(pool2.max_size(), 10);

    let pool3 = create_pool(database_url, 20).unwrap();
    assert_eq!(pool3.max_size(), 20);
}

#[test]
fn create_pool_with_postgres_url_variants() {
    let urls = vec![
        "postgres://localhost/test",
        "postgres://user@localhost/test",
        "postgres://user:pass@localhost/test",
        "postgres://user:pass@localhost:5432/test",
        "postgresql://user:pass@localhost:5432/test",
    ];

    for url in urls {
        let result = create_pool(url, 5);
        assert!(result.is_ok(), "Failed to create pool for URL: {}", url);
    }
}
