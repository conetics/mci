use super::*;
use crate::errors;

// ── pure URL / scheme parsing (no filesystem access) ─────────────────────────

#[test]
fn test_http_url() {
    let result = Source::parse("http://example.com/example.json");
    assert_eq!(
        result.unwrap(),
        Source::Http("http://example.com/example.json".to_string())
    );
}

#[test]
fn test_https_url() {
    let result = Source::parse("https://example.com/example.json");
    assert_eq!(
        result.unwrap(),
        Source::Http("https://example.com/example.json".to_string())
    );
}

#[test]
fn test_unsupported_scheme_ftp() {
    let result = Source::parse("ftp://example.com/example.json");
    assert!(result.is_err());

    match result.unwrap_err() {
        errors::AppError::UnsupportedScheme(scheme) => assert_eq!(scheme, "ftp"),
        _ => panic!("Expected UnsupportedScheme error"),
    }
}

#[test]
fn test_unsupported_scheme_s3() {
    let result = Source::parse("s3://bucket/example.json");
    assert!(result.is_err());

    match result.unwrap_err() {
        errors::AppError::UnsupportedScheme(scheme) => assert_eq!(scheme, "s3"),
        _ => panic!("Expected UnsupportedScheme error"),
    }
}

#[test]
fn test_empty_string_returns_error() {
    let result = Source::parse("");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        errors::AppError::InvalidSource(_)
    ));
}

#[test]
fn test_http_url_with_query_params() {
    let result = Source::parse("https://example.com/def.json?version=1.0");
    assert_eq!(
        result.unwrap(),
        Source::Http("https://example.com/def.json?version=1.0".to_string())
    );
}

#[test]
fn test_http_url_with_port() {
    let result = Source::parse("http://localhost:8080/example.json");
    assert_eq!(
        result.unwrap(),
        Source::Http("http://localhost:8080/example.json".to_string())
    );
}

#[test]
fn test_single_slash_scheme_routed_to_parse_url() {
    let result = Source::parse("ftp:/example.com/example.json");
    assert!(result.is_err());
    match result.unwrap_err() {
        errors::AppError::UnsupportedScheme(scheme) => assert_eq!(scheme, "ftp"),
        e => panic!("expected UnsupportedScheme, got {e:?}"),
    }
}
