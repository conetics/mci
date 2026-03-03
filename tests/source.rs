use mci::{errors::AppError, utils::source::Source};
use serial_test::serial;
use std::fs;
use tempfile::TempDir;
use url::Url;

#[test]
fn file_url_for_existing_file_parses_as_file_source() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("example.json");
    fs::write(&path, b"test").unwrap();

    let file_url = Url::from_file_path(&path).unwrap();
    let result = Source::parse(file_url.as_str());

    assert!(result.is_ok());
    match result.unwrap() {
        Source::File(p) => assert_eq!(p, path),
        Source::Http(_) => panic!("expected File variant"),
    }
}

#[test]
fn file_url_for_nonexistent_path_returns_not_found() {
    let result = Source::parse("file:///nonexistent/path/example.json");

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::NotFound(_)));
}

#[test]
fn absolute_path_to_existing_file_parses_correctly() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("example.json");
    fs::write(&path, b"test").unwrap();

    let result = Source::parse(path.to_str().unwrap());

    assert!(result.is_ok());
    match result.unwrap() {
        Source::File(p) => assert_eq!(p, path),
        Source::Http(_) => panic!("expected File variant"),
    }
}

#[test]
fn nonexistent_absolute_path_returns_not_found() {
    let result = Source::parse("/nonexistent/path/example.json");

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::NotFound(_)));
}

#[test]
fn path_to_directory_returns_bad_request() {
    let dir = TempDir::new().unwrap();

    let result = Source::parse(dir.path().to_str().unwrap());

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::BadRequest(_)));
}

#[test]
#[serial]
fn relative_path_to_existing_file_parses_correctly() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("example.json");
    fs::write(&path, b"test").unwrap();

    std::env::set_current_dir(&dir).unwrap();

    let result = Source::parse("./example.json");

    assert!(result.is_ok());
}

#[test]
fn as_path_returns_some_for_file_and_none_for_http() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("example.json");
    fs::write(&path, b"test").unwrap();

    let file_source = Source::parse(path.to_str().unwrap()).unwrap();
    assert!(file_source.as_path().is_some());
    assert_eq!(file_source.as_path().unwrap(), path.as_path());

    let http_source = Source::Http("http://example.com/def.json".into());
    assert!(http_source.as_path().is_none());
}

#[test]
fn as_url_returns_some_for_http_and_none_for_file() {
    let http_source = Source::Http("http://example.com/def.json".into());
    assert!(http_source.as_url().is_some());
    assert_eq!(http_source.as_url().unwrap(), "http://example.com/def.json");

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("example.json");
    fs::write(&path, b"test").unwrap();

    let file_source = Source::parse(path.to_str().unwrap()).unwrap();
    assert!(file_source.as_url().is_none());
}
