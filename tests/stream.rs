use anyhow::Result;
use mci::utils::stream::{stream_content_from_path, stream_content_from_url};
use tempfile::TempDir;
use tokio::fs;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

#[tokio::test]
async fn stream_from_url_returns_body_on_success() -> Result<()> {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/data"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"hello stream"))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let url = format!("{}/data", server.uri());

    let response = stream_content_from_url(&client, &url).await?;
    let bytes = response.bytes().await?;

    assert_eq!(bytes.as_ref(), b"hello stream");

    Ok(())
}

#[tokio::test]
async fn stream_from_url_errors_on_non_2xx() -> Result<()> {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/notfound"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let url = format!("{}/notfound", server.uri());

    let result = stream_content_from_url(&client, &url).await;

    assert!(result.is_err());

    Ok(())
}

#[tokio::test]
async fn stream_from_path_reads_file_content() -> Result<()> {
    let dir = TempDir::new()?;
    let file_path = dir.path().join("data.bin");

    fs::write(&file_path, b"binary content").await?;

    let stream = stream_content_from_path(&file_path).await?;
    let collected = stream.collect().await?;

    assert_eq!(collected.into_bytes().as_ref(), b"binary content");

    Ok(())
}

#[tokio::test]
async fn stream_from_path_errors_on_missing_file() -> Result<()> {
    let result = stream_content_from_path("/nonexistent/path/data.bin").await;

    assert!(result.is_err());

    Ok(())
}
