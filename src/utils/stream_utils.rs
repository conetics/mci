use crate::utils::http_client_utils::build_http_client;
use aws_smithy_types::byte_stream::ByteStream;
use std::path::Path;
use tokio_util::io::ReaderStream;

pub async fn stream_content_from_path(
    path: &str,
) -> Result<ReaderStream<tokio::fs::File>, Box<dyn std::error::Error>> {
    let file = tokio::fs::File::open(path).await?;

    Ok(ReaderStream::new(file))
}

pub async fn byte_stream_from_path(path: &str) -> Result<ByteStream, Box<dyn std::error::Error>> {
    Ok(ByteStream::from_path(Path::new(path)).await?)
}

pub async fn stream_content_from_url(
    url: &str,
) -> Result<reqwest::Response, Box<dyn std::error::Error>> {
    let client = build_http_client(30)?;
    let response = client
        .get(url)
        .header("User-Agent", "MCI/1.0")
        .send()
        .await?
        .error_for_status()?;

    Ok(response)
}
