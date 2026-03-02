use anyhow::Result;
use aws_smithy_types::byte_stream;
use reqwest::{Client, Response};
use std::path;

pub async fn stream_content_from_url(http_client: &Client, url: &str) -> Result<Response> {
    let response = http_client.get(url).send().await?.error_for_status()?;
    Ok(response)
}

pub async fn stream_content_from_path(
    path: impl AsRef<path::Path>,
) -> Result<byte_stream::ByteStream> {
    Ok(byte_stream::ByteStream::from_path(path).await?)
}

#[cfg(test)]
#[path = "stream_tests.rs"]
mod tests;
