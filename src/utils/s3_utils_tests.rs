use super::*;
use aws_sdk_s3::{primitives::ByteStream, Client};
use bytes::Bytes;
use sha2::{Digest, Sha256};

/// Verifies that uploading a stream with a matching SHA-256 digest does not produce a digest-mismatch error.
///
/// The test computes the SHA-256 digest for the bytes `"hello world"`, uploads the data via `put_stream` with
/// the computed `sha256:<hex>` digest, and fails if an error contains `"Digest mismatch"`.
///
/// # Examples
///
///
///
/// // Prepare client and data
/// let client = aws_sdk_s3::Client::from_conf(aws_sdk_s3::Config::builder().build());
/// let data = b"hello world";
///
/// // Compute digest
/// let mut hasher = Sha256::new();
/// hasher.update(data);
/// let digest = format!("sha256:{:x}", hasher.finalize());
///
/// // Build stream and call `put_stream` (async)
/// let stream = ByteStream::from(Bytes::from_static(data));
/// // put_stream(&client, "test-bucket", "test-key", stream, Some(&digest)).await?;
/// ```
#[tokio::test]
async fn test_put_stream_sha256_digest_match() {
    let client = Client::from_conf(aws_sdk_s3::Config::builder().build());
    let data = b"hello world";
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = format!("sha256:{:x}", hasher.finalize());
    let stream = ByteStream::from(Bytes::from_static(data));
    let result = put_stream(&client, "test-bucket", "test-key", stream, Some(&digest)).await;

    match result {
        Ok(_) => {}
        Err(e) => {
            let msg = format!("{e:?}");
            assert!(
                !msg.contains("Digest mismatch"),
                "should not get a digest error when digest matches, got: {msg}"
            );
        }
    }
}

#[tokio::test]
async fn test_put_stream_sha256_digest_mismatch() {
    let client = Client::from_conf(aws_sdk_s3::Config::builder().build());
    let data = b"hello world";
    let wrong_digest = "sha256:deadbeef";
    let stream = ByteStream::from(Bytes::from_static(data));
    let result = put_stream(
        &client,
        "test-bucket",
        "test-key",
        stream,
        Some(wrong_digest),
    )
    .await;
    let err = result.expect_err("should fail with wrong digest");
    assert!(
        format!("{err:?}").contains("Digest mismatch"),
        "error should mention digest mismatch"
    );
}

/// Verifies that `put_stream` returns an error when given a digest string with an invalid format.
///
/// # Examples
///
/// ```
/// # use aws_sdk_s3::Client;
/// # use aws_smithy_http::byte_stream::ByteStream;
/// # use bytes::Bytes;
/// # async fn __example() {
/// let client = Client::from_conf(aws_sdk_s3::Config::builder().build());
/// let data = b"hello world";
/// let bad_digest = "nocolon";
/// let stream = ByteStream::from(Bytes::from_static(data));
/// let result = put_stream(&client, "test-bucket", "test-key", stream, Some(bad_digest)).await;
/// let err = result.expect_err("should fail with invalid digest format");
/// assert!(format!("{err:?}").contains("Invalid digest format"));
/// # }
/// ```
#[tokio::test]
async fn test_put_stream_invalid_digest_format() {
    let client = Client::from_conf(aws_sdk_s3::Config::builder().build());
    let data = b"hello world";
    let bad_digest = "nocolon";
    let stream = ByteStream::from(Bytes::from_static(data));
    let result = put_stream(&client, "test-bucket", "test-key", stream, Some(bad_digest)).await;
    let err = result.expect_err("should fail with invalid digest format");
    assert!(
        format!("{err:?}").contains("Invalid digest format"),
        "error should mention invalid digest format"
    );
}

#[tokio::test]
async fn test_put_stream_unsupported_algorithm() {
    let client = Client::from_conf(aws_sdk_s3::Config::builder().build());
    let data = b"hello world";
    let digest = "md5:abc123";
    let stream = ByteStream::from(Bytes::from_static(data));
    let result = put_stream(&client, "test-bucket", "test-key", stream, Some(digest)).await;
    let err = result.expect_err("should fail with unsupported algorithm");
    assert!(
        format!("{err:?}").contains("Unsupported hash algorithm"),
        "error should mention unsupported algorithm"
    );
}
