use super::*;
use aws_sdk_s3::{primitives, Client};
use bytes::Bytes;
use sha2::{Digest, Sha256};

#[tokio::test]
async fn test_put_stream_sha256_digest_match() {
    let client = Client::from_conf(aws_sdk_s3::Config::builder().build());
    let data = b"hello world";

    let mut hasher = Sha256::new();
    hasher.update(data);

    let digest = format!("sha256:{:x}", hasher.finalize());
    let stream = primitives::ByteStream::from(Bytes::from_static(data));
    let result = put_stream(&client, "test-bucket", "test-key", stream, Some(&digest)).await;

    match result {
        Ok(_) => {}
        Err(e) => {
            let msg = format!("{e:?}");
            assert!(
                msg.contains("Failed to upload object to S3"),
                "expected an S3 upload error (no endpoint configured), but got: {msg}"
            );
        }
    }
}

#[tokio::test]
async fn test_put_stream_sha256_digest_mismatch() {
    let client = Client::from_conf(aws_sdk_s3::Config::builder().build());
    let data = b"hello world";
    let wrong_digest = "sha256:deadbeef";
    let stream = primitives::ByteStream::from(Bytes::from_static(data));
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

#[tokio::test]
async fn test_put_stream_invalid_digest_format() {
    let client = Client::from_conf(aws_sdk_s3::Config::builder().build());
    let data = b"hello world";
    let bad_digest = "nocolon";
    let stream = primitives::ByteStream::from(Bytes::from_static(data));
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
    let stream = primitives::ByteStream::from(Bytes::from_static(data));
    let result = put_stream(&client, "test-bucket", "test-key", stream, Some(digest)).await;
    let err = result.expect_err("should fail with unsupported algorithm");

    assert!(
        format!("{err:?}").contains("Unsupported hash algorithm"),
        "error should mention unsupported algorithm"
    );
}
