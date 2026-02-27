use super::*;
use aws_sdk_s3::{primitives::ByteStream, Client};
use bytes::Bytes;
use sha2::{Digest, Sha256};

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

#[tokio::test]
async fn test_put_stream_with_none_digest() {
    let client = Client::from_conf(aws_sdk_s3::Config::builder().build());
    let data = b"test data without digest";
    let stream = ByteStream::from(Bytes::from_static(data));
    let result = put_stream(&client, "test-bucket", "test-key", stream, None).await;

    match result {
        Ok(_) => {}
        Err(e) => {
            let msg = format!("{e:?}");
            assert!(
                !msg.contains("Digest"),
                "should not have digest-related error when None is passed, got: {msg}"
            );
        }
    }
}

#[tokio::test]
async fn test_put_stream_empty_data_with_digest() {
    let client = Client::from_conf(aws_sdk_s3::Config::builder().build());
    let data = b"";
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
                "should not get a digest error for empty data with correct digest, got: {msg}"
            );
        }
    }
}

#[tokio::test]
async fn test_put_stream_large_data_digest_match() {
    let client = Client::from_conf(aws_sdk_s3::Config::builder().build());
    let data = vec![b'x'; 10_000];
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let digest = format!("sha256:{:x}", hasher.finalize());
    let stream = ByteStream::from(Bytes::from(data));
    let result = put_stream(&client, "test-bucket", "test-key", stream, Some(&digest)).await;

    match result {
        Ok(_) => {}
        Err(e) => {
            let msg = format!("{e:?}");
            assert!(
                !msg.contains("Digest mismatch"),
                "should not get a digest error for large data with correct digest, got: {msg}"
            );
        }
    }
}

#[tokio::test]
async fn test_put_stream_digest_with_multiple_colons() {
    let client = Client::from_conf(aws_sdk_s3::Config::builder().build());
    let data = b"test";
    let digest = "sha256:abc:def:ghi";
    let stream = ByteStream::from(Bytes::from_static(data));
    let result = put_stream(&client, "test-bucket", "test-key", stream, Some(digest)).await;
    let err = result.expect_err("should fail with multiple colons in digest");
    assert!(
        format!("{err:?}").contains("Digest mismatch"),
        "error should mention digest mismatch for malformed hash"
    );
}

#[tokio::test]
async fn test_put_stream_digest_case_sensitivity() {
    let client = Client::from_conf(aws_sdk_s3::Config::builder().build());
    let data = b"hello world";
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest_lower = format!("sha256:{:x}", hasher.finalize());
    let stream = ByteStream::from(Bytes::from_static(data));

    let result = put_stream(&client, "test-bucket", "test-key", stream, Some(&digest_lower)).await;

    match result {
        Ok(_) => {}
        Err(e) => {
            let msg = format!("{e:?}");
            assert!(
                !msg.contains("Digest mismatch"),
                "lowercase hex digest should match, got: {msg}"
            );
        }
    }
}

#[tokio::test]
async fn test_put_stream_algorithm_case_sensitivity() {
    let client = Client::from_conf(aws_sdk_s3::Config::builder().build());
    let data = b"test";
    let digest = "SHA256:abc123";
    let stream = ByteStream::from(Bytes::from_static(data));
    let result = put_stream(&client, "test-bucket", "test-key", stream, Some(digest)).await;
    let err = result.expect_err("should fail with uppercase algorithm");
    assert!(
        format!("{err:?}").contains("Unsupported hash algorithm"),
        "error should mention unsupported algorithm for uppercase"
    );
}

#[tokio::test]
async fn test_put_stream_whitespace_in_digest() {
    let client = Client::from_conf(aws_sdk_s3::Config::builder().build());
    let data = b"test";
    let digest = " sha256:abc123 ";
    let stream = ByteStream::from(Bytes::from_static(data));
    let result = put_stream(&client, "test-bucket", "test-key", stream, Some(digest)).await;

    assert!(
        result.is_err(),
        "should fail with whitespace in digest"
    );
}