use anyhow::Result;
use aws_sdk_s3::{primitives::ByteStream, Client};

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use sha2::{Digest, Sha256};
    use tokio;

    #[tokio::test]
    async fn test_put_stream_sha256_digest_match() {
        let client = Client::from_conf(aws_sdk_s3::Config::builder().build());
        let data = b"hello world";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let digest = format!("sha256:{:x}", hasher.finalize());
        let stream = ByteStream::from(Bytes::from_static(data));
        let result = put_stream(&client, "test-bucket", "test-key", stream, Some(&digest)).await;
        assert!(result.is_ok());
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
        assert!(result.is_err());
    }
}
