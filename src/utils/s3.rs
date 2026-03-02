use anyhow::{Context, Result};
use aws_sdk_s3::{primitives, Client};
use bytes::Bytes;
use sha2::{Digest, Sha256};

pub async fn delete_objects_with_prefix(
    s3_client: &Client,
    bucket: &str,
    prefix: &str,
) -> Result<()> {
    let objects = s3_client
        .list_objects_v2()
        .bucket(bucket)
        .prefix(prefix)
        .send()
        .await
        .context("Failed to list objects for deletion in S3")?;

    for obj in objects.contents() {
        if let Some(key) = obj.key() {
            s3_client
                .delete_object()
                .bucket(bucket)
                .key(key)
                .send()
                .await
                .context(format!("Failed to delete S3 object: {}", key))?;
        }
    }
    Ok(())
}

pub async fn put_stream(
    client: &Client,
    bucket: &str,
    key: &str,
    body: primitives::ByteStream,
    expected_digest: Option<&str>,
) -> Result<()> {
    let body = if let Some(expected_digest) = expected_digest {
        let (algorithm, expected_hash) = expected_digest
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("Invalid digest format, expected 'algorithm:hash'"))?;

        let mut all_bytes = Vec::new();
        let computed_hash = match algorithm {
            "sha256" => {
                let bytes = body.collect().await?.into_bytes();
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                all_bytes.extend_from_slice(&bytes);
                format!("{:x}", hasher.finalize())
            }
            _ => anyhow::bail!("Unsupported hash algorithm: {}", algorithm),
        };

        if computed_hash != expected_hash {
            anyhow::bail!(
                "Digest mismatch: expected {}, got {}:{}",
                expected_digest,
                algorithm,
                computed_hash
            );
        }

        primitives::ByteStream::from(Bytes::from(all_bytes))
    } else {
        body
    };

    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(body)
        .send()
        .await
        .context("Failed to upload object to S3")?;

    Ok(())
}

#[cfg(test)]
#[path = "s3_tests.rs"]
mod test;
