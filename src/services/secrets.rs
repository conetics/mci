use crate::services::common::{validate_schema, ResourceKind};
use crate::{errors, utils};
use anyhow::{Context, Result};
use aws_sdk_s3::{error, operation, primitives, Client};
use serde_json::Value as JsonValue;

pub fn validate_secrets(schema: &JsonValue, secrets: &JsonValue) -> Result<JsonValue> {
    validate_schema(schema, secrets)
}

pub async fn get_schema(s3_client: &Client, target: ResourceKind, id: &str) -> Result<JsonValue> {
    let response = s3_client
        .get_object()
        .bucket(target.secrets_bucket())
        .key(format!("{}/secrets.schema.json", id))
        .send()
        .await
        .context("Failed to get secrets schema from S3")?;
    let bytes = response
        .body
        .collect()
        .await
        .context("Failed to read secrets schema stream")?
        .into_bytes();

    serde_json::from_slice(&bytes).context("Failed to deserialize secrets schema JSON")
}

async fn get_secrets(
    s3_client: &Client,
    target: ResourceKind,
    id: &str,
) -> Result<Option<JsonValue>> {
    let response = match s3_client
        .get_object()
        .bucket(target.secrets_bucket())
        .key(format!("{}/secrets.json", id))
        .send()
        .await
    {
        Ok(output) => output,
        Err(error::SdkError::ServiceError(err))
            if matches!(
                err.err(),
                operation::get_object::GetObjectError::NoSuchKey(_)
            ) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e).context("Failed to get secrets from S3"),
    };
    let bytes = response
        .body
        .collect()
        .await
        .context("Failed to read secrets stream")?
        .into_bytes();

    serde_json::from_slice(&bytes)
        .map(Some)
        .context("Failed to deserialize secrets JSON")
}

pub async fn patch_secrets(
    s3_client: &Client,
    target: ResourceKind,
    id: &str,
    operations: &json_patch::Patch,
    kms_key_id: Option<&str>,
) -> Result<()> {
    let current = get_secrets(s3_client, target, id)
        .await?
        .unwrap_or_else(|| serde_json::json!({}));
    let patched = utils::json::apply_patch(&current, operations)
        .map_err(|e| errors::ServiceError::PatchFailed { source: e })?;
    let schema = get_schema(s3_client, target, id).await?;
    let output = validate_secrets(&schema, &patched)?;
    let is_valid = output
        .get("valid")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !is_valid {
        return Err(errors::ServiceError::InvalidChanges(format!(
            "Secrets changes are invalid: {}",
            output
        ))
        .into());
    }
    let body = serde_json::to_vec_pretty(&patched)
        .context("Failed to serialize patched secrets for upload")?;
    let mut req = s3_client
        .put_object()
        .bucket(target.secrets_bucket())
        .key(format!("{}/secrets.json", id))
        .body(primitives::ByteStream::from(body));

    if let Some(key_id) = kms_key_id {
        req = req
            .server_side_encryption(aws_sdk_s3::types::ServerSideEncryption::AwsKms)
            .ssekms_key_id(key_id);
    }

    req.send()
        .await
        .context("Failed to store patched secrets in S3")?;

    Ok(())
}

pub async fn delete_secrets(s3_client: &Client, target: ResourceKind, id: &str) -> Result<()> {
    let prefix = format!("{}/", id);
    utils::s3::delete_objects_with_prefix(s3_client, target.secrets_bucket(), &prefix)
        .await
        .context("Failed to delete secrets artifacts from S3")?;
    Ok(())
}
