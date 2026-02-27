use crate::utils::{json_utils, s3_utils};
use anyhow::{Context, Result};
use aws_sdk_s3::{
    error::SdkError, operation::get_object::GetObjectError, primitives::ByteStream, Client,
};
use serde_json::Value as JsonValue;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretsTarget {
    Definition,
    Module,
}

fn bucket_for(target: SecretsTarget) -> &'static str {
    match target {
        SecretsTarget::Definition => "definition-secrets",
        SecretsTarget::Module => "module-secrets",
    }
}

pub fn validate_secrets(schema: &JsonValue, secrets: &JsonValue) -> Result<JsonValue> {
    let validator = jsonschema::validator_for(schema).context("Invalid JSON schema")?;
    let evaluation = validator.evaluate(secrets);

    serde_json::to_value(evaluation.list()).context("Failed to serialize validation output")
}

pub async fn get_schema(s3_client: &Client, target: SecretsTarget, id: &str) -> Result<JsonValue> {
    let response = s3_client
        .get_object()
        .bucket(bucket_for(target))
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
    target: SecretsTarget,
    id: &str,
) -> Result<Option<JsonValue>> {
    let response = match s3_client
        .get_object()
        .bucket(bucket_for(target))
        .key(format!("{}/secrets.json", id))
        .send()
        .await
    {
        Ok(output) => output,
        Err(SdkError::ServiceError(err)) if matches!(err.err(), GetObjectError::NoSuchKey(_)) => {
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
    target: SecretsTarget,
    id: &str,
    operations: &json_patch::Patch,
    kms_key_id: Option<&str>,
) -> Result<()> {
    let current = get_secrets(s3_client, target, id)
        .await?
        .unwrap_or_else(|| serde_json::json!({}));

    let patched = json_utils::apply_patch(&current, operations)?;

    let schema = get_schema(s3_client, target, id).await?;
    let output = validate_secrets(&schema, &patched)?;
    let is_valid = output
        .get("valid")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !is_valid {
        anyhow::bail!("Secrets changes are invalid: {}", output);
    }

    let body = serde_json::to_vec_pretty(&patched)
        .context("Failed to serialize patched secrets for upload")?;

    let mut req = s3_client
        .put_object()
        .bucket(bucket_for(target))
        .key(format!("{}/secrets.json", id))
        .body(ByteStream::from(body));

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

pub async fn delete_secrets(s3_client: &Client, target: SecretsTarget, id: &str) -> Result<()> {
    let prefix = format!("{}/", id);
    s3_utils::delete_objects_with_prefix(s3_client, bucket_for(target), &prefix)
        .await
        .context("Failed to delete secrets artifacts from S3")?;

    Ok(())
}

#[cfg(test)]
#[path = "secrets_services_tests.rs"]
mod tests;
