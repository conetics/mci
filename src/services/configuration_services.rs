use crate::utils::s3_utils;
use anyhow::{Context, Result};
use aws_sdk_s3::{primitives::ByteStream, Client};
use serde_json::Value as JsonValue;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigurationTarget {
    Definition,
    Module,
}

fn bucket_for(target: ConfigurationTarget) -> &'static str {
    match target {
        ConfigurationTarget::Definition => "definition-configurations",
        ConfigurationTarget::Module => "module-configurations",
    }
}

pub fn validate_configuration(schema: &JsonValue, configuration: &JsonValue) -> Result<JsonValue> {
    let validator = jsonschema::validator_for(schema).context("Invalid JSON schema")?;
    let evaluation = validator.evaluate(configuration);

    serde_json::to_value(evaluation.list()).context("Failed to serialize validation output")
}

pub async fn get_schema(
    s3_client: &Client,
    target: ConfigurationTarget,
    id: &str,
) -> Result<JsonValue> {
    let response = s3_client
        .get_object()
        .bucket(bucket_for(target))
        .key(format!("{}/configuration.schema.json", id))
        .send()
        .await
        .context("Failed to get configuration schema from S3")?;
    let bytes = response
        .body
        .collect()
        .await
        .context("Failed to read configuration schema stream")?
        .into_bytes();

    serde_json::from_slice(&bytes).context("Failed to deserialize configuration schema JSON")
}

pub async fn get_configuration(
    s3_client: &Client,
    target: ConfigurationTarget,
    id: &str,
) -> Result<JsonValue> {
    let response = s3_client
        .get_object()
        .bucket(bucket_for(target))
        .key(format!("{}/configuration.json", id))
        .send()
        .await
        .context("Failed to get configuration from S3")?;
    let bytes = response
        .body
        .collect()
        .await
        .context("Failed to read configuration stream")?
        .into_bytes();

    serde_json::from_slice(&bytes).context("Failed to deserialize configuration JSON")
}

pub async fn put_configuration(
    s3_client: &Client,
    target: ConfigurationTarget,
    id: &str,
    configuration: &JsonValue,
) -> Result<()> {
    let schema = get_schema(s3_client, target, id).await?;
    let output = validate_configuration(&schema, configuration)?;
    let is_valid = output
        .get("valid")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !is_valid {
        anyhow::bail!("Configuration changes are invalid");
    }

    let body = serde_json::to_vec_pretty(configuration)
        .context("Failed to serialize configuration for upload")?;

    s3_client
        .put_object()
        .bucket(bucket_for(target))
        .key(format!("{}/configuration.json", id))
        .body(ByteStream::from(body))
        .send()
        .await
        .context("Failed to store configuration in S3")?;

    Ok(())
}

pub async fn patch_configuration(
    s3_client: &Client,
    target: ConfigurationTarget,
    id: &str,
    operations: &json_patch::Patch,
) -> Result<JsonValue> {
    use crate::utils::json_utils;

    let current = match get_configuration(s3_client, target, id).await {
        Ok(config) => config,
        Err(_) => serde_json::json!({}),
    };

    let patched = json_utils::apply_patch(&current, operations)?;

    let schema = get_schema(s3_client, target, id).await?;
    let output = validate_configuration(&schema, &patched)?;
    let is_valid = output
        .get("valid")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !is_valid {
        anyhow::bail!("Configuration changes are invalid");
    }

    let body = serde_json::to_vec_pretty(&patched)
        .context("Failed to serialize patched configuration for upload")?;

    s3_client
        .put_object()
        .bucket(bucket_for(target))
        .key(format!("{}/configuration.json", id))
        .body(ByteStream::from(body))
        .send()
        .await
        .context("Failed to store patched configuration in S3")?;

    Ok(patched)
}

pub async fn delete_configuration(
    s3_client: &Client,
    target: ConfigurationTarget,
    id: &str,
) -> Result<()> {
    s3_utils::delete_objects_with_prefix(s3_client, bucket_for(target), id)
        .await
        .context("Failed to delete configuration artifacts from S3")?;

    Ok(())
}

#[cfg(test)]
#[path = "configuration_services_tests.rs"]
mod tests;
