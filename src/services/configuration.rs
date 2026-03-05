use crate::services::common::{validate_schema, ResourceKind};
use anyhow::{Context, Result};
use aws_sdk_s3::{error, operation, primitives, Client};
use serde_json::Value as JsonValue;

pub fn validate_configuration(schema: &JsonValue, configuration: &JsonValue) -> Result<JsonValue> {
    validate_schema(schema, configuration)
}

pub async fn get_schema(s3_client: &Client, target: ResourceKind, id: &str) -> Result<JsonValue> {
    let send_result = s3_client
        .get_object()
        .bucket(target.config_bucket())
        .key(format!("{}/configuration.schema.json", id))
        .send()
        .await;
    let response = match send_result {
        Ok(r) => r,
        Err(error::SdkError::ServiceError(err))
            if matches!(
                err.err(),
                operation::get_object::GetObjectError::NoSuchKey(_)
            ) =>
        {
            return Err(crate::errors::AppError::not_found("Configuration not found").into());
        }
        Err(e) => return Err(e).context("Failed to get configuration schema from S3"),
    };
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
    target: ResourceKind,
    id: &str,
) -> Result<JsonValue> {
    let send_result = s3_client
        .get_object()
        .bucket(target.config_bucket())
        .key(format!("{}/configuration.json", id))
        .send()
        .await;
    let response = match send_result {
        Ok(r) => r,
        Err(error::SdkError::ServiceError(err))
            if matches!(
                err.err(),
                operation::get_object::GetObjectError::NoSuchKey(_)
            ) =>
        {
            return Err(crate::errors::AppError::not_found("Configuration not found").into());
        }
        Err(e) => return Err(e).context("Failed to get configuration from S3"),
    };
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
    target: ResourceKind,
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
        return Err(crate::errors::ServiceError::InvalidChanges(
            "Configuration changes are invalid".into(),
        )
        .into());
    }

    let body = serde_json::to_vec_pretty(configuration)
        .context("Failed to serialize configuration for upload")?;

    s3_client
        .put_object()
        .bucket(target.config_bucket())
        .key(format!("{}/configuration.json", id))
        .body(primitives::ByteStream::from(body))
        .send()
        .await
        .context("Failed to store configuration in S3")?;

    Ok(())
}

pub async fn patch_configuration(
    s3_client: &Client,
    target: ResourceKind,
    id: &str,
    operations: &json_patch::Patch,
) -> Result<JsonValue> {
    let current = match get_configuration(s3_client, target, id).await {
        Ok(config) => config,
        Err(e) => {
            if e.downcast_ref::<crate::errors::AppError>()
                .map(|ae| matches!(ae, crate::errors::AppError::NotFound(_)))
                .unwrap_or(false)
            {
                serde_json::json!({})
            } else {
                return Err(e);
            }
        }
    };
    let patched = crate::utils::json::apply_patch(&current, operations)
        .map_err(|e| crate::errors::ServiceError::PatchFailed { source: e })?;
    let schema = get_schema(s3_client, target, id).await?;
    let output = validate_configuration(&schema, &patched)?;
    let is_valid = output
        .get("valid")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !is_valid {
        return Err(crate::errors::ServiceError::InvalidChanges(
            "Configuration changes are invalid".into(),
        )
        .into());
    }

    let body = serde_json::to_vec_pretty(&patched)
        .context("Failed to serialize patched configuration for upload")?;

    s3_client
        .put_object()
        .bucket(target.config_bucket())
        .key(format!("{}/configuration.json", id))
        .body(primitives::ByteStream::from(body))
        .send()
        .await
        .context("Failed to store patched configuration in S3")?;

    Ok(patched)
}

pub async fn delete_configuration(
    s3_client: &Client,
    target: ResourceKind,
    id: &str,
) -> Result<()> {
    let prefix = format!("{}/", id);
    crate::utils::s3::delete_objects_with_prefix(s3_client, target.config_bucket(), &prefix)
        .await
        .context("Failed to delete configuration artifacts from S3")?;
    Ok(())
}
