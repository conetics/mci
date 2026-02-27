use crate::utils::{json_utils, s3_utils};
use anyhow::{Context, Result};
use aws_sdk_s3::{error::SdkError, operation::get_object::GetObjectError, primitives::ByteStream, Client};
use serde_json::Value as JsonValue;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretsTarget {
    Definition,
    Module,
}

/// Return the S3 bucket name associated with the given secret target.
///
/// The function maps a SecretsTarget variant to the literal bucket name used for that target.
///
/// # Examples
///
/// ```
/// use crate::services::secrets_services::SecretsTarget;
/// let bucket = crate::services::secrets_services::bucket_for(SecretsTarget::Definition);
/// assert_eq!(bucket, "definition-secrets");
/// ```
fn bucket_for(target: SecretsTarget) -> &'static str {
    match target {
        SecretsTarget::Definition => "definition-secrets",
        SecretsTarget::Module => "module-secrets",
    }
}

/// Validates a JSON instance against a JSON Schema and returns the validator's evaluation as JSON.
///
/// The returned JSON is the serialized evaluation list produced by the JSON Schema validator.
///
/// # Errors
/// Fails if the provided schema is invalid or if the validation output cannot be serialized.
///
/// # Examples
///
/// ```
/// use serde_json::json;
/// // Example schema: object with required string property "name".
/// let schema = json!({
///     "type": "object",
///     "properties": { "name": { "type": "string" } },
///     "required": ["name"]
/// });
///
/// let secrets = json!({ "name": "example" });
///
/// let eval = validate_secrets(&schema, &secrets).unwrap();
/// assert!(eval.is_array());
/// ```
pub fn validate_secrets(schema: &JsonValue, secrets: &JsonValue) -> Result<JsonValue> {
    let validator = jsonschema::validator_for(schema).context("Invalid JSON schema")?;
    let evaluation = validator.evaluate(secrets);

    serde_json::to_value(evaluation.list()).context("Failed to serialize validation output")
}

/// Fetches the secrets JSON Schema from S3 for the given target and id and returns it as JSON.
///
/// Retrieves the object at "<id>/secrets.schema.json" from the bucket corresponding to `target`,
/// deserializes the object body to a `serde_json::Value`, and returns it. Errors if the S3 fetch
/// or JSON deserialization fails; error contexts describe the failing step.
///
/// # Examples
///
/// ```no_run
/// # async fn example(client: &aws_sdk_s3::Client) -> Result<(), anyhow::Error> {
/// let schema = crate::services::secrets_services::get_schema(
///     client,
///     crate::services::secrets_services::SecretsTarget::Definition,
///     "my-id",
/// ).await?;
/// assert!(schema.is_object());
/// # Ok(()) }
/// ```
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

/// Fetches the secrets JSON for an identifier from the given target S3 bucket.
///
/// Attempts to retrieve "<id>/secrets.json" from the bucket for `target`. If the object exists, its
/// body is parsed as JSON and returned; if the object is missing, `None` is returned. Other S3 or
/// deserialization errors are propagated with context.
///
/// # Returns
///
/// `Some(JsonValue)` with the parsed secrets when the object exists, `None` if the object does not
/// exist, or an error on failure.
///
/// # Examples
///
/// ```
/// # async fn example_usage() -> anyhow::Result<()> {
/// # // `client` and actual AWS setup are omitted; this shows the call pattern.
/// # use aws_sdk_s3::Client;
/// # use serde_json::json;
/// # use crate::services::secrets_services::SecretsTarget;
/// // let client: Client = ...;
/// // let result = get_secrets(&client, SecretsTarget::Definition, "my-id").await?;
/// // match result {
/// //     Some(secrets) => println!("secrets: {}", secrets),
/// //     None => println!("no secrets found"),
/// // }
/// # Ok(())
/// # }
/// ```
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

/// Apply a JSON Patch to the stored secrets, validate the result against the stored schema, and upload the updated secrets to S3.
///
/// The function loads the current secrets (or uses an empty object if missing), applies the provided JSON Patch operations, validates the patched secrets against the corresponding schema stored in S3, and on successful validation writes the updated secrets back to S3. If `kms_key_id` is provided, the uploaded object is encrypted using SSE-KMS with that key.
///
/// # Parameters
///
/// - `s3_client`: AWS S3 client used to read and write objects.
/// - `target`: Which secrets bucket to operate on (Definition or Module).
/// - `id`: Identifier of the secret resource; used as the object key prefix.
/// - `operations`: JSON Patch operations to apply to the current secrets.
/// - `kms_key_id`: Optional KMS key id to enable server-side encryption with AWS KMS.
///
/// # Returns
///
/// `Ok(())` on success, error otherwise.
///
/// # Examples
///
/// ```
/// # use json_patch::Patch;
/// # use aws_sdk_s3::Client;
/// # use crate::services::secrets_services::SecretsTarget;
/// # async fn example() -> anyhow::Result<()> {
/// let s3_client = /* construct or obtain an S3 Client */ unimplemented!();
/// let patch = Patch::new(); // build patch operations
/// patch_secrets(&s3_client, SecretsTarget::Definition, "my-secret-id", &patch, Some("arn:aws:kms:...")) .await?;
/// # Ok(())
/// # }
/// ```
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
        anyhow::bail!("Secrets changes are invalid");
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

/// Delete all secret-related objects under the given id prefix in the target bucket.
///
/// Attempts to remove every S3 object whose key begins with "<id>/" in the bucket for `target`.
///
/// # Returns
///
/// `Ok(())` on success, an error if the S3 deletion operation fails.
///
/// # Examples
///
/// ```no_run
/// # use aws_sdk_s3::Client;
/// # use crate::services::secrets_services::{delete_secrets, SecretsTarget};
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     let client = /* create S3 client */;
///     delete_secrets(&client, SecretsTarget::Definition, "my-id").await?;
///     Ok(())
/// }
/// ```
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
