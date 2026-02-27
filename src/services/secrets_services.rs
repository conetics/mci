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

/// Map a SecretsTarget to its corresponding S3 bucket name.
///
/// # Examples
///
/// ```ignore
/// let b = bucket_for(SecretsTarget::Definition);
/// assert_eq!(b, "definition-secrets");
/// let b2 = bucket_for(SecretsTarget::Module);
/// assert_eq!(b2, "module-secrets");
/// ```
///
/// # Returns
///
/// The S3 bucket name for the given target.
fn bucket_for(target: SecretsTarget) -> &'static str {
    match target {
        SecretsTarget::Definition => "definition-secrets",
        SecretsTarget::Module => "module-secrets",
    }
}

/// Validate a JSON instance against a JSON Schema and return the validator's evaluation as JSON.
///
/// The returned JSON is the serialized evaluation list produced by the JSON Schema validator:
/// an empty array indicates the instance is valid; otherwise the array contains validation entries describing failures.
///
/// # Examples
///
/// ```no_run
/// use serde_json::json;
/// use mci::services::secrets_services::validate_secrets;
///
/// let schema = json!({"type": "object", "properties": {"a": {"type": "string"}}});
/// let valid = json!({"a": "ok"});
/// let invalid = json!({"a": 1});
///
/// let ok_eval = validate_secrets(&schema, &valid).unwrap();
/// let err_eval = validate_secrets(&schema, &invalid).unwrap();
/// ```
pub fn validate_secrets(schema: &JsonValue, secrets: &JsonValue) -> Result<JsonValue> {
    let validator = jsonschema::validator_for(schema).context("Invalid JSON schema")?;
    let evaluation = validator.evaluate(secrets);

    serde_json::to_value(evaluation.list()).context("Failed to serialize validation output")
}

/// Fetches and deserializes the secrets JSON Schema for the given target and id from S3.
///
/// On success returns the parsed `serde_json::Value` representing the schema. Returns an error
/// if the S3 object cannot be retrieved, its body cannot be read, or the JSON cannot be parsed.
///
/// # Examples
///
/// ```no_run
/// # use mci::services::secrets_services::{get_schema, SecretsTarget};
/// # async fn example(client: &aws_sdk_s3::Client) {
/// let schema = get_schema(client, SecretsTarget::Definition, "my-definition").await.unwrap();
/// assert!(schema.is_object());
/// # }
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

/// Retrieves the secrets JSON for the given target and id from S3.
///
/// Attempts to read "{id}/secrets.json" from the bucket for `target`. If the object does not
/// exist, returns `None`. On success returns the deserialized JSON value of the object.
///
/// # Returns
///
/// `Some(JsonValue)` with the parsed secrets JSON if the object exists, `None` if the key is not
/// present, or an error if the S3 request, stream read, or JSON deserialization fails.
///
/// # Examples
///
/// ```ignore
/// # use aws_sdk_s3::Client;
/// # async fn example(client: &Client) {
/// let id = "example-id";
/// let result = get_secrets(client, SecretsTarget::Definition, id).await;
/// match result {
///     Ok(Some(secrets)) => println!("Secrets: {}", secrets),
///     Ok(None) => println!("No secrets found for id: {}", id),
///     Err(e) => eprintln!("Error fetching secrets: {}", e),
/// }
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

// TODO: This read-modify-write (get_secrets -> apply_patch -> put_object) has a
// lost-update race under concurrent PATCH requests. The fix is to capture the
// S3 ETag from get_secrets and use a conditional PutObject (If-Match) so a
// concurrent write returns 412/409 instead of being silently overwritten.
// Deferred: requires verifying MinIO testcontainer compatibility with If-Match
// on PutObject, adding ETag threading through get_secrets, and designing the
// client-facing retry/conflict contract. Low priority — secrets patches are
// infrequent admin operations with minimal concurrency risk.

/// Applies a JSON Patch to the stored secrets for `id`, validates the patched result against the stored schema, and uploads the updated secrets to the appropriate S3 bucket.
///
/// If no existing secrets are found, an empty object `{}` is used as the patch base. On success the updated secrets are written to `{id}/secrets.json` in the bucket resolved from `target`. If `kms_key_id` is provided, server-side encryption with AWS KMS is enabled for the upload.
///
/// # Parameters
///
/// - `operations`: JSON Patch to apply to the current secrets.
/// - `kms_key_id`: Optional KMS Key ID to enable server-side encryption for the uploaded object.
///
/// # Returns
///
/// `Ok(())` on success, or an error if patch application, validation, serialization, or the S3 upload fails. If validation fails the error message will include the validation output prefixed by "Secrets changes are invalid:".
///
/// # Examples
///
/// ```no_run
/// # use aws_sdk_s3::Client;
/// # use json_patch::Patch;
/// # use mci::services::secrets_services::{patch_secrets, SecretsTarget};
/// # async fn example(s3_client: &Client) -> anyhow::Result<()> {
/// let patch = Patch::default();
/// let kms: Option<&str> = None;
/// patch_secrets(s3_client, SecretsTarget::Definition, "my-id", &patch, kms).await?;
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

/// Deletes all secret artifacts under the given identifier in the specified secrets target bucket.
///
/// The function removes all objects with the prefix "{id}/" from the S3 bucket mapped to `target`.
///
/// # Arguments
///
/// * `target` - The secrets target (Definition or Module) used to select the S3 bucket.
/// * `id` - The identifier whose secret artifacts (objects under the "{id}/" prefix) will be deleted.
///
/// # Returns
///
/// `Ok(())` on successful deletion, or an error if the S3 deletion operation fails.
///
/// # Examples
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use aws_sdk_s3::Client;
/// use mci::services::secrets_services::{delete_secrets, SecretsTarget};
///
/// // `client` would be an initialized S3 Client; shown here as a placeholder.
/// let client: Client = unimplemented!();
/// delete_secrets(&client, SecretsTarget::Definition, "my-resource").await?;
/// # Ok(())
/// # }
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
