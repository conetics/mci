use crate::services::{configuration, secrets, ResourceKind};
use aws_sdk_s3::Client as S3Client;
use serde::Deserialize;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct InstallRequest {
    #[validate(url)]
    pub source: String,
}

/// Logs structured warnings for any S3 cleanup failures that occurred after a
/// successful DB deletion.  Cleanup is best-effort: this function never signals
/// failure so that the DB outcome is always authoritative.
pub fn handle_delete_cleanup(
    id: &str,
    kind: ResourceKind,
    config_result: anyhow::Result<()>,
    secrets_result: anyhow::Result<()>,
) {
    if let Err(e) = config_result {
        tracing::warn!(
            id = %id,
            kind = ?kind,
            error = %e,
            "Best-effort configuration cleanup failed after deletion; \
             orphaned S3 objects may remain under the '{}/{}/' prefix",
            kind.config_bucket(),
            id,
        );
    }
    if let Err(e) = secrets_result {
        tracing::warn!(
            id = %id,
            kind = ?kind,
            error = %e,
            "Best-effort secrets cleanup failed after deletion; \
             orphaned S3 objects may remain under the '{}/{}/' prefix",
            kind.secrets_bucket(),
            id,
        );
    }
}

/// Spawns a background task that performs best-effort S3 cleanup after a
/// successful DB deletion.  Each cleanup operation is attempted once; on
/// failure a single retry is issued and a structured `WARN`-level log is
/// emitted for every failed attempt so that log-aggregation pipelines can
/// trigger compensating workflows or alert on persistent orphaned objects.
///
/// The caller always receives control back immediately; the DB deletion result
/// is never reverted regardless of cleanup outcome.
pub fn spawn_cleanup_task(s3: S3Client, id: String, kind: ResourceKind) {
    tokio::spawn(async move {
        let config_result = configuration::delete_configuration(&s3, kind, &id).await;
        let config_result = if let Err(ref e) = config_result {
            tracing::warn!(
                id = %id,
                kind = ?kind,
                error = %e,
                attempt = 1u32,
                "Best-effort configuration cleanup failed; scheduling retry",
            );
            configuration::delete_configuration(&s3, kind, &id).await
        } else {
            config_result
        };

        let secrets_result = secrets::delete_secrets(&s3, kind, &id).await;
        let secrets_result = if let Err(ref e) = secrets_result {
            tracing::warn!(
                id = %id,
                kind = ?kind,
                error = %e,
                attempt = 1u32,
                "Best-effort secrets cleanup failed; scheduling retry",
            );
            secrets::delete_secrets(&s3, kind, &id).await
        } else {
            secrets_result
        };

        handle_delete_cleanup(&id, kind, config_result, secrets_result);
    });
}

#[cfg(test)]
#[path = "common_tests.rs"]
mod tests;
