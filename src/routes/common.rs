use crate::errors::AppError;
use anyhow::anyhow;
use axum::http;
use serde::Deserialize;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct InstallRequest {
    #[validate(url)]
    pub source: String,
}

pub async fn handle_delete_cleanup(
    id: &str,
    entity_label: &str,
    config_result: anyhow::Result<()>,
    secrets_result: anyhow::Result<()>,
) -> Result<http::StatusCode, AppError> {
    match (config_result, secrets_result) {
        (Ok(()), Ok(())) => Ok(http::StatusCode::NO_CONTENT),
        (Err(e), Ok(())) => Err(anyhow!(
            "{} '{}' was deleted but its configuration could not be removed from S3: {}. \
             Orphaned configuration objects may remain in the '{}/' prefix.",
            entity_label,
            id,
            e,
            id
        )
        .into()),
        (Ok(()), Err(e)) => Err(anyhow!(
            "{} '{}' was deleted but its secrets could not be removed from S3: {}. \
             Orphaned secrets objects may remain in the '{}/' prefix.",
            entity_label,
            id,
            e,
            id
        )
        .into()),
        (Err(config_err), Err(secrets_err)) => Err(anyhow!(
            "{} '{}' was deleted but S3 cleanup failed for both configuration ({}) and \
                 secrets ({}). Orphaned objects may remain in the '{}/' prefix.",
            entity_label,
            id,
            config_err,
            secrets_err,
            id
        )
        .into()),
    }
}

#[cfg(test)]
#[path = "common_tests.rs"]
mod tests;
