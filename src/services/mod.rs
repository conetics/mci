// TODO: Add an orphan cleanup function (e.g. `cleanup_orphaned_artifacts`) that
// reconciles S3 state against the database and removes stale objects. Process:
//
// 1. List all top-level prefixes (i.e. resource ids) in each S3 bucket:
//    - definition-configurations, definition-secrets
//    - module-configurations, module-secrets
//    - definitions, modules
// 2. For each discovered prefix/id, query the database to check whether the
//    corresponding definition or module record still exists.
// 3. If the record no longer exists, delete all objects under that prefix —
//    these are orphans left behind by partial delete failures.
// 4. Optionally emit structured logs or metrics for each orphan removed so
//    the operator has visibility into cleanup activity.
// 5. Expose the function behind an admin-only endpoint or run it on a
//    periodic schedule (e.g. tokio cron task) so orphans don't accumulate.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("{0}")]
    InvalidChanges(String),

    #[error("Failed to apply JSON patch: {source}")]
    PatchFailed {
        #[source]
        source: anyhow::Error,
    },
}

pub mod configuration_services;
pub mod definitions_services;
pub mod modules_services;
pub mod secrets_services;
