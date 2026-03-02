use axum::{http, response, Json};
use serde_json::json;
use std::{error, fmt};
use thiserror::Error;
use validator::ValidationErrors;

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

#[derive(Debug)]
pub enum AppError {
    // 4xx
    BadRequest(String),
    Conflict(String),
    InvalidSource(String),
    NotFound(String),
    UnsupportedScheme(String),
    Validation(ValidationErrors),

    // 5xx
    Database(diesel::result::Error),
    Internal(anyhow::Error),
    Pool(diesel::r2d2::PoolError),
    TaskJoin(tokio::task::JoinError),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::BadRequest(msg) => write!(f, "Bad request: {}", msg),
            AppError::Conflict(msg) => write!(f, "Conflict: {}", msg),
            AppError::InvalidSource(msg) => write!(f, "Invalid source: {}", msg),
            AppError::NotFound(msg) => write!(f, "Not found: {}", msg),
            AppError::UnsupportedScheme(scheme) => write!(f, "Unsupported scheme: '{}'", scheme),
            AppError::Validation(err) => write!(f, "Validation error: {}", err),
            AppError::Database(err) => write!(f, "Database error: {}", err),
            AppError::Internal(err) => write!(f, "Internal error: {}", err),
            AppError::Pool(err) => write!(f, "Connection pool error: {}", err),
            AppError::TaskJoin(err) => write!(f, "Task join error: {}", err),
        }
    }
}

impl error::Error for AppError {}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::Internal(err)
    }
}

impl From<diesel::r2d2::PoolError> for AppError {
    fn from(err: diesel::r2d2::PoolError) -> Self {
        AppError::Pool(err)
    }
}

impl From<diesel::result::Error> for AppError {
    fn from(err: diesel::result::Error) -> Self {
        match err {
            diesel::result::Error::NotFound => AppError::NotFound("Resource not found".to_string()),
            _ => AppError::Database(err),
        }
    }
}

impl From<tokio::task::JoinError> for AppError {
    fn from(err: tokio::task::JoinError) -> Self {
        AppError::TaskJoin(err)
    }
}

impl From<ValidationErrors> for AppError {
    fn from(err: ValidationErrors) -> Self {
        AppError::Validation(err)
    }
}

impl response::IntoResponse for AppError {
    fn into_response(self) -> response::Response {
        let (status, error_type, message) = match &self {
            // 4xx
            AppError::BadRequest(msg) => {
                (http::StatusCode::BAD_REQUEST, "bad_request", msg.clone())
            }
            AppError::Conflict(msg) => (http::StatusCode::CONFLICT, "conflict", msg.clone()),
            AppError::InvalidSource(msg) => {
                (http::StatusCode::BAD_REQUEST, "invalid_source", msg.clone())
            }
            AppError::NotFound(msg) => (http::StatusCode::NOT_FOUND, "not_found", msg.clone()),
            AppError::UnsupportedScheme(scheme) => (
                http::StatusCode::BAD_REQUEST,
                "unsupported_scheme",
                format!("Unsupported scheme: '{}'", scheme),
            ),
            AppError::Validation(errors) => (
                http::StatusCode::BAD_REQUEST,
                "validation_error",
                format_validation_errors(errors),
            ),

            // 5xx
            AppError::Database(err) => {
                tracing::error!("Database error: {:?}", err);
                (
                    http::StatusCode::INTERNAL_SERVER_ERROR,
                    "database_error",
                    "A database error occurred".to_string(),
                )
            }
            AppError::Internal(err) => {
                tracing::error!("Internal error: {:?}", err);
                (
                    http::StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "An internal error occurred".to_string(),
                )
            }
            AppError::Pool(err) => {
                tracing::error!("Connection pool error: {:?}", err);
                (
                    http::StatusCode::INTERNAL_SERVER_ERROR,
                    "pool_error",
                    "Database connection error".to_string(),
                )
            }
            AppError::TaskJoin(err) => {
                tracing::error!("Task join error: {:?}", err);
                (
                    http::StatusCode::INTERNAL_SERVER_ERROR,
                    "task_error",
                    "Task execution failed".to_string(),
                )
            }
        };

        let body = Json(json!({
            "error": {
                "type": error_type,
                "message": message,
            }
        }));

        (status, body).into_response()
    }
}

impl AppError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        AppError::BadRequest(msg.into())
    }

    pub fn conflict(msg: impl Into<String>) -> Self {
        AppError::Conflict(msg.into())
    }

    pub fn internal(err: impl Into<anyhow::Error>) -> Self {
        AppError::Internal(err.into())
    }

    pub fn invalid_source(msg: impl Into<String>) -> Self {
        AppError::InvalidSource(msg.into())
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        AppError::NotFound(msg.into())
    }

    pub fn unsupported_scheme(scheme: impl Into<String>) -> Self {
        AppError::UnsupportedScheme(scheme.into())
    }

    pub fn from_service_error(err: anyhow::Error) -> Self {
        match err.downcast::<ServiceError>() {
            Ok(service_err) => AppError::BadRequest(service_err.to_string()),
            Err(other) => AppError::Internal(other),
        }
    }
}

fn format_validation_errors(errors: &ValidationErrors) -> String {
    let mut messages = Vec::new();

    for (field, field_errors) in errors.field_errors() {
        for error in field_errors {
            let message = error
                .message
                .as_ref()
                .map(|m| m.to_string())
                .unwrap_or_else(|| format!("Invalid value for field '{}'", field));

            messages.push(message);
        }
    }

    messages.join(", ")
}

#[cfg(test)]
#[path = "errors_tests.rs"]
mod tests;
