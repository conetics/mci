use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::fmt;
use validator::ValidationErrors;

#[derive(Debug)]
pub enum AppError {
    NotFound(String),
    Conflict(String),
    BadRequest(String),
    Validation(ValidationErrors),

    UnsupportedScheme(String),
    InvalidSource(String),

    Internal(anyhow::Error),
    Pool(diesel::r2d2::PoolError),
    Database(diesel::result::Error),
    TaskJoin(tokio::task::JoinError),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Conflict(msg) => write!(f, "Conflict: {}", msg),
            AppError::NotFound(msg) => write!(f, "Not found: {}", msg),
            AppError::BadRequest(msg) => write!(f, "Bad request: {}", msg),
            AppError::Validation(err) => write!(f, "Validation error: {}", err),

            AppError::UnsupportedScheme(scheme) => write!(f, "Unsupported scheme: '{}'", scheme),
            AppError::InvalidSource(msg) => write!(f, "Invalid source: {}", msg),

            AppError::Internal(err) => write!(f, "Internal error: {}", err),
            AppError::Database(err) => write!(f, "Database error: {}", err),
            AppError::TaskJoin(err) => write!(f, "Task join error: {}", err),
            AppError::Pool(err) => write!(f, "Connection pool error: {}", err),
        }
    }
}

impl std::error::Error for AppError {}

impl From<ValidationErrors> for AppError {
    fn from(err: ValidationErrors) -> Self {
        AppError::Validation(err)
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

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::Internal(err)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_type, message) = match &self {
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "bad_request", msg.clone()),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, "not_found", msg.clone()),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, "conflict", msg.clone()),
            AppError::Validation(errors) => (
                StatusCode::BAD_REQUEST,
                "validation_error",
                format_validation_errors(errors),
            ),

            AppError::InvalidSource(msg) => {
                (StatusCode::BAD_REQUEST, "invalid_source", msg.clone())
            }
            AppError::UnsupportedScheme(scheme) => (
                StatusCode::BAD_REQUEST,
                "unsupported_scheme",
                format!("Unsupported scheme: '{}'", scheme),
            ),

            AppError::Database(err) => {
                tracing::error!("Database error: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "database_error",
                    "A database error occurred".to_string(),
                )
            }
            AppError::Pool(err) => {
                tracing::error!("Connection pool error: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "pool_error",
                    "Database connection error".to_string(),
                )
            }
            AppError::TaskJoin(err) => {
                tracing::error!("Task join error: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "task_error",
                    "Task execution failed".to_string(),
                )
            }
            AppError::Internal(err) => {
                tracing::error!("Internal error: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "An internal error occurred".to_string(),
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

impl AppError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        AppError::BadRequest(msg.into())
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        AppError::NotFound(msg.into())
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

    pub fn unsupported_scheme(scheme: impl Into<String>) -> Self {
        AppError::UnsupportedScheme(scheme.into())
    }
}

#[cfg(test)]
#[path = "errors_tests.rs"]
mod tests;
