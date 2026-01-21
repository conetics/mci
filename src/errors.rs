use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use validator::ValidationErrors;

pub enum AppError {
    Database(diesel::result::Error),
    Pool(diesel::r2d2::PoolError),
    TaskJoin(tokio::task::JoinError),
    Validation(ValidationErrors),
}

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
        AppError::Database(err)
    }
}

impl From<tokio::task::JoinError> for AppError {
    fn from(err: tokio::task::JoinError) -> Self {
        AppError::TaskJoin(err)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::Database(diesel::result::Error::NotFound) => {
                (StatusCode::NOT_FOUND, "Resource not found".to_string())
            }
            AppError::Database(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            ),
            AppError::Pool(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Connection pool error".to_string(),
            ),
            AppError::TaskJoin(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Task execution error".to_string(),
            ),
            AppError::Validation(errors) => (
                StatusCode::BAD_REQUEST,
                format!("Validation error: {}", errors),
            ),
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}
