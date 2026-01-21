use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use validator::ValidationErrors;

#[derive(Debug)]
pub enum AppError {
    Database(diesel::result::Error),
    Pool(deadpool_diesel::PoolError),
    R2D2(diesel::r2d2::Error),
    TaskJoin(tokio::task::JoinError),
    Validation(ValidationErrors),
}

impl From<ValidationErrors> for AppError {
    fn from(err: ValidationErrors) -> Self {
        AppError::Validation(err)
    }
}

impl From<diesel::result::Error> for AppError {
    fn from(err: diesel::result::Error) -> Self {
        AppError::Database(err)
    }
}

impl From<deadpool_diesel::PoolError> for AppError {
    fn from(err: deadpool_diesel::PoolError) -> Self {
        AppError::Pool(err)
    }
}

impl From<tokio::task::JoinError> for AppError {
    fn from(err: tokio::task::JoinError) -> Self {
        AppError::TaskJoin(err)
    }
}

impl From<diesel::r2d2::Error> for AppError {
    fn from(err: diesel::r2d2::Error) -> Self {
        AppError::R2D2(err)
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
            AppError::R2D2(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Connection pool error".to_string(),
            ),
            AppError::TaskJoin(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Task execution error".to_string(),
            ),
            AppError::Validation(errors) => {
                let a = errors.field_errors();
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("Validation error: {}", errors),
                )
            }
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}