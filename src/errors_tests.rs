use super::*;
use http_body_util::BodyExt;
use validator::{Validate, ValidationError};

#[derive(Debug, Validate)]
struct TestStruct {
    #[validate(length(min = 3))]
    name: String,
    #[validate(range(min = 18))]
    age: i32,
}

fn validate_schema(test: &SchemaTest) -> Result<(), ValidationError> {
    if test.value.is_none() {
        let mut error = ValidationError::new("missing_value");
        error.message = Some("value required".into());
        return Err(error);
    }
    Ok(())
}

#[derive(Debug, Validate)]
#[validate(schema(function = "validate_schema"))]
struct SchemaTest {
    value: Option<String>,
}

#[test]
fn test_format_validation_errors_with_custom_messages() {
    let test = TestStruct {
        name: "ab".to_string(),
        age: 15,
    };
    let errors = test.validate().unwrap_err();
    let formatted = format_validation_errors(&errors);

    assert!(formatted.contains("name") || formatted.contains("age"));
}

#[test]
fn test_format_validation_errors_includes_schema_errors() {
    let test = SchemaTest { value: None };
    let errors = test.validate().unwrap_err();
    let formatted = format_validation_errors(&errors);

    assert!(formatted.contains("value required"));
}

#[tokio::test]
async fn test_app_error_not_found_response() {
    let error = AppError::not_found("User not found");
    let response = error.into_response();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body = response.into_body();
    let bytes = body.collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(json["error"]["type"], "not_found");
    assert_eq!(json["error"]["message"], "User not found");
}

#[tokio::test]
async fn test_app_error_bad_request_response() {
    let error = AppError::bad_request("Invalid input");
    let response = error.into_response();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body();
    let bytes = body.collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(json["error"]["type"], "bad_request");
    assert_eq!(json["error"]["message"], "Invalid input");
}

#[tokio::test]
async fn test_app_error_validation_response() {
    let test = TestStruct {
        name: "ab".to_string(),
        age: 15,
    };
    let validation_errors = test.validate().unwrap_err();
    let error = AppError::from(validation_errors);
    let response = error.into_response();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body();
    let bytes = body.collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(json["error"]["type"], "validation_error");
    assert!(!json["error"]["message"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn test_app_error_internal_hides_details() {
    let error = AppError::internal(anyhow::anyhow!("Sensitive database password exposed"));
    let response = error.into_response();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let body = response.into_body();
    let bytes = body.collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(json["error"]["type"], "internal_error");
    assert_eq!(json["error"]["message"], "An internal error occurred");
    assert!(!json["error"]["message"]
        .as_str()
        .unwrap()
        .contains("password"));
}

#[test]
fn test_diesel_not_found_converts_to_app_error_not_found() {
    let diesel_error = diesel::result::Error::NotFound;
    let app_error = AppError::from(diesel_error);

    match app_error {
        AppError::NotFound(msg) => {
            assert_eq!(msg, "Resource not found");
        }
        _ => panic!("Expected NotFound variant"),
    }
}

#[test]
fn test_diesel_other_error_converts_to_database_error() {
    let diesel_error = diesel::result::Error::DatabaseError(
        diesel::result::DatabaseErrorKind::UniqueViolation,
        Box::new("test".to_string()),
    );
    let app_error = AppError::from(diesel_error);

    match app_error {
        AppError::Database(_) => {}
        _ => panic!("Expected Database variant"),
    }
}

#[tokio::test]
async fn test_app_error_invalid_source_response() {
    let error = AppError::invalid_source("invalid://source");
    let response = error.into_response();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body();
    let bytes = body.collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(json["error"]["type"], "invalid_source");
    assert!(json["error"]["message"]
        .as_str()
        .unwrap()
        .contains("invalid://source"));
}

#[tokio::test]
async fn test_app_error_unsupported_scheme_response() {
    let error = AppError::unsupported_scheme("ftp");
    let response = error.into_response();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body();
    let bytes = body.collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(json["error"]["type"], "unsupported_scheme");
    assert!(json["error"]["message"].as_str().unwrap().contains("ftp"));
}

#[test]
fn test_invalid_source_display() {
    let error = AppError::invalid_source("bad-input");
    let display = format!("{}", error);
    assert!(display.contains("Invalid source"));
    assert!(display.contains("bad-input"));
}

#[test]
fn test_unsupported_scheme_display() {
    let error = AppError::unsupported_scheme("ftp");
    let display = format!("{}", error);
    assert!(display.contains("Unsupported scheme"));
    assert!(display.contains("ftp"));
}

#[tokio::test]
async fn test_app_error_conflict_response() {
    let error = AppError::conflict("Definition with ID 'x' already exists");
    let response = error.into_response();

    assert_eq!(response.status(), StatusCode::CONFLICT);

    let body = response.into_body();
    let bytes = body.collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(json["error"]["type"], "conflict");
    assert!(json["error"]["message"]
        .as_str()
        .unwrap()
        .contains("already exists"));
}

#[tokio::test]
async fn test_app_error_database_response_hides_details() {
    let diesel_error = diesel::result::Error::DatabaseError(
        diesel::result::DatabaseErrorKind::UniqueViolation,
        Box::new("duplicate key violates unique constraint".to_string()),
    );
    let error = AppError::from(diesel_error);
    let response = error.into_response();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let body = response.into_body();
    let bytes = body.collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(json["error"]["type"], "database_error");
    assert_eq!(json["error"]["message"], "A database error occurred");
    assert!(!json["error"]["message"]
        .as_str()
        .unwrap()
        .contains("duplicate key"));
}

#[tokio::test]
async fn test_app_error_pool_response_hides_details() {
    let manager = diesel::r2d2::ConnectionManager::<diesel::PgConnection>::new(
        "postgres://invalid:invalid@192.0.2.1:5432/invalid",
    );
    let pool = diesel::r2d2::Pool::builder()
        .max_size(1)
        .connection_timeout(std::time::Duration::from_millis(50))
        .build_unchecked(manager);

    let pool_err = match pool.get() {
        Err(e) => e,
        Ok(_) => panic!("expected pool error"),
    };
    let error = AppError::Pool(pool_err);

    let display = format!("{}", error);
    assert!(display.contains("Connection pool error"));

    let response = error.into_response();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let body = response.into_body();
    let bytes = body.collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(json["error"]["type"], "pool_error");
    assert_eq!(json["error"]["message"], "Database connection error");
}

#[test]
fn test_from_anyhow_error() {
    let anyhow_err = anyhow::anyhow!("something went wrong");
    let app_error = AppError::from(anyhow_err);

    match app_error {
        AppError::Internal(err) => {
            assert!(err.to_string().contains("something went wrong"));
        }
        _ => panic!("Expected Internal variant"),
    }
}

#[test]
fn test_from_validation_errors() {
    let test = TestStruct {
        name: "ab".to_string(),
        age: 15,
    };
    let validation_errors = test.validate().unwrap_err();
    let app_error = AppError::from(validation_errors);

    match app_error {
        AppError::Validation(_) => {}
        _ => panic!("Expected Validation variant"),
    }
}

#[test]
fn test_conflict_display() {
    let error = AppError::conflict("duplicate item");
    let display = format!("{}", error);
    assert!(display.contains("Conflict"));
    assert!(display.contains("duplicate item"));
}

#[test]
fn test_not_found_display() {
    let error = AppError::not_found("missing item");
    let display = format!("{}", error);
    assert!(display.contains("Not found"));
    assert!(display.contains("missing item"));
}

#[test]
fn test_bad_request_display() {
    let error = AppError::bad_request("bad input");
    let display = format!("{}", error);
    assert!(display.contains("Bad request"));
    assert!(display.contains("bad input"));
}

#[test]
fn test_internal_display() {
    let error = AppError::internal(anyhow::anyhow!("boom"));
    let display = format!("{}", error);
    assert!(display.contains("Internal error"));
    assert!(display.contains("boom"));
}

#[test]
fn test_from_service_error_invalid_changes_maps_to_bad_request() {
    let err: anyhow::Error =
        crate::services::ServiceError::InvalidChanges("Configuration changes are invalid".into())
            .into();
    let app_error = AppError::from_service_error(err);

    match app_error {
        AppError::BadRequest(msg) => {
            assert!(msg.contains("Configuration changes are invalid"));
        }
        _ => panic!("Expected BadRequest variant, got {:?}", app_error),
    }
}

#[test]
fn test_from_service_error_patch_failed_maps_to_bad_request() {
    let source = anyhow::anyhow!("path '/missing' does not exist");
    let err: anyhow::Error =
        crate::services::ServiceError::PatchFailed { source }.into();
    let app_error = AppError::from_service_error(err);

    match app_error {
        AppError::BadRequest(msg) => {
            assert!(msg.contains("Failed to apply JSON patch"));
        }
        _ => panic!("Expected BadRequest variant, got {:?}", app_error),
    }
}

#[test]
fn test_from_service_error_other_anyhow_maps_to_internal() {
    let err = anyhow::anyhow!("unexpected S3 failure");
    let app_error = AppError::from_service_error(err);

    match app_error {
        AppError::Internal(inner) => {
            assert!(inner.to_string().contains("unexpected S3 failure"));
        }
        _ => panic!("Expected Internal variant, got {:?}", app_error),
    }
}
