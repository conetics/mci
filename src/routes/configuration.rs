use axum::{extract, http, routing, Json, Router};
use serde_json::Value as JsonValue;
use crate::{errors, models, services, AppState};

pub async fn get_definition_configuration_schema(
    extract::State(state): extract::State<AppState>,
    extract::Path(id): extract::Path<String>,
) -> Result<Json<models::configuration::ConfigurationSchema>, errors::AppError> {
    let schema = services::configuration::get_schema(
        &state.s3_client,
        services::configuration::ConfigurationTarget::Definition,
        &id,
    )
    .await?;
    Ok(Json(models::configuration::ConfigurationSchema::new(schema)))
}

pub async fn get_definition_configuration(
    extract::State(state): extract::State<AppState>,
    extract::Path(id): extract::Path<String>,
) -> Result<Json<models::configuration::ConfigurationDocument>, errors::AppError> {
    let config = services::configuration::get_configuration(
        &state.s3_client,
        services::configuration::ConfigurationTarget::Definition,
        &id,
    )
    .await?;
    let schema = services::configuration::get_schema(
        &state.s3_client,
        services::configuration::ConfigurationTarget::Definition,
        &id,
    )
    .await?;
    let validation = services::configuration::validate_configuration(&schema, &config)?;
    Ok(Json(models::configuration::ConfigurationDocument::new(config, validation)))
}

pub async fn put_definition_configuration(
    extract::State(state): extract::State<AppState>,
    extract::Path(id): extract::Path<String>,
    Json(body): Json<JsonValue>,
) -> Result<http::StatusCode, errors::AppError> {
    services::configuration::put_configuration(
        &state.s3_client,
        services::configuration::ConfigurationTarget::Definition,
        &id,
        &body,
    )
    .await
    .map_err(errors::AppError::from_service_error)?;
    Ok(http::StatusCode::NO_CONTENT)
}

pub async fn patch_definition_configuration(
    extract::State(state): extract::State<AppState>,
    extract::Path(id): extract::Path<String>,
    Json(body): Json<JsonValue>,
) -> Result<Json<JsonValue>, errors::AppError> {
    let operations: json_patch::Patch =
        serde_json::from_value(body).map_err(|e| errors::AppError::bad_request(e.to_string()))?;
    let patched = services::configuration::patch_configuration(
        &state.s3_client,
        services::configuration::ConfigurationTarget::Definition,
        &id,
        &operations,
    )
    .await
    .map_err(errors::AppError::from_service_error)?;
    Ok(Json(patched))
}

pub async fn get_module_configuration_schema(
    extract::State(state): extract::State<AppState>,
    extract::Path(id): extract::Path<String>,
) -> Result<Json<models::configuration::ConfigurationSchema>, errors::AppError> {
    let schema = services::configuration::get_schema(
        &state.s3_client,
        services::configuration::ConfigurationTarget::Module,
        &id,
    )
    .await?;
    Ok(Json(models::configuration::ConfigurationSchema::new(schema)))
}

pub async fn get_module_configuration(
    extract::State(state): extract::State<AppState>,
    extract::Path(id): extract::Path<String>,
) -> Result<Json<models::configuration::ConfigurationDocument>, errors::AppError> {
    let config = services::configuration::get_configuration(
        &state.s3_client,
        services::configuration::ConfigurationTarget::Module,
        &id,
    )
    .await?;
    let schema = services::configuration::get_schema(
        &state.s3_client,
        services::configuration::ConfigurationTarget::Module,
        &id,
    )
    .await?;
    let validation = services::configuration::validate_configuration(&schema, &config)?;
    Ok(Json(models::configuration::ConfigurationDocument::new(config, validation)))
}

pub async fn put_module_configuration(
    extract::State(state): extract::State<AppState>,
    extract::Path(id): extract::Path<String>,
    Json(body): Json<JsonValue>,
) -> Result<http::StatusCode, errors::AppError> {
    services::configuration::put_configuration(
        &state.s3_client,
        services::configuration::ConfigurationTarget::Module,
        &id,
        &body,
    )
    .await
    .map_err(errors::AppError::from_service_error)?;
    Ok(http::StatusCode::NO_CONTENT)
}

pub async fn patch_module_configuration(
    extract::State(state): extract::State<AppState>,
    extract::Path(id): extract::Path<String>,
    Json(body): Json<JsonValue>,
) -> Result<Json<JsonValue>, errors::AppError> {
    let operations: json_patch::Patch =
        serde_json::from_value(body).map_err(|e| errors::AppError::bad_request(e.to_string()))?;
    let patched = services::configuration::patch_configuration(
        &state.s3_client,
        services::configuration::ConfigurationTarget::Module,
        &id,
        &operations,
    )
    .await
    .map_err(errors::AppError::from_service_error)?;
    Ok(Json(patched))
}

pub fn create_route() -> Router<AppState> {
    Router::new()
        .route(
            "/definitions/:id/configuration/schema",
            routing::get(get_definition_configuration_schema),
        )
        .route(
            "/definitions/:id/configuration",
            routing::get(get_definition_configuration),
        )
        .route(
            "/definitions/:id/configuration",
            routing::put(put_definition_configuration),
        )
        .route(
            "/definitions/:id/configuration",
            routing::patch(patch_definition_configuration),
        )
        .route(
            "/modules/:id/configuration/schema",
            routing::get(get_module_configuration_schema),
        )
        .route("/modules/:id/configuration", routing::get(get_module_configuration))
        .route("/modules/:id/configuration", routing::put(put_module_configuration))
        .route(
            "/modules/:id/configuration",
            routing::patch(patch_module_configuration),
        )
}

pub fn create_route_v1() -> Router<AppState> {
    create_route()
}
