use crate::services::ResourceKind;
use crate::{errors, models, services, AppState};
use axum::{extract, http, routing, Json, Router};
use serde_json::Value as JsonValue;

async fn get_secrets_schema_handler(
    kind: ResourceKind,
    state: AppState,
    id: String,
) -> Result<Json<models::secrets::SecretsSchema>, errors::AppError> {
    let schema = services::secrets::get_schema(&state.s3_client, kind, &id).await?;
    Ok(Json(models::secrets::SecretsSchema::new(schema)))
}

async fn patch_secrets_handler(
    kind: ResourceKind,
    state: AppState,
    id: String,
    body: JsonValue,
) -> Result<http::StatusCode, errors::AppError> {
    let operations: json_patch::Patch =
        serde_json::from_value(body).map_err(|e| errors::AppError::bad_request(e.to_string()))?;
    services::secrets::patch_secrets(
        &state.s3_client,
        kind,
        &id,
        &operations,
        state.config.s3_kms_key_id.as_deref(),
    )
    .await
    .map_err(errors::AppError::from_service_error)?;
    Ok(http::StatusCode::NO_CONTENT)
}

pub async fn get_definition_secrets_schema(
    extract::State(state): extract::State<AppState>,
    extract::Path(id): extract::Path<String>,
) -> Result<Json<models::secrets::SecretsSchema>, errors::AppError> {
    get_secrets_schema_handler(ResourceKind::Definition, state, id).await
}

pub async fn patch_definition_secrets(
    extract::State(state): extract::State<AppState>,
    extract::Path(id): extract::Path<String>,
    Json(body): Json<JsonValue>,
) -> Result<http::StatusCode, errors::AppError> {
    patch_secrets_handler(ResourceKind::Definition, state, id, body).await
}

pub async fn get_module_secrets_schema(
    extract::State(state): extract::State<AppState>,
    extract::Path(id): extract::Path<String>,
) -> Result<Json<models::secrets::SecretsSchema>, errors::AppError> {
    get_secrets_schema_handler(ResourceKind::Module, state, id).await
}

pub async fn patch_module_secrets(
    extract::State(state): extract::State<AppState>,
    extract::Path(id): extract::Path<String>,
    Json(body): Json<JsonValue>,
) -> Result<http::StatusCode, errors::AppError> {
    patch_secrets_handler(ResourceKind::Module, state, id, body).await
}

pub fn create_route_v1() -> Router<AppState> {
    Router::new()
        .route(
            "/definitions/{id}/secrets/schema",
            routing::get(get_definition_secrets_schema),
        )
        .route(
            "/definitions/{id}/secrets",
            routing::patch(patch_definition_secrets),
        )
        .route(
            "/modules/{id}/secrets/schema",
            routing::get(get_module_secrets_schema),
        )
        .route(
            "/modules/{id}/secrets",
            routing::patch(patch_module_secrets),
        )
}
