use crate::{
    errors::AppError,
    models::{Definition, Module, UpdateDefinitionRequest, UpdateModuleRequest},
    services::{
        configuration_services::{self, ConfigurationTarget},
        definitions_services::{self, DefinitionFilter, DefinitionPayload},
        modules_services::{self, ModuleFilter, ModulePayload},
        secrets_services::{self, SecretsTarget},
    },
    AppState,
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct InstallDefinitionRequest {
    #[validate(url)]
    pub source: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct InstallModuleRequest {
    #[validate(url)]
    pub source: String,
}

pub async fn list_definitions(
    State(state): State<AppState>,
    Query(filter): Query<DefinitionFilter>,
) -> Result<Json<Vec<Definition>>, AppError> {
    let mut conn = state.db_pool.get()?;

    let definitions = tokio::task::spawn_blocking(move || {
        definitions_services::list_definitions(&mut conn, &filter)
    })
    .await??;

    Ok(Json(definitions))
}

pub async fn create_definition(
    State(state): State<AppState>,
    Json(payload): Json<DefinitionPayload>,
) -> Result<(StatusCode, Json<Definition>), AppError> {
    let db_pool = state.db_pool.clone();
    let http_client = state.http_client.clone();
    let s3_client = state.s3_client.clone();

    let definition = definitions_services::create_definition(
        &mut db_pool.get()?,
        &http_client,
        &s3_client,
        &payload,
    )
    .await?;

    Ok((StatusCode::CREATED, Json(definition)))
}

pub async fn get_definition(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Definition>, AppError> {
    let mut conn = state.db_pool.get()?;

    let definition =
        tokio::task::spawn_blocking(move || definitions_services::get_definition(&mut conn, &id))
            .await??;

    Ok(Json(definition))
}

pub async fn delete_definition(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let mut conn = state.db_pool.get()?;
    let s3_client = state.s3_client.clone();
    let rows_deleted = definitions_services::delete_definition(&mut conn, &s3_client, &id).await?;

    if rows_deleted == 0 {
        return Err(AppError::not_found(format!(
            "Definition with id '{}' not found",
            id
        )));
    }

    configuration_services::delete_configuration(
        &state.s3_client,
        ConfigurationTarget::Definition,
        &id,
    )
    .await
    .ok();

    secrets_services::delete_secrets(&state.s3_client, SecretsTarget::Definition, &id).await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn update_definition(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<UpdateDefinitionRequest>,
) -> Result<Json<Definition>, AppError> {
    request.validate()?;
    let update = request.into_changeset();
    let mut conn = state.db_pool.get()?;

    let definition = tokio::task::spawn_blocking(move || {
        definitions_services::update_definition(&mut conn, &id, &update)
    })
    .await??;

    Ok(Json(definition))
}

pub async fn install_definition(
    State(state): State<AppState>,
    Json(request): Json<InstallDefinitionRequest>,
) -> Result<(StatusCode, Json<Definition>), AppError> {
    request.validate()?;

    let db_pool = state.db_pool.clone();
    let http_client = state.http_client.clone();
    let s3_client = state.s3_client.clone();

    let definition = definitions_services::create_definition_from_registry(
        &mut db_pool.get()?,
        &http_client,
        &s3_client,
        &request.source,
    )
    .await?;

    Ok((StatusCode::CREATED, Json(definition)))
}

pub async fn upgrade_definition(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Definition>, AppError> {
    let db_pool = state.db_pool.clone();
    let http_client = state.http_client.clone();
    let s3_client = state.s3_client.clone();

    let definition = definitions_services::update_definition_from_source(
        &mut db_pool.get()?,
        &http_client,
        &s3_client,
        &id,
    )
    .await?;

    Ok(Json(definition))
}

pub async fn list_modules(
    State(state): State<AppState>,
    Query(filter): Query<ModuleFilter>,
) -> Result<Json<Vec<Module>>, AppError> {
    let mut conn = state.db_pool.get()?;

    let modules =
        tokio::task::spawn_blocking(move || modules_services::list_modules(&mut conn, &filter))
            .await??;

    Ok(Json(modules))
}

pub async fn create_module(
    State(state): State<AppState>,
    Json(payload): Json<ModulePayload>,
) -> Result<(StatusCode, Json<Module>), AppError> {
    let db_pool = state.db_pool.clone();
    let http_client = state.http_client.clone();
    let s3_client = state.s3_client.clone();

    let module =
        modules_services::create_module(&mut db_pool.get()?, &http_client, &s3_client, &payload)
            .await?;

    Ok((StatusCode::CREATED, Json(module)))
}

pub async fn get_module(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Module>, AppError> {
    let mut conn = state.db_pool.get()?;

    let module =
        tokio::task::spawn_blocking(move || modules_services::get_module(&mut conn, &id)).await??;

    Ok(Json(module))
}

pub async fn delete_module(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let mut conn = state.db_pool.get()?;
    let s3_client = state.s3_client.clone();
    let rows_deleted = modules_services::delete_module(&mut conn, &s3_client, &id).await?;

    if rows_deleted == 0 {
        return Err(AppError::not_found(format!(
            "Module with id '{}' not found",
            id
        )));
    }

    configuration_services::delete_configuration(
        &state.s3_client,
        ConfigurationTarget::Module,
        &id,
    )
    .await
    .ok();

    secrets_services::delete_secrets(&state.s3_client, SecretsTarget::Module, &id).await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn update_module(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<UpdateModuleRequest>,
) -> Result<Json<Module>, AppError> {
    request.validate()?;
    let update = request.into_changeset();
    let mut conn = state.db_pool.get()?;

    let module = tokio::task::spawn_blocking(move || {
        modules_services::update_module(&mut conn, &id, &update)
    })
    .await??;

    Ok(Json(module))
}

pub async fn install_module(
    State(state): State<AppState>,
    Json(request): Json<InstallModuleRequest>,
) -> Result<(StatusCode, Json<Module>), AppError> {
    request.validate()?;

    let db_pool = state.db_pool.clone();
    let http_client = state.http_client.clone();
    let s3_client = state.s3_client.clone();

    let module = modules_services::create_module_from_registry(
        &mut db_pool.get()?,
        &http_client,
        &s3_client,
        &request.source,
    )
    .await?;

    Ok((StatusCode::CREATED, Json(module)))
}

pub async fn upgrade_module(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Module>, AppError> {
    let db_pool = state.db_pool.clone();
    let http_client = state.http_client.clone();
    let s3_client = state.s3_client.clone();

    let module = modules_services::update_module_from_source(
        &mut db_pool.get()?,
        &http_client,
        &s3_client,
        &id,
    )
    .await?;

    Ok(Json(module))
}

pub async fn get_definition_configuration_schema(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<JsonValue>, AppError> {
    let schema =
        configuration_services::get_schema(&state.s3_client, ConfigurationTarget::Definition, &id)
            .await?;

    Ok(Json(schema))
}

pub async fn get_definition_configuration(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<JsonValue>, AppError> {
    let config = configuration_services::get_configuration(
        &state.s3_client,
        ConfigurationTarget::Definition,
        &id,
    )
    .await?;

    let schema =
        configuration_services::get_schema(&state.s3_client, ConfigurationTarget::Definition, &id)
            .await?;

    let validation = configuration_services::validate_configuration(&schema, &config)?;

    Ok(Json(serde_json::json!({
        "configuration": config,
        "validation": validation,
    })))
}

pub async fn put_definition_configuration(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<JsonValue>,
) -> Result<StatusCode, AppError> {
    configuration_services::put_configuration(
        &state.s3_client,
        ConfigurationTarget::Definition,
        &id,
        &body,
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn patch_definition_configuration(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<JsonValue>,
) -> Result<Json<JsonValue>, AppError> {
    let operations: json_patch::Patch =
        serde_json::from_value(body).map_err(|e| AppError::bad_request(e.to_string()))?;

    let patched = configuration_services::patch_configuration(
        &state.s3_client,
        ConfigurationTarget::Definition,
        &id,
        &operations,
    )
    .await?;

    Ok(Json(patched))
}

pub async fn get_module_configuration_schema(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<JsonValue>, AppError> {
    let schema =
        configuration_services::get_schema(&state.s3_client, ConfigurationTarget::Module, &id)
            .await?;

    Ok(Json(schema))
}

pub async fn get_module_configuration(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<JsonValue>, AppError> {
    let config = configuration_services::get_configuration(
        &state.s3_client,
        ConfigurationTarget::Module,
        &id,
    )
    .await?;

    let schema =
        configuration_services::get_schema(&state.s3_client, ConfigurationTarget::Module, &id)
            .await?;

    let validation = configuration_services::validate_configuration(&schema, &config)?;

    Ok(Json(serde_json::json!({
        "configuration": config,
        "validation": validation,
    })))
}

pub async fn put_module_configuration(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<JsonValue>,
) -> Result<StatusCode, AppError> {
    configuration_services::put_configuration(
        &state.s3_client,
        ConfigurationTarget::Module,
        &id,
        &body,
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn patch_module_configuration(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<JsonValue>,
) -> Result<Json<JsonValue>, AppError> {
    let operations: json_patch::Patch =
        serde_json::from_value(body).map_err(|e| AppError::bad_request(e.to_string()))?;

    let patched = configuration_services::patch_configuration(
        &state.s3_client,
        ConfigurationTarget::Module,
        &id,
        &operations,
    )
    .await?;

    Ok(Json(patched))
}

pub async fn get_definition_secrets_schema(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<JsonValue>, AppError> {
    let schema =
        secrets_services::get_schema(&state.s3_client, SecretsTarget::Definition, &id).await?;

    Ok(Json(schema))
}

pub async fn patch_definition_secrets(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<JsonValue>,
) -> Result<StatusCode, AppError> {
    let operations: json_patch::Patch =
        serde_json::from_value(body).map_err(|e| AppError::bad_request(e.to_string()))?;

    secrets_services::patch_secrets(
        &state.s3_client,
        SecretsTarget::Definition,
        &id,
        &operations,
        state.s3_kms_key_id.as_deref(),
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_module_secrets_schema(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<JsonValue>, AppError> {
    let schema = secrets_services::get_schema(&state.s3_client, SecretsTarget::Module, &id).await?;

    Ok(Json(schema))
}

pub async fn patch_module_secrets(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<JsonValue>,
) -> Result<StatusCode, AppError> {
    let operations: json_patch::Patch =
        serde_json::from_value(body).map_err(|e| AppError::bad_request(e.to_string()))?;

    secrets_services::patch_secrets(
        &state.s3_client,
        SecretsTarget::Module,
        &id,
        &operations,
        state.s3_kms_key_id.as_deref(),
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}
