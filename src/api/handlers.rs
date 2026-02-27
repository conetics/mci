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
use tracing::warn;
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

/// Deletes a definition by id and removes its associated configuration and secrets.
///
/// Deletes the definition record from the database and, on success, deletes the definition's
/// configuration and secrets stored in S3. Returns `StatusCode::NO_CONTENT` when deletion
/// completes successfully; returns an `AppError::not_found` if no definition with the given id exists.
///
/// # Returns
///
/// `StatusCode::NO_CONTENT` on success; an `AppError` on failure (for example, `not_found` if the
/// definition does not exist).
///
/// # Examples
///
/// ```
/// use axum::http::StatusCode;
///
/// // Handler returns NO_CONTENT on successful deletion.
/// let status = StatusCode::NO_CONTENT;
/// assert_eq!(status, StatusCode::NO_CONTENT);
/// ```
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

    let config_result = configuration_services::delete_configuration(
        &state.s3_client,
        ConfigurationTarget::Definition,
        &id,
    )
    .await;

    let secrets_result =
        secrets_services::delete_secrets(&state.s3_client, SecretsTarget::Definition, &id).await;

    match (config_result, secrets_result) {
        (Ok(()), Ok(())) => Ok(StatusCode::NO_CONTENT),
        (Err(e), Ok(())) => Err(anyhow::anyhow!(
            "Definition '{}' was deleted but its configuration could not be removed from S3: {}. \
             Orphaned configuration objects may remain in the '{}/' prefix.",
            id, e, id
        ).into()),
        (Ok(()), Err(e)) => Err(anyhow::anyhow!(
            "Definition '{}' was deleted but its secrets could not be removed from S3: {}. \
             Orphaned secrets objects may remain in the '{}/' prefix.",
            id, e, id
        ).into()),
        (Err(config_err), Err(secrets_err)) => {
            warn!(
                definition_id = %id,
                config_error = %config_err,
                secrets_error = %secrets_err,
                "Definition '{}' was deleted but both configuration and secrets \
                 cleanup failed. Orphaned objects may remain in S3 under the '{}/' prefix.",
                id, id
            );
            Err(anyhow::anyhow!(
                "Definition '{}' was deleted but S3 cleanup failed for both configuration ({}) \
                 and secrets ({}). Orphaned objects may remain in the '{}/' prefix.",
                id, config_err, secrets_err, id
            ).into())
        }
    }
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

/// Deletes a module and its associated configuration and secrets.
///
/// Attempts to remove the module record from the database and, on success,
/// deletes the module's stored configuration and secrets from S3. If no
/// module with the given id exists, an `AppError::not_found` is returned.
///
/// # Returns
///
/// `StatusCode::NO_CONTENT` on success.
///
/// # Errors
///
/// Returns `AppError::not_found` if a module with the provided id does not exist.
/// Other `AppError` variants may be returned for database, S3, or service failures.
///
/// # Examples
///
///
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

    let config_result = configuration_services::delete_configuration(
        &state.s3_client,
        ConfigurationTarget::Module,
        &id,
    )
    .await;

    let secrets_result =
        secrets_services::delete_secrets(&state.s3_client, SecretsTarget::Module, &id).await;

    match (config_result, secrets_result) {
        (Ok(()), Ok(())) => Ok(StatusCode::NO_CONTENT),
        (Err(e), Ok(())) => Err(anyhow::anyhow!(
            "Module '{}' was deleted but its configuration could not be removed from S3: {}. \
             Orphaned configuration objects may remain in the '{}/' prefix.",
            id, e, id
        ).into()),
        (Ok(()), Err(e)) => Err(anyhow::anyhow!(
            "Module '{}' was deleted but its secrets could not be removed from S3: {}. \
             Orphaned secrets objects may remain in the '{}/' prefix.",
            id, e, id
        ).into()),
        (Err(config_err), Err(secrets_err)) => {
            warn!(
                module_id = %id,
                config_error = %config_err,
                secrets_error = %secrets_err,
                "Module '{}' was deleted but both configuration and secrets \
                 cleanup failed. Orphaned objects may remain in S3 under the '{}/' prefix.",
                id, id
            );
            Err(anyhow::anyhow!(
                "Module '{}' was deleted but S3 cleanup failed for both configuration ({}) \
                 and secrets ({}). Orphaned objects may remain in the '{}/' prefix.",
                id, config_err, secrets_err, id
            ).into())
        }
    }
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
    .await
    .map_err(AppError::from_service_error)?;

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
    .await
    .map_err(AppError::from_service_error)?;

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
    .await
    .map_err(AppError::from_service_error)?;

    Ok(StatusCode::NO_CONTENT)
}

/// Applies a JSON Patch to a module's stored configuration and returns the resulting configuration.
///
/// The request body must be a JSON Patch (an array of JSON Patch operations). The handler validates
/// and parses the patch, applies it to the module configuration stored via the configuration service,
/// and returns the patched configuration as JSON.
///
/// # Returns
///
/// The patched configuration as JSON.
///
/// # Examples
///
/// ```
/// use serde_json::json;
/// use json_patch::Patch;
///
/// // Example JSON Patch that replaces /name
/// let patch_value = json!([ { "op": "replace", "path": "/name", "value": "new-name" } ]);
/// let operations: Patch = serde_json::from_value(patch_value).expect("valid patch");
/// assert_eq!(operations.0.len(), 1);
/// ```
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
    .await
    .map_err(AppError::from_service_error)?;

    Ok(Json(patched))
}

/// Fetches the secrets JSON schema for a definition by id.
///
/// Returns the secrets schema as a JSON value suitable for validation or inspection.
///
/// # Examples
///
/// ```no_run
/// use axum::extract::{State, Path};
/// use serde_json::json;
/// use mci::api::handlers::get_definition_secrets_schema;
/// // Assume `state` is an initialized AppState and `id` is the definition id.
/// // let response = get_definition_secrets_schema(State(state), Path(id.to_string())).await;
/// ```
pub async fn get_definition_secrets_schema(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<JsonValue>, AppError> {
    let schema =
        secrets_services::get_schema(&state.s3_client, SecretsTarget::Definition, &id).await?;

    Ok(Json(schema))
}

/// Applies a JSON Patch to a definition's secrets.
///
/// The request body is parsed as a `json_patch::Patch` and applied to the secrets for the definition
/// identified by `id` using the application's secrets service and optional KMS key. Returns
/// `StatusCode::NO_CONTENT` on success.
///
/// # Examples
///
/// ```
/// use serde_json::json;
/// use json_patch::Patch;
///
/// // Example JSON Patch body to add a secret value
/// let body = json!([ { "op": "add", "path": "/apiKey", "value": "new-key" } ]);
/// let patch: Patch = serde_json::from_value(body).unwrap();
/// // `patch` can then be passed to the secrets service or handler for application.
/// ```
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
    .await
    .map_err(AppError::from_service_error)?;

    Ok(StatusCode::NO_CONTENT)
}

/// Fetches the secrets JSON schema for the specified module.
///
/// # Parameters
///
/// - `id`: The module identifier to retrieve the secrets schema for.
///
/// # Returns
///
/// A JSON value containing the secrets schema for the module.
///
/// # Examples
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // `state` and `id` would be provided by the application context in real usage.
/// // let result = get_module_secrets_schema(State(state), Path(id)).await?;
/// # Ok(())
/// # }
/// ```
pub async fn get_module_secrets_schema(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<JsonValue>, AppError> {
    let schema = secrets_services::get_schema(&state.s3_client, SecretsTarget::Module, &id).await?;

    Ok(Json(schema))
}

/// Applies a JSON Patch to the secrets for the specified module.
///
/// Parses the request body as a `json_patch::Patch` and forwards the patch to the secrets service for the module identified by `id`.
///
/// # Returns
///
/// `StatusCode::NO_CONTENT` on success.
///
/// # Examples
///
/// ```
/// use serde_json::json;
/// use json_patch::Patch;
///
/// // Example JSON Patch that replaces "/foo" with "bar"
/// let patch_value = json!([ { "op": "replace", "path": "/foo", "value": "bar" } ]);
/// let operations: Patch = serde_json::from_value(patch_value).unwrap();
/// assert_eq!(operations.0.len(), 1);
/// ```
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
    .await
    .map_err(AppError::from_service_error)?;

    Ok(StatusCode::NO_CONTENT)
}
