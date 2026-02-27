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

/// Deletes a definition and removes its associated configuration and secrets from storage.
///
/// This handler removes the definition identified by `id` from the database. If the definition
/// existed, it also attempts to delete its configuration (errors ignored) and deletes its secrets
/// (errors propagated).
///
/// # Returns
///
/// `StatusCode::NO_CONTENT` on successful deletion, or an `AppError` if the definition was not
/// found or if secrets deletion fails.
///
/// # Examples
///
/// ```
/// // Example (conceptual): on success the handler returns NO_CONTENT
/// // let result = delete_definition(state, Path("def-id".to_string())).await;
/// // assert_eq!(result.unwrap(), axum::http::StatusCode::NO_CONTENT);
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

    configuration_services::delete_configuration(
        &state.s3_client,
        ConfigurationTarget::Definition,
        &id,
    )
    .await
    .ok();

    secrets_services::delete_secrets(&state.s3_client, SecretsTarget::Definition, &id)
        .await?;

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

/// Deletes a module and its associated configuration and secrets.
///
/// Removes the module record and attempts to remove its stored configuration and secrets from object storage.
///
/// # Returns
/// `StatusCode::NO_CONTENT` on success.
///
/// # Errors
/// Returns `AppError::not_found` if no module with the given id exists. Other failures propagate as `AppError`.
///
/// # Examples
///
/// ```
/// # use axum::extract::{State, Path};
/// # use axum::http::StatusCode;
/// # use crate::AppState;
/// # async fn example(state: AppState, id: String) {
/// let response = crate::api::handlers::delete_module(State(state), Path(id)).await;
/// match response {
///     Ok(StatusCode::NO_CONTENT) => (),
///     Err(e) => panic!("delete failed: {:?}", e),
/// }
/// # }
/// ```
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

    secrets_services::delete_secrets(&state.s3_client, SecretsTarget::Module, &id)
        .await?;

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

/// Apply a JSON Patch (RFC 6902) to a module's configuration and return the resulting configuration.
///
/// The request body must be a JSON Patch document; it will be parsed and applied to the module's
/// configuration stored via the configured S3 backend.
///
/// # Parameters
///
/// - `id`: Identifier of the module whose configuration will be patched.
/// - `body`: A JSON Patch (RFC 6902) document describing the modifications.
///
/// # Returns
///
/// The patched configuration as JSON.
///
/// # Errors
///
/// Returns a 400 Bad Request `AppError` if the request body is not a valid JSON Patch. Other
/// errors returned by the underlying configuration service are propagated as `AppError`.
///
/// # Examples
///
/// ```
/// use serde_json::json;
/// use json_patch::Patch;
///
/// // Construct a JSON Patch to replace the "replicas" field with 3
/// let patch_value = json!([{"op":"replace","path":"/replicas","value":3}]);
/// let patch: Patch = serde_json::from_value(patch_value).expect("valid JSON Patch");
/// assert_eq!(patch.operations().len(), 1);
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
    .await?;

    Ok(Json(patched))
}

/// Fetches the secrets schema for a definition.
///
/// Retrieves the secrets schema associated with the definition identified by `id`.
///
/// # Returns
///
/// The secrets schema as a JSON value.
///
/// # Examples
///
/// ```
/// # use axum::extract::{State, Path};
/// # use serde_json::json;
/// # use crate::api::handlers::get_definition_secrets_schema;
/// # use crate::AppState;
/// # async fn example(state: AppState) {
/// let id = "example-definition".to_string();
/// let result = get_definition_secrets_schema(State(state), Path(id)).await;
/// let schema_json = result.unwrap().0;
/// assert!(schema_json.is_object());
/// # }
/// ```
pub async fn get_definition_secrets_schema(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<JsonValue>, AppError> {
    let schema =
        secrets_services::get_schema(&state.s3_client, SecretsTarget::Definition, &id).await?;

    Ok(Json(schema))
}

/// Applies a JSON Patch to the secrets of the specified definition and persists the changes.
///
/// Parses the incoming JSON body as a `json_patch::Patch`, applies it to the definition's secrets
/// in S3 using the configured KMS key when present, and returns HTTP 204 on success.
///
/// # Examples
///
/// ```
/// let body = serde_json::json!([{
///     "op": "add",
///     "path": "/new_secret",
///     "value": "s3cr3t"
/// }]);
///
/// let patch: json_patch::Patch = serde_json::from_value(body).unwrap();
/// assert_eq!(patch.0.len(), 1);
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
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Retrieve the JSON schema for a module's secrets.
///
/// Returns the secrets schema associated with the module identified by `id`.
///
/// # Examples
///
/// ```
/// # async fn example() {
/// // Prepare an AppState with a configured S3 client and a module id.
/// let state = /* AppState */ unimplemented!();
/// let id = "module-id".to_string();
///
/// // Call the handler and inspect the result.
/// let result = get_module_secrets_schema(State(state), Path(id)).await;
/// match result {
///     Ok(Json(schema)) => { /* use schema (serde_json::Value) */ },
///     Err(_) => { /* handle error */ },
/// }
/// # }
/// ```
pub async fn get_module_secrets_schema(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<JsonValue>, AppError> {
    let schema = secrets_services::get_schema(&state.s3_client, SecretsTarget::Module, &id).await?;

    Ok(Json(schema))
}

/// Applies a JSON Patch to the secrets for a specific module.
///
/// Parses the request body as a `json_patch::Patch` and delegates to the secrets service
/// to apply the operations to the module identified by `id`. Uses the configured S3
/// client and optional KMS key from application state. Returns `StatusCode::NO_CONTENT` on success.
///
/// # Examples
///
/// ```
/// use serde_json::json;
/// use json_patch::Patch;
///
/// // Build a JSON Patch and ensure it deserializes as expected.
/// let body = json!([ { "op": "add", "path": "/new_secret", "value": "s3cr3t" } ]);
/// let patch: Patch = serde_json::from_value(body).unwrap();
/// assert_eq!(patch.0.len(), 1);
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
    .await?;

    Ok(StatusCode::NO_CONTENT)
}
