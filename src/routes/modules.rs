use crate::{errors, models, services, AppState};
use anyhow::anyhow;
use axum::{extract, http, routing, Json, Router};
use serde::Deserialize;
use tracing::warn;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct InstallModuleRequest {
    #[validate(url)]
    pub source: String,
}

pub async fn list_modules(
    extract::State(state): extract::State<AppState>,
    extract::Query(filter): extract::Query<services::modules::ModuleFilter>,
) -> Result<Json<Vec<models::modules::Module>>, errors::AppError> {
    let mut conn = state.db_pool.get()?;
    let modules =
        tokio::task::spawn_blocking(move || services::modules::list_modules(&mut conn, &filter))
            .await??;
    Ok(Json(modules))
}

pub async fn create_module(
    extract::State(state): extract::State<AppState>,
    Json(payload): Json<services::modules::ModulePayload>,
) -> Result<(http::StatusCode, Json<models::modules::Module>), errors::AppError> {
    let db_pool = state.db_pool.clone();
    let http_client = state.http_client.clone();
    let s3_client = state.s3_client.clone();
    let module =
        services::modules::create_module(&mut db_pool.get()?, &http_client, &s3_client, &payload)
            .await?;
    Ok((http::StatusCode::CREATED, Json(module)))
}

pub async fn install_module(
    extract::State(state): extract::State<AppState>,
    Json(request): Json<InstallModuleRequest>,
) -> Result<(http::StatusCode, Json<models::modules::Module>), errors::AppError> {
    request.validate()?;
    let db_pool = state.db_pool.clone();
    let http_client = state.http_client.clone();
    let s3_client = state.s3_client.clone();
    let module = services::modules::create_module_from_registry(
        &mut db_pool.get()?,
        &http_client,
        &s3_client,
        &request.source,
    )
    .await?;
    Ok((http::StatusCode::CREATED, Json(module)))
}

pub async fn upgrade_module(
    extract::State(state): extract::State<AppState>,
    extract::Path(id): extract::Path<String>,
) -> Result<Json<models::modules::Module>, errors::AppError> {
    let db_pool = state.db_pool.clone();
    let http_client = state.http_client.clone();
    let s3_client = state.s3_client.clone();
    let module = services::modules::update_module_from_source(
        &mut db_pool.get()?,
        &http_client,
        &s3_client,
        &id,
    )
    .await?;
    Ok(Json(module))
}

pub async fn get_module(
    extract::State(state): extract::State<AppState>,
    extract::Path(id): extract::Path<String>,
) -> Result<Json<models::modules::Module>, errors::AppError> {
    let mut conn = state.db_pool.get()?;
    let module = tokio::task::spawn_blocking(move || services::modules::get_module(&mut conn, &id))
        .await??;
    Ok(Json(module))
}

pub async fn delete_module(
    extract::State(state): extract::State<AppState>,
    extract::Path(id): extract::Path<String>,
) -> Result<http::StatusCode, errors::AppError> {
    let mut conn = state.db_pool.get()?;
    let s3_client = state.s3_client.clone();
    let rows_deleted = services::modules::delete_module(&mut conn, &s3_client, &id).await?;
    if rows_deleted == 0 {
        return Err(errors::AppError::not_found(format!(
            "Module with id '{}' not found",
            id
        )));
    }
    let config_result = services::configuration::delete_configuration(
        &s3_client,
        services::configuration::ConfigurationTarget::Module,
        &id,
    )
    .await;
    let secrets_result = services::secrets::delete_secrets(
        &s3_client,
        services::secrets::SecretsTarget::Module,
        &id,
    )
    .await;
    match (config_result, secrets_result) {
        (Ok(()), Ok(())) => Ok(http::StatusCode::NO_CONTENT),
        (Err(e), Ok(())) => Err(anyhow!(
            "Module '{}' was deleted but its configuration could not be removed from S3: {}. Orphaned configuration objects may remain in the '{}/' prefix.",
            id, e, id
        )
        .into()),
        (Ok(()), Err(e)) => Err(anyhow!(
            "Module '{}' was deleted but its secrets could not be removed from S3: {}. Orphaned secrets objects may remain in the '{}/' prefix.",
            id, e, id
        )
        .into()),
        (Err(config_err), Err(secrets_err)) => {
            warn!(
                module_id = %id,
                config_error = %config_err,
                secrets_error = %secrets_err,
                "Module '{}' was deleted but both configuration and secrets cleanup failed. Orphaned objects may remain in S3 under the '{}/' prefix.",
                id, id
            );
            Err(anyhow!(
                "Module '{}' was deleted but S3 cleanup failed for both configuration ({}) and secrets ({}). Orphaned objects may remain in the '{}/' prefix.",
                id, config_err, secrets_err, id
            )
            .into())
        }
    }
}

pub async fn update_module(
    extract::State(state): extract::State<AppState>,
    extract::Path(id): extract::Path<String>,
    Json(request): Json<models::modules::UpdateModuleRequest>,
) -> Result<Json<models::modules::Module>, errors::AppError> {
    request.validate()?;
    let update = request.into_changeset();
    let mut conn = state.db_pool.get()?;
    let module = tokio::task::spawn_blocking(move || {
        services::modules::update_module(&mut conn, &id, &update)
    })
    .await??;
    Ok(Json(module))
}

pub fn create_route() -> Router<AppState> {
    Router::new()
        .route("/modules", routing::get(list_modules))
        .route("/modules", routing::post(create_module))
        .route("/modules/install", routing::post(install_module))
        .route("/modules/:id", routing::get(get_module))
        .route("/modules/:id", routing::patch(update_module))
        .route("/modules/:id", routing::delete(delete_module))
        .route("/modules/:id/update", routing::post(upgrade_module))
}

pub fn create_route_v1() -> Router<AppState> {
    create_route()
}
