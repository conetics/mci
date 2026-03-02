use crate::{errors, models, services, AppState};
use anyhow::anyhow;
use axum::{extract, http, routing, Json, Router};
use serde::Deserialize;
use tracing::warn;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct InstallDefinitionRequest {
    #[validate(url)]
    pub source: String,
}

pub async fn list_definitions(
    extract::State(state): extract::State<AppState>,
    extract::Query(filter): extract::Query<services::definitions::DefinitionFilter>,
) -> Result<Json<Vec<models::definitions::Definition>>, errors::AppError> {
    let mut conn = state.db_pool.get()?;
    let definitions = tokio::task::spawn_blocking(move || {
        services::definitions::list_definitions(&mut conn, &filter)
    })
    .await??;
    Ok(Json(definitions))
}

pub async fn create_definition(
    extract::State(state): extract::State<AppState>,
    Json(payload): Json<services::definitions::DefinitionPayload>,
) -> Result<(http::StatusCode, Json<models::definitions::Definition>), errors::AppError> {
    let db_pool = state.db_pool.clone();
    let http_client = state.http_client.clone();
    let s3_client = state.s3_client.clone();
    let definition = services::definitions::create_definition(
        &mut db_pool.get()?,
        &http_client,
        &s3_client,
        &payload,
    )
    .await?;
    Ok((http::StatusCode::CREATED, Json(definition)))
}

pub async fn install_definition(
    extract::State(state): extract::State<AppState>,
    Json(request): Json<InstallDefinitionRequest>,
) -> Result<(http::StatusCode, Json<models::definitions::Definition>), errors::AppError> {
    request.validate()?;
    let db_pool = state.db_pool.clone();
    let http_client = state.http_client.clone();
    let s3_client = state.s3_client.clone();
    let definition = services::definitions::create_definition_from_registry(
        &mut db_pool.get()?,
        &http_client,
        &s3_client,
        &request.source,
    )
    .await?;
    Ok((http::StatusCode::CREATED, Json(definition)))
}

pub async fn upgrade_definition(
    extract::State(state): extract::State<AppState>,
    extract::Path(id): extract::Path<String>,
) -> Result<Json<models::definitions::Definition>, errors::AppError> {
    let db_pool = state.db_pool.clone();
    let http_client = state.http_client.clone();
    let s3_client = state.s3_client.clone();
    let definition = services::definitions::update_definition_from_source(
        &mut db_pool.get()?,
        &http_client,
        &s3_client,
        &id,
    )
    .await?;
    Ok(Json(definition))
}

pub async fn get_definition(
    extract::State(state): extract::State<AppState>,
    extract::Path(id): extract::Path<String>,
) -> Result<Json<models::definitions::Definition>, errors::AppError> {
    let mut conn = state.db_pool.get()?;
    let definition =
        tokio::task::spawn_blocking(move || services::definitions::get_definition(&mut conn, &id))
            .await??;
    Ok(Json(definition))
}

pub async fn delete_definition(
    extract::State(state): extract::State<AppState>,
    extract::Path(id): extract::Path<String>,
) -> Result<http::StatusCode, errors::AppError> {
    let mut conn = state.db_pool.get()?;
    let s3_client = state.s3_client.clone();
    let rows_deleted = services::definitions::delete_definition(&mut conn, &s3_client, &id).await?;
    if rows_deleted == 0 {
        return Err(errors::AppError::not_found(format!(
            "Definition with id '{}' not found",
            id
        )));
    }
    let config_result = services::configuration::delete_configuration(
        &s3_client,
        services::configuration::ConfigurationTarget::Definition,
        &id,
    )
    .await;
    let secrets_result = services::secrets::delete_secrets(
        &s3_client,
        services::secrets::SecretsTarget::Definition,
        &id,
    )
    .await;
    match (config_result, secrets_result) {
        (Ok(()), Ok(())) => Ok(http::StatusCode::NO_CONTENT),
        (Err(e), Ok(())) => Err(anyhow!(
            "Definition '{}' was deleted but its configuration could not be removed from S3: {}. Orphaned configuration objects may remain in the '{}/' prefix.",
            id, e, id
        )
        .into()),
        (Ok(()), Err(e)) => Err(anyhow!(
            "Definition '{}' was deleted but its secrets could not be removed from S3: {}. Orphaned secrets objects may remain in the '{}/' prefix.",
            id, e, id
        )
        .into()),
        (Err(config_err), Err(secrets_err)) => {
            warn!(
                definition_id = %id,
                config_error = %config_err,
                secrets_error = %secrets_err,
                "Definition '{}' was deleted but both configuration and secrets cleanup failed. Orphaned objects may remain in S3 under the '{}/' prefix.",
                id, id
            );
            Err(anyhow!(
                "Definition '{}' was deleted but S3 cleanup failed for both configuration ({}) and secrets ({}). Orphaned objects may remain in the '{}/' prefix.",
                id, config_err, secrets_err, id
            )
            .into())
        }
    }
}

pub async fn update_definition(
    extract::State(state): extract::State<AppState>,
    extract::Path(id): extract::Path<String>,
    Json(request): Json<models::definitions::UpdateDefinitionRequest>,
) -> Result<Json<models::definitions::Definition>, errors::AppError> {
    request.validate()?;
    let update = request.into_changeset();
    let mut conn = state.db_pool.get()?;
    let definition = tokio::task::spawn_blocking(move || {
        services::definitions::update_definition(&mut conn, &id, &update)
    })
    .await??;
    Ok(Json(definition))
}

pub fn create_route() -> Router<AppState> {
    Router::new()
        .route("/definitions", routing::get(list_definitions))
        .route("/definitions", routing::post(create_definition))
        .route("/definitions/install", routing::post(install_definition))
        .route("/definitions/:id", routing::get(get_definition))
        .route("/definitions/:id", routing::patch(update_definition))
        .route("/definitions/:id", routing::delete(delete_definition))
        .route("/definitions/:id/update", routing::post(upgrade_definition))
}

pub fn create_route_v1() -> Router<AppState> {
    create_route()
}
