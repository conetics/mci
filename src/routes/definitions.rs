use crate::routes::common::{spawn_cleanup_task, InstallRequest};
use crate::services::ResourceKind;
use crate::{errors, models, services, AppState};
use axum::{extract, http, routing, Json, Router};
use validator::Validate;

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
    match services::definitions::create_definition(
        &db_pool,
        &http_client,
        &s3_client,
        &payload,
    )
    .await
    {
        Ok(definition) => Ok((http::StatusCode::CREATED, Json(definition))),
        Err(e) => Err(errors::AppError::from_service_error(e)),
    }
}

pub async fn install_definition(
    extract::State(state): extract::State<AppState>,
    Json(request): Json<InstallRequest>,
) -> Result<(http::StatusCode, Json<models::definitions::Definition>), errors::AppError> {
    request.validate()?;
    let db_pool = state.db_pool.clone();
    let http_client = state.http_client.clone();
    let s3_client = state.s3_client.clone();
    let definition = services::definitions::create_definition_from_registry(
        &db_pool,
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
        &db_pool,
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
    let db_pool = state.db_pool.clone();
    let s3_client = state.s3_client.clone();

    let rows_deleted =
        services::definitions::delete_definition(&db_pool, &s3_client, &id)
            .await
            .map_err(errors::AppError::from_service_error)?;
    if rows_deleted == 0 {
        return Err(errors::AppError::not_found(format!(
            "Definition with id '{}' not found",
            id
        )));
    }

    spawn_cleanup_task(s3_client, id, ResourceKind::Definition);
    Ok(http::StatusCode::NO_CONTENT)
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

pub fn create_route_v1() -> Router<AppState> {
    Router::new()
        .route("/definitions", routing::get(list_definitions))
        .route("/definitions", routing::post(create_definition))
        .route("/definitions/install", routing::post(install_definition))
        .route("/definitions/{id}", routing::get(get_definition))
        .route("/definitions/{id}", routing::patch(update_definition))
        .route("/definitions/{id}", routing::delete(delete_definition))
        .route(
            "/definitions/{id}/update",
            routing::post(upgrade_definition),
        )
}
