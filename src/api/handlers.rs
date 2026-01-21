use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use validator::Validate;

use crate::{
    errors::AppError,
    models::{NewSpec, Spec, UpdateSpec},
    services::specs::{self as service, SpecFilter},
    AppState,
};

pub async fn get_spec(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Spec>, AppError> {
    let mut conn = state.db_pool.get()?;

    let spec = tokio::task::spawn_blocking(move || service::get_spec(&mut conn, &id)).await??;

    Ok(Json(spec))
}

pub async fn list_specs(
    State(state): State<AppState>,
    Query(filter): Query<SpecFilter>,
) -> Result<Json<Vec<Spec>>, AppError> {
    let mut conn = state.db_pool.get()?;

    let specs =
        tokio::task::spawn_blocking(move || service::list_specs(&mut conn, filter)).await??;

    Ok(Json(specs))
}

pub async fn create_spec(
    State(state): State<AppState>,
    Json(new_spec): Json<NewSpec>,
) -> Result<(StatusCode, Json<Spec>), AppError> {
    new_spec.validate()?;

    let mut conn = state.db_pool.get()?;

    let spec =
        tokio::task::spawn_blocking(move || service::create_spec(&mut conn, new_spec)).await??;

    Ok((StatusCode::CREATED, Json(spec)))
}

pub async fn update_spec(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(update): Json<UpdateSpec>,
) -> Result<Json<Spec>, AppError> {
    update.validate()?;

    let mut conn = state.db_pool.get()?;

    let spec =
        tokio::task::spawn_blocking(move || service::update_spec(&mut conn, &id, update)).await??;

    Ok(Json(spec))
}

pub async fn delete_spec(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let mut conn = state.db_pool.get()?;

    tokio::task::spawn_blocking(move || service::delete_spec(&mut conn, &id)).await??;

    Ok(StatusCode::NO_CONTENT)
}
