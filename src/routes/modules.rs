use crate::routes::common::{handle_delete_cleanup, InstallRequest};
use crate::services::ResourceKind;
use crate::{errors, models, services, AppState};
use axum::{extract, http, routing, Json, Router};
use validator::Validate;

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
    Json(request): Json<InstallRequest>,
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
        ResourceKind::Module,
        &id,
    )
    .await;
    let secrets_result = services::secrets::delete_secrets(
        &s3_client,
        ResourceKind::Module,
        &id,
    )
    .await;
    handle_delete_cleanup(&id, "Module", config_result, secrets_result).await
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

pub fn create_route_v1() -> Router<AppState> {
    Router::new()
        .route("/modules", routing::get(list_modules))
        .route("/modules", routing::post(create_module))
        .route("/modules/install", routing::post(install_module))
    .route("/modules/{id}", routing::get(get_module))
    .route("/modules/{id}", routing::patch(update_module))
    .route("/modules/{id}", routing::delete(delete_module))
    .route("/modules/{id}/update", routing::post(upgrade_module))
}
