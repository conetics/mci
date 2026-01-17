use axum::Router;
use deadpool_postgres::Pool;
use tower_http::trace::TraceLayer;

pub mod api;
pub mod config;
pub mod db;
pub mod domains;
pub mod errors;

#[derive(Clone)]
pub struct AppState {
    pub db_pool: Pool,
}

pub fn app(app_state: AppState) -> Router {
    Router::new()
        .merge(api::routes::routes())
        .layer(TraceLayer::new_for_http())
        .with_state(app_state)
}
