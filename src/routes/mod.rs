use crate::state::AppState;
use axum::Router;

pub mod common;
pub mod configuration;
pub mod definitions;
pub mod modules;
pub mod secrets;

pub fn all_routes() -> Router<AppState> {
    let v1_routes = Router::new()
        .merge(definitions::create_route_v1())
        .merge(modules::create_route_v1())
        .merge(configuration::create_route_v1())
        .merge(secrets::create_route_v1());

    Router::new()
        .merge(v1_routes.clone())
        .nest("/v1", v1_routes)
}
