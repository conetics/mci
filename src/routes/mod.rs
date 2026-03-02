// src/routes/mod.rs
use crate::state::AppState;
use axum::Router;

pub mod configuration;
pub mod definitions;
pub mod modules;
pub mod secrets;

pub fn all_routes() -> Router<AppState> {
    let v1 = Router::new()
        .merge(definitions::create_route_v1())
        .merge(modules::create_route_v1())
        .merge(configuration::create_route_v1())
        .merge(secrets::create_route_v1());

    Router::new()
        .nest("/v1", v1)
        .merge(definitions::create_route())
        .merge(modules::create_route())
        .merge(configuration::create_route())
        .merge(secrets::create_route())
}
