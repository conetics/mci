use crate::{api::handlers, AppState};
use axum::{
    routing::{delete, get, put},
    Router,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/definitions", get(handlers::list_definitions))
        // .route("/definitions", post(handlers::create_definition))
        .route("/definitions/{id}", get(handlers::get_definition))
        .route("/definitions/{id}", put(handlers::update_definition))
        .route("/definitions/{id}", delete(handlers::delete_definition))
}
