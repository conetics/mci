use crate::{api::handlers, AppState};
use axum::{
    routing::{delete, get, patch, post, put},
    Router,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/definitions", get(handlers::list_definitions))
        .route("/definitions", post(handlers::create_definition))
        .route("/definitions/install", post(handlers::install_definition))
        .route("/definitions/{id}", get(handlers::get_definition))
        .route("/definitions/{id}", patch(handlers::update_definition))
        .route("/definitions/{id}", delete(handlers::delete_definition))
        .route(
            "/definitions/{id}/update",
            post(handlers::upgrade_definition),
        )
        .route(
            "/definitions/{id}/secrets",
            patch(handlers::patch_definition_secrets),
        )
        .route(
            "/definitions/{id}/secrets/schema",
            get(handlers::get_definition_secrets_schema),
        )
        .route(
            "/definitions/{id}/configuration",
            get(handlers::get_definition_configuration),
        )
        .route(
            "/definitions/{id}/configuration",
            put(handlers::put_definition_configuration),
        )
        .route(
            "/definitions/{id}/configuration",
            patch(handlers::patch_definition_configuration),
        )
        .route(
            "/definitions/{id}/configuration/schema",
            get(handlers::get_definition_configuration_schema),
        )
        .route("/modules", get(handlers::list_modules))
        .route("/modules", post(handlers::create_module))
        .route("/modules/install", post(handlers::install_module))
        .route("/modules/{id}", get(handlers::get_module))
        .route("/modules/{id}", patch(handlers::update_module))
        .route("/modules/{id}", delete(handlers::delete_module))
        .route("/modules/{id}/update", post(handlers::upgrade_module))
        .route(
            "/modules/{id}/secrets",
            patch(handlers::patch_module_secrets),
        )
        .route(
            "/modules/{id}/secrets/schema",
            get(handlers::get_module_secrets_schema),
        )
        .route(
            "/modules/{id}/configuration",
            get(handlers::get_module_configuration),
        )
        .route(
            "/modules/{id}/configuration",
            put(handlers::put_module_configuration),
        )
        .route(
            "/modules/{id}/configuration",
            patch(handlers::patch_module_configuration),
        )
        .route(
            "/modules/{id}/configuration/schema",
            get(handlers::get_module_configuration_schema),
        )
}
