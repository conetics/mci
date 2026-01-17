use crate::{api::handlers, AppState};
use axum::{routing::get, Router};

pub fn routes() -> Router<AppState> {
    Router::new().route("/test", get(handlers::json_message))
}
