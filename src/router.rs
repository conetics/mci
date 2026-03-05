use crate::{routes, state};
use axum::{http, Router};
use tower_http::{compression, cors, propagate_header, sensitive_headers, trace};

pub fn create_router(state: state::AppState) -> Router {
    Router::new()
        .merge(routes::all_routes())
        .layer(sensitive_headers::SetSensitiveHeadersLayer::new(
            std::iter::once(http::header::AUTHORIZATION),
        ))
        .layer(
            trace::TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().include_headers(true))
                .on_request(trace::DefaultOnRequest::new().level(tracing::Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(tracing::Level::INFO)),
        )
        .layer(compression::CompressionLayer::new())
        .layer(propagate_header::PropagateHeaderLayer::new(
            http::header::HeaderName::from_static("x-request-id"),
        ))
        .layer(if cfg!(debug_assertions) {
            cors::CorsLayer::permissive()
        } else {
            let origins: Vec<http::HeaderValue> = state
                .config
                .allowed_origins
                .as_deref()
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .filter_map(|s| s.parse().ok())
                .collect();
            cors::CorsLayer::new()
                .allow_origin(origins)
                .allow_methods([
                    http::Method::GET,
                    http::Method::POST,
                    http::Method::PUT,
                    http::Method::PATCH,
                    http::Method::DELETE,
                ])
                .allow_headers([http::header::CONTENT_TYPE, http::header::AUTHORIZATION])
                .max_age(std::time::Duration::from_secs(3600))
        })
        .with_state(state)
}
