use crate::{routes, state};
use axum::{http, Router};
use tower_http::{compression, cors, propagate_header, sensitive_headers, trace};

pub fn create_router(state: state::AppState) -> Router {
    Router::new()
        .merge(Router::new().nest("/v1", Router::new().merge(routes::all_routes())))
        .layer(
            trace::TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().include_headers(true))
                .on_request(trace::DefaultOnRequest::new().level(tracing::Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(tracing::Level::INFO)),
        )
        .layer(sensitive_headers::SetSensitiveHeadersLayer::new(
            std::iter::once(http::header::AUTHORIZATION),
        ))
        .layer(compression::CompressionLayer::new())
        .layer(propagate_header::PropagateHeaderLayer::new(
            http::header::HeaderName::from_static("x-request-id"),
        ))
        .layer(cors::CorsLayer::permissive())
        .with_state(state)
}
