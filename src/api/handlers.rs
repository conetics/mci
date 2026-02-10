use crate::{
    errors::AppError,
    models::{Definition, UpdateDefinition},
    services::definitions::{self as service, DefinitionFilter},
    AppState,
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use validator::Validate;

pub async fn get_definition(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Definition>, AppError> {
    let mut conn = state.db_pool.get()?;
    let definition =
        tokio::task::spawn_blocking(move || service::get_definition(&mut conn, &id)).await??;

    Ok(Json(definition))
}

pub async fn list_definitions(
    State(state): State<AppState>,
    Query(filter): Query<DefinitionFilter>,
) -> Result<Json<Vec<Definition>>, AppError> {
    let mut conn = state.db_pool.get()?;
    let definitions =
        tokio::task::spawn_blocking(move || service::list_definitions(&mut conn, filter)).await??;

    Ok(Json(definitions))
}

// pub async fn create_definition(
//     State(state): State<AppState>,
//     Json(new_definition): Json<NewDefinition>,
// ) -> Result<(StatusCode, Json<Definition>), AppError> {
//     new_definition.validate()?;
//
//     let mut conn = state.db_pool.get()?;
//     let definition =
//         tokio::task::spawn_blocking(move || service::create_definition(&mut conn, new_definition)).await??;
//
//     Ok((StatusCode::CREATED, Json(definition)))
// }

pub async fn update_definition(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(update): Json<UpdateDefinition>,
) -> Result<Json<Definition>, AppError> {
    update.validate()?;

    let mut conn = state.db_pool.get()?;
    let definition =
        tokio::task::spawn_blocking(move || service::update_definition(&mut conn, &id, update))
            .await??;

    Ok(Json(definition))
}

pub async fn delete_definition(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let mut conn = state.db_pool.get()?;

    tokio::task::spawn_blocking(move || service::delete_definition(&mut conn, &id)).await??;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use crate::AppState;
    use crate::{db, s3};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        Router,
    };
    use diesel::{Connection, RunQueryDsl};
    use serde_json::json;
    use tower::ServiceExt;

    async fn setup_test_app() -> Router {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/mci".to_string());
        let mut root_conn =
            diesel::PgConnection::establish(&database_url.replace("/mci", "/postgres"))
                .expect("Failed to connect to postgres database to setup test db");

        let db_name = "mci";
        diesel::sql_query(format!("DROP DATABASE IF EXISTS {}", db_name))
            .execute(&mut root_conn)
            .expect("Failed to drop test database");
        diesel::sql_query(format!("CREATE DATABASE {}", db_name))
            .execute(&mut root_conn)
            .expect("Failed to create test database");

        let pool = db::create_pool(&database_url);
        let mut conn = pool
            .get()
            .expect("Failed to get database connection for migrations");

        tokio::task::spawn_blocking(move || db::run_migrations(&mut conn))
            .await
            .expect("Migration task panicked")
            .expect("Failed to run migrations");

        let app_state = AppState {
            db_pool: pool,
            s3_client: s3::create_s3_client("http://localhost:9000", "test", "test").await,
        };

        crate::app(app_state)
    }

    // #[tokio::test]
    // async fn test_create_definition_success() {
    //     let app = setup_test_app().await;
    //     let new_definition = json!({
    //         "id": "test-definition",
    //         "definition_url": "https://example.com/definition",
    //         "definition_type": "openapi",
    //         "source_url": "https://example.com",
    //         "description": "Test"
    //     });
    //     let response = app
    //         .oneshot(
    //             Request::builder()
    //                 .method("POST")
    //                 .uri("/definitions")
    //                 .header("content-type", "application/json")
    //                 .body(Body::from(serde_json::to_string(&new_definition).unwrap()))
    //                 .unwrap(),
    //         )
    //         .await
    //         .unwrap();
    //
    //     assert_eq!(response.status(), StatusCode::CREATED);
    // }
    //
    // #[tokio::test]
    // async fn test_create_definition_validation_error() {
    //     let app = setup_test_app().await;
    //     let invalid_definition = json!({
    //         "id": "a",
    //         "definition_url": "not-a-url",
    //         "definition_type": "openapi",
    //         "source_url": "https://example.com",
    //         "description": "Test"
    //     });
    //     let response = app
    //         .oneshot(
    //             Request::builder()
    //                 .method("POST")
    //                 .uri("/definitions")
    //                 .header("content-type", "application/json")
    //                 .body(Body::from(serde_json::to_string(&invalid_definition).unwrap()))
    //                 .unwrap(),
    //         )
    //         .await
    //         .unwrap();
    //
    //     assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    // }

    #[tokio::test]
    async fn test_get_definition_not_found() {
        let app = setup_test_app().await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/definitions/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
