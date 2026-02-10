use crate::{
    db::DbConnection,
    models::{Definition, NewDefinition, UpdateDefinition},
    schema::definitions,
};
use aws_smithy_types::byte_stream::ByteStream;
use diesel::prelude::*;
use futures::stream::TryStreamExt;
use http_body_util::StreamBody;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::fs;
use tokio_util::io::ReaderStream;

#[derive(Debug, Deserialize, Default)]
pub struct DefinitionFilter {
    pub query: Option<String>,
    pub enabled: Option<bool>,
    pub definition_type: Option<String>,
}

#[derive(Debug, Clone)]
pub enum DefinitionSource {
    Http(String),
    Path(String),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DefinitionPayload {
    pub id: String,
    #[serde(rename = "type")]
    pub definition_type: String,
    pub definition_url: String,
    pub description: String,
}

impl DefinitionSource {
    pub fn parse(input: &str) -> Self {
        match input.split_once(':') {
            Some(("http" | "https", _)) => Self::Http(input.to_string()),
            Some(("path", path_data)) => Self::Path(path_data.to_string()),
            _ => Self::Path(input.to_string()),
        }
    }
}

fn build_http_client(timeout_secs: u64) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .build()
}

async fn fetch_definition_from_path(
    path: &str,
) -> Result<DefinitionPayload, Box<dyn std::error::Error>> {
    let metadata = fs::metadata(path).await?;
    if !metadata.is_file() {
        return Err("Path is not a file".into());
    }

    let content = fs::read_to_string(path).await?;
    let definition_payload = serde_json::from_str::<DefinitionPayload>(&content)?;
    Ok(definition_payload)
}

async fn fetch_definition_from_url(
    url: &str,
    timeout_secs: u64,
) -> Result<DefinitionPayload, Box<dyn std::error::Error>> {
    let client = build_http_client(timeout_secs)?;
    let definition_payload = client
        .get(url)
        .header("User-Agent", "MCI/1.0")
        .send()
        .await?
        .error_for_status()?
        .json::<DefinitionPayload>()
        .await?;
    Ok(definition_payload)
}

pub async fn stream_content_from_path(
    path: &str,
) -> Result<ReaderStream<tokio::fs::File>, Box<dyn std::error::Error>> {
    let file = tokio::fs::File::open(path).await?;
    Ok(ReaderStream::new(file))
}

pub async fn stream_content_from_url(
    url: &str,
) -> Result<reqwest::Response, Box<dyn std::error::Error>> {
    let client = build_http_client(30)?;
    let response = client
        .get(url)
        .header("User-Agent", "MCI/1.0")
        .send()
        .await?
        .error_for_status()?;
    Ok(response)
}

fn create_definition(
    conn: &mut DbConnection,
    new_definition: NewDefinition,
) -> QueryResult<Definition> {
    diesel::insert_into(definitions::table)
        .values(&new_definition)
        .returning(Definition::as_returning())
        .get_result(conn)
}

pub fn get_definition(conn: &mut DbConnection, definition_id: &str) -> QueryResult<Definition> {
    definitions::table
        .find(definition_id)
        .select(Definition::as_select())
        .first(conn)
}

pub fn list_definitions(
    conn: &mut DbConnection,
    filter: DefinitionFilter,
) -> QueryResult<Vec<Definition>> {
    let mut query = definitions::table.into_boxed();

    if let Some(search) = filter.query {
        let pattern = format!("%{}%", search);
        query = query.filter(
            definitions::id
                .ilike(pattern.clone())
                .or(definitions::description.ilike(pattern)),
        );
    }
    if let Some(enabled) = filter.enabled {
        query = query.filter(definitions::enabled.eq(enabled));
    }
    if let Some(definition_type) = filter.definition_type {
        query = query.filter(definitions::definition_type.eq(definition_type));
    }

    query.select(Definition::as_select()).load(conn)
}

pub fn update_definition(
    conn: &mut DbConnection,
    id: &str,
    update: UpdateDefinition,
) -> QueryResult<Definition> {
    diesel::update(definitions::table.find(id))
        .set(&update)
        .returning(Definition::as_returning())
        .get_result(conn)
}

pub fn delete_definition(conn: &mut DbConnection, id: &str) -> QueryResult<usize> {
    diesel::delete(definitions::table.find(id)).execute(conn)
}

pub async fn fetch_and_create_definition(
    conn: &mut DbConnection,
    s3_client: &aws_sdk_s3::Client,
    source_input: &str,
) -> Result<Definition, Box<dyn std::error::Error>> {
    let source_url = DefinitionSource::parse(source_input);

    let payload = match &source_url {
        DefinitionSource::Http(url) => fetch_definition_from_url(url, 30).await?,
        DefinitionSource::Path(path) => fetch_definition_from_path(path).await?,
    };

    if get_definition(conn, &payload.id).is_ok() {
        return Err(format!(
            "Conflict: Definition with ID '{}' already exists",
            payload.id
        )
        .into());
    }

    let definition_url = DefinitionSource::parse(&payload.definition_url);

    let body = match definition_url {
        DefinitionSource::Http(url) => {
            let response = reqwest::get(&url).await?;
            let stream = response.bytes_stream();
            let frames = stream.map_ok(|bytes| hyper::body::Frame::data(bytes));
            let body = StreamBody::new(frames);

            ByteStream::from_body_1_x(body)
        }
        DefinitionSource::Path(path) => ByteStream::from_path(Path::new(&path)).await?,
    };

    crate::s3::upload_stream(s3_client, "definitionifications", &payload.id, body).await?;

    let new_definition = NewDefinition {
        id: payload.id,
        definition_url: payload.definition_url,
        definition_type: payload.definition_type,
        description: payload.description,
        source_url: source_input.to_string(),
    };

    Ok(create_definition(conn, new_definition)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use aws_sdk_s3::config::http::HttpResponse;
    use aws_sdk_s3::{
        config::{BehaviorVersion, Credentials, Region},
        Client as S3Client,
    };
    use aws_smithy_runtime::client::http::test_util::StaticReplayClient;
    use diesel::Connection;
    use hyper::StatusCode;
    use serde_json::json;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn setup_test_db() -> DbConnection {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/mci".to_string());
        let pool = db::create_pool(&database_url);
        let mut conn = pool.get().unwrap();

        db::run_migrations(&mut conn).expect("Migration failed");
        conn.begin_test_transaction().unwrap();

        conn
    }

    async fn setup_mock_s3() -> S3Client {
        let http_client = StaticReplayClient::new(vec![
            aws_smithy_runtime_api::client::http::HttpResponse::new(
                http::StatusCode::OK,
                SdkBody::empty(),
            ),
        ]);
        let config = aws_sdk_s3::config::Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .credentials_provider(Credentials::new("test", "test", None, None, "test"))
            .http_client(http_client)
            .build();

        S3Client::from_conf(config)
    }

    fn dummy_definition_fields() -> NewDefinition {
        NewDefinition {
            id: "".into(),
            definition_url: "http://test.com".into(),
            definition_type: "openapi".into(),
            source_url: "http://test.com".into(),
            description: "test".into(),
        }
    }

    fn create_valid_temp_definition(id: &str) -> (NamedTempFile, String) {
        let mut file = NamedTempFile::new().unwrap();
        let path = file.path().to_str().unwrap().to_string();
        let payload = json!({
            "id": id,
            "type": "openapi",
            "definition_url": format!("path:{}", path),
            "description": "Behavioral test definition"
        });

        writeln!(file, "{}", payload.to_string()).unwrap();

        (file, path)
    }

    #[test]
    fn test_create_and_get_lifecycle() {
        let mut conn = setup_test_db();
        let id = "lifecycle-id";
        let new_definition = NewDefinition {
            id: id.into(),
            ..dummy_definition_fields()
        };

        let created = create_definition(&mut conn, new_definition).expect("Should insert record");
        assert_eq!(created.id, id);

        let fetched = get_definition(&mut conn, id).expect("Should fetch record");
        assert_eq!(fetched.id, id);
    }

    #[test]
    fn test_update_record_behavior() {
        let mut conn = setup_test_db();
        let id = "update-id";

        create_definition(
            &mut conn,
            NewDefinition {
                id: id.into(),
                ..dummy_definition_fields()
            },
        )
        .unwrap();

        let update = UpdateDefinition {
            description: Some("new description".into()),
            enabled: Some(false),
            ..Default::default()
        };

        let updated = update_definition(&mut conn, id, update).expect("Should update");
        assert_eq!(updated.description, "new description");
        assert!(!updated.enabled);
    }

    #[test]
    fn test_delete_record_behavior() {
        let mut conn = setup_test_db();
        let id = "delete-id";
        create_definition(
            &mut conn,
            NewDefinition {
                id: id.into(),
                ..dummy_definition_fields()
            },
        )
        .unwrap();

        let rows_deleted = delete_definition(&mut conn, id).expect("Should delete");
        assert_eq!(rows_deleted, 1);
        assert!(get_definition(&mut conn, id).is_err());
    }

    #[test]
    fn test_complex_filtering_logic() {
        let mut conn = setup_test_db();

        let definition1 = NewDefinition {
            id: "alpha".into(),
            definition_type: "openapi".into(),
            ..dummy_definition_fields()
        };
        let definition2 = NewDefinition {
            id: "beta".into(),
            definition_type: "asyncapi".into(),
            ..dummy_definition_fields()
        };

        create_definition(&mut conn, definition1).unwrap();
        create_definition(&mut conn, definition2).unwrap();

        let filter_type = DefinitionFilter {
            definition_type: Some("openapi".into()),
            ..Default::default()
        };
        let results = list_definitions(&mut conn, filter_type).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "alpha");

        let filter_query = DefinitionFilter {
            query: Some("bet".into()),
            ..Default::default()
        };
        let results = list_definitions(&mut conn, filter_query).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "beta");
    }

    #[test]
    fn test_path_resolution_behavior() {
        let cases = vec![
            (
                "/absolute/path/definition.json",
                "/absolute/path/definition.json",
            ),
            (
                "./relative/path/definition.json",
                "./relative/path/definition.json",
            ),
            (
                "path:/prefixed/path/definition.json",
                "/prefixed/path/definition.json",
            ),
        ];

        for (input, expected) in cases {
            if let DefinitionSource::Path(actual) = DefinitionSource::parse(input) {
                assert_eq!(actual, expected, "Failed resolution for: {}", input);
            } else {
                panic!(
                    "Input {} should have resolved to DefinitionSource::Path",
                    input
                );
            }
        }
    }

    #[tokio::test]
    async fn test_fetch_and_create_success_flow() {
        let mut conn = setup_test_db();
        let s3 = setup_mock_s3().await;
        let id = "success-behavior-test";
        let (_file, path) = create_valid_temp_definition(id);
        let result = fetch_and_create_definition(&mut conn, &s3, &path).await;

        assert!(result.is_ok(), "Service flow failed: {:?}", result.err());
        let definition = result.unwrap();
        assert_eq!(definition.id, id);
        assert_eq!(definition.source_url, path);
    }

    #[tokio::test]
    async fn test_conflict_prevention_integrity() {
        let mut conn = setup_test_db();
        let s3 = setup_mock_s3().await;
        let id = "conflict-id";
        let (_file, path) = create_valid_temp_definition(id);
        let existing = NewDefinition {
            id: id.to_string(),
            ..dummy_definition_fields()
        };

        create_definition(&mut conn, existing).unwrap();

        let result = fetch_and_create_definition(&mut conn, &s3, &path).await;
        assert!(result.is_err());

        let err_msg = result.err().unwrap().to_string();
        assert!(
            err_msg.contains("already exists"),
            "Expected conflict error, got: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn test_id_derived_from_content_not_input() {
        let mut conn = setup_test_db();
        let s3 = setup_mock_s3().await;
        let content_id = "derived-id-123";
        let (_file, path) = create_valid_temp_definition(content_id);
        let result = fetch_and_create_definition(&mut conn, &s3, &path)
            .await
            .unwrap();

        assert_eq!(result.id, content_id);
        assert!(result.id != path);
    }

    #[tokio::test]
    async fn test_fetch_from_url_behavior() {
        let mock_server = MockServer::start().await;
        let payload = json!({
            "id": "web-definition",
            "type": "openapi",
            "definition_url": "http://example.com/raw",
            "description": "Remote definition"
        });

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&payload))
            .mount(&mock_server)
            .await;

        let res = fetch_definition_from_url(&mock_server.uri(), 1).await;

        assert!(res.is_ok());
        assert_eq!(res.unwrap().id, "web-definition");
    }
}
