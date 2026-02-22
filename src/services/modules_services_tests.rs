use super::*;
use std::fs::write;
use tempfile::TempDir;
use wiremock::matchers::{header, method, path as path_matcher};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn create_valid_payload() -> ModulePayload {
    ModulePayload {
        id: "test-mod-id".to_string(),
        name: "Test Module".to_string(),
        r#type: ModuleType::Sandbox,
        description: "test module description".to_string(),
        file_url: "".to_string(),
        digest: "sha256:abc123".to_string(),
        source_url: None,
    }
}

#[cfg(test)]
mod test_fetch_module_from_path {
    use super::*;
    use std::path::Path;

    #[tokio::test]
    async fn test_valid_json_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("module.json");
        let payload = create_valid_payload();

        write(&file_path, serde_json::to_string(&payload).unwrap()).unwrap();

        let client = reqwest::Client::new();
        let source =
            crate::utils::source_utils::Source::parse(file_path.to_str().unwrap()).unwrap();
        let result = crate::services::modules_services::fetch_module(&client, &source).await;
        assert!(result.is_ok());

        let loaded = result.unwrap();
        assert_eq!(loaded.id, "test-mod-id");
        assert_eq!(loaded.name, "Test Module");
    }

    #[tokio::test]
    async fn test_invalid_json() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("invalid.json");

        write(&file_path, "not valid json {").unwrap();

        let client = reqwest::Client::new();
        let source =
            crate::utils::source_utils::Source::parse(file_path.to_str().unwrap()).unwrap();
        let result = crate::services::modules_services::fetch_module(&client, &source).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to parse module JSON"));
    }

    #[tokio::test]
    async fn test_empty_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("empty.json");

        write(&file_path, "").unwrap();

        let client = reqwest::Client::new();
        let source =
            crate::utils::source_utils::Source::parse(file_path.to_str().unwrap()).unwrap();
        let result = crate::services::modules_services::fetch_module(&client, &source).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to parse module JSON"));
    }

    #[tokio::test]
    async fn test_file_not_found() {
        let path = Path::new("/nonexistent/file.json");
        let source_result = crate::utils::source_utils::Source::parse(path.to_str().unwrap());
        assert!(source_result.is_err());
        let err = source_result.unwrap_err();
        assert!(err.to_string().contains("File does not exist"));
    }
}

#[cfg(test)]
mod test_fetch_module_from_url {
    use super::*;

    #[tokio::test]
    async fn test_successful_fetch() {
        let mock_server = MockServer::start().await;
        let payload = create_valid_payload();

        Mock::given(method("GET"))
            .and(path_matcher("/module.json"))
            .and(header("User-Agent", "MCI/1.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&payload))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let url = format!("{}/module.json", mock_server.uri());
        let source = crate::utils::source_utils::Source::parse(&url).unwrap();

        let result = crate::services::modules_services::fetch_module(&client, &source).await;
        assert!(result.is_ok());

        let loaded = result.unwrap();
        assert_eq!(loaded.id, "test-mod-id");
        assert_eq!(loaded.name, "Test Module");
    }

    #[tokio::test]
    async fn test_404_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_matcher("/notfound.json"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let url = format!("{}/notfound.json", mock_server.uri());
        let source = crate::utils::source_utils::Source::parse(&url).unwrap();

        let result = crate::services::modules_services::fetch_module(&client, &source).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("error status"));
    }

    #[tokio::test]
    async fn test_500_server_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_matcher("/error.json"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let url = format!("{}/error.json", mock_server.uri());
        let source = crate::utils::source_utils::Source::parse(&url).unwrap();

        let result = crate::services::modules_services::fetch_module(&client, &source).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("error status"));
    }

    #[tokio::test]
    async fn test_invalid_json_response() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_matcher("/invalid.json"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not valid json {"))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let url = format!("{}/invalid.json", mock_server.uri());
        let source = crate::utils::source_utils::Source::parse(&url).unwrap();

        let result = crate::services::modules_services::fetch_module(&client, &source).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to parse module JSON"));
    }

    #[tokio::test]
    async fn test_connection_refused() {
        let client = reqwest::Client::new();
        let url = "http://localhost:59999/module.json";
        let source = crate::utils::source_utils::Source::parse(url).unwrap();
        let result = crate::services::modules_services::fetch_module(&client, &source).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to send HTTP request"));
    }

    #[tokio::test]
    async fn test_timeout() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_matcher("/slow.json"))
            .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(10)))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(1))
            .build()
            .unwrap();

        let url = format!("{}/slow.json", mock_server.uri());
        let source = crate::utils::source_utils::Source::parse(&url).unwrap();

        let result = crate::services::modules_services::fetch_module(&client, &source).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_user_agent_is_set() {
        let mock_server = MockServer::start().await;
        let payload = create_valid_payload();

        Mock::given(method("GET"))
            .and(path_matcher("/module.json"))
            .and(header("User-Agent", "MCI/1.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&payload))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let url = format!("{}/module.json", mock_server.uri());
        let source = crate::utils::source_utils::Source::parse(&url).unwrap();

        let result = crate::services::modules_services::fetch_module(&client, &source).await;
        assert!(result.is_ok());
    }
}

#[cfg(test)]
mod test_fetch_module {
    use super::*;
    use url::Url;

    #[tokio::test]
    async fn test_fetch_from_file_source() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("module.json");
        let payload = create_valid_payload();

        write(&file_path, serde_json::to_string(&payload).unwrap()).unwrap();

        let source = source_utils::Source::parse(file_path.to_str().unwrap()).unwrap();
        let client = reqwest::Client::new();

        let result = fetch_module(&client, &source).await;
        assert!(result.is_ok());

        let loaded = result.unwrap();
        assert_eq!(loaded.id, "test-mod-id");
    }

    #[tokio::test]
    async fn test_fetch_from_http_source() {
        let mock_server = MockServer::start().await;
        let payload = create_valid_payload();

        Mock::given(method("GET"))
            .and(path_matcher("/module.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&payload))
            .mount(&mock_server)
            .await;

        let url = format!("{}/module.json", mock_server.uri());
        let source = source_utils::Source::parse(&url).unwrap();
        let client = reqwest::Client::new();

        let result = fetch_module(&client, &source).await;
        assert!(result.is_ok());

        let loaded = result.unwrap();
        assert_eq!(loaded.id, "test-mod-id");
    }

    #[tokio::test]
    async fn test_fetch_from_file_url_source() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("module.json");
        let payload = create_valid_payload();

        write(&file_path, serde_json::to_string(&payload).unwrap()).unwrap();

        let file_url = Url::from_file_path(&file_path).unwrap();
        let source = source_utils::Source::parse(file_url.as_str()).unwrap();
        let client = reqwest::Client::new();

        let result = fetch_module(&client, &source).await;
        assert!(result.is_ok());

        let loaded = result.unwrap();
        assert_eq!(loaded.id, "test-mod-id");
    }
}
