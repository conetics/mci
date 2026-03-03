use super::*;

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    const ID: &str = "test-id-123";
    const LABEL: &str = "Definition";

    async fn run(
        config: anyhow::Result<()>,
        secrets: anyhow::Result<()>,
    ) -> Result<http::StatusCode, AppError> {
        handle_delete_cleanup(ID, LABEL, config, secrets).await
    }

    #[tokio::test]
    async fn both_ok_returns_no_content() {
        let result = run(Ok(()), Ok(())).await;
        assert_eq!(result.unwrap(), http::StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn config_err_secrets_ok_returns_app_error() {
        let result = run(Err(anyhow!("bucket not found")), Ok(())).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn config_err_secrets_ok_error_mentions_configuration() {
        let result = run(Err(anyhow!("bucket not found")), Ok(())).await;
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("configuration"));
        assert!(msg.contains(ID));
        assert!(msg.contains(LABEL));
    }

    #[tokio::test]
    async fn config_ok_secrets_err_returns_app_error() {
        let result = run(Ok(()), Err(anyhow!("access denied"))).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn config_ok_secrets_err_error_mentions_secrets() {
        let result = run(Ok(()), Err(anyhow!("access denied"))).await;
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("secrets"));
        assert!(msg.contains(ID));
        assert!(msg.contains(LABEL));
    }

    #[tokio::test]
    async fn both_err_returns_app_error() {
        let result = run(
            Err(anyhow!("config bucket not found")),
            Err(anyhow!("secrets access denied")),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn both_err_mentions_both_failures() {
        let result = run(
            Err(anyhow!("config bucket not found")),
            Err(anyhow!("secrets access denied")),
        )
        .await;
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("configuration"));
        assert!(msg.contains("secrets"));
        assert!(msg.contains(ID));
        assert!(msg.contains(LABEL));
    }

    #[tokio::test]
    async fn error_messages_include_original_error_text() {
        let config_err_msg = "some specific s3 error";
        let result = run(Err(anyhow!(config_err_msg)), Ok(())).await;
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains(config_err_msg));
    }

    #[tokio::test]
    async fn both_err_messages_include_both_original_errors() {
        let config_err_msg = "config s3 error";
        let secrets_err_msg = "secrets s3 error";
        let result = run(
            Err(anyhow!(config_err_msg)),
            Err(anyhow!(secrets_err_msg)),
        )
        .await;
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains(config_err_msg));
        assert!(msg.contains(secrets_err_msg));
    }
}
