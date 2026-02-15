use mci::http::create_client;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_client_succeeds() {
        let result = create_client(30);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_client_respects_timeout() {
        let client = create_client(1).unwrap();
        let result = client.get("https://httpbin.org/delay/10").send().await;

        assert!(result.is_err());
        assert!(result.unwrap_err().is_timeout());
    }
}
