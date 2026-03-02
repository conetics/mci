use aws_sdk_s3::{config, Client, Config};

pub async fn create_client(
    endpoint_url: &str,
    access_key: &str,
    secret_key: &str,
    region: &str,
) -> Client {
    let s3_config = Config::builder()
        .endpoint_url(endpoint_url)
        .credentials_provider(config::Credentials::new(
            access_key.to_string(),
            secret_key.to_string(),
            None,
            None,
            "mci-storage",
        ))
        .region(config::Region::new(region.to_string()))
        .force_path_style(true)
        .build();

    Client::from_conf(s3_config)
}
