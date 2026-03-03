use anyhow::{Context, Result};
use reqwest;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::fs;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    Definition,
    Module,
}

impl ResourceKind {
    pub fn config_bucket(self) -> &'static str {
        match self {
            ResourceKind::Definition => "definition-configurations",
            ResourceKind::Module => "module-configurations",
        }
    }

    pub fn secrets_bucket(self) -> &'static str {
        match self {
            ResourceKind::Definition => "definition-secrets",
            ResourceKind::Module => "module-secrets",
        }
    }
}

#[derive(Debug, Deserialize)]
pub enum SortBy {
    Id,
    Name,
    Type,
}

#[derive(Debug, Deserialize)]
pub enum SortOrder {
    Asc,
    Desc,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Payload<T> {
    pub id: String,
    pub name: String,
    pub r#type: T,
    pub description: String,
    pub file_url: String,
    pub digest: String,
    pub source_url: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct Filter<T> {
    pub query: Option<String>,
    pub is_enabled: Option<bool>,
    pub r#type: Option<T>,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
    pub sort_by: Option<SortBy>,
    pub sort_order: Option<SortOrder>,
}

pub fn validate_schema(
    schema: &serde_json::Value,
    data: &serde_json::Value,
) -> Result<serde_json::Value> {
    let validator = jsonschema::validator_for(schema).context("Invalid JSON schema")?;
    let evaluation = validator.evaluate(data);
    serde_json::to_value(evaluation.list()).context("Failed to serialize validation output")
}

pub async fn fetch_payload<T>(
    http_client: &reqwest::Client,
    source: &crate::utils::source::Source,
    label: &str,
) -> Result<T>
where
    T: DeserializeOwned,
{
    match source {
        crate::utils::source::Source::Http(url) => {
            let payload = http_client
                .get(url)
                .header("User-Agent", "MCI/1.0")
                .send()
                .await
                .context("Failed to send HTTP request")?
                .error_for_status()
                .context("HTTP request returned error status")?
                .json::<T>()
                .await
                .context(format!("Failed to parse {} JSON from response", label))?;
            Ok(payload)
        }
        crate::utils::source::Source::File(path) => {
            let content = fs::read_to_string(path)
                .await
                .context(format!("Failed to read {} file", label))?;
            let payload = serde_json::from_str::<T>(&content)
                .context(format!("Failed to parse {} JSON", label))?;
            Ok(payload)
        }
    }
}


#[cfg(test)]
#[path = "common_tests.rs"]
mod tests;
