use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretsSchema {
    pub schema: JsonValue,
}

impl SecretsSchema {
    pub fn new(schema: JsonValue) -> Self {
        Self { schema }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretsDocument {
    pub secrets: JsonValue,
}

impl SecretsDocument {
    pub fn new(secrets: JsonValue) -> Self {
        Self { secrets }
    }
}
