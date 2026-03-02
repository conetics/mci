use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigurationSchema {
    pub schema: JsonValue,
}

impl ConfigurationSchema {
    pub fn new(schema: JsonValue) -> Self {
        Self { schema }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigurationDocument {
    pub configuration: JsonValue,
    pub validation: JsonValue,
}

impl ConfigurationDocument {
    pub fn new(configuration: JsonValue, validation: JsonValue) -> Self {
        Self {
            configuration,
            validation,
        }
    }
}

#[cfg(test)]
#[path = "configuration_tests.rs"]
mod tests;
