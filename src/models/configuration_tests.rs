use super::*;
use serde_json::json;

#[test]
fn configuration_schema_new() {
    let schema = json!({
        "type": "object",
        "properties": {
            "port": { "type": "integer" }
        }
    });

    let config_schema = ConfigurationSchema::new(schema.clone());
    assert_eq!(config_schema.schema, schema);
}

#[test]
fn configuration_schema_serialize_deserialize() {
    let schema = json!({
        "type": "object",
        "properties": {
            "name": { "type": "string" },
            "count": { "type": "integer" }
        },
        "required": ["name"]
    });

    let config_schema = ConfigurationSchema::new(schema.clone());
    let serialized = serde_json::to_string(&config_schema).unwrap();
    let deserialized: ConfigurationSchema = serde_json::from_str(&serialized).unwrap();

    assert_eq!(deserialized.schema, schema);
}

#[test]
fn configuration_schema_clone() {
    let schema = json!({
        "type": "object",
        "properties": {
            "enabled": { "type": "boolean" }
        }
    });

    let config_schema1 = ConfigurationSchema::new(schema.clone());
    let config_schema2 = config_schema1.clone();

    assert_eq!(config_schema1.schema, config_schema2.schema);
}

#[test]
fn configuration_schema_debug() {
    let schema = json!({"type": "string"});
    let config_schema = ConfigurationSchema::new(schema);

    let debug_str = format!("{:?}", config_schema);
    assert!(debug_str.contains("ConfigurationSchema"));
}

#[test]
fn configuration_document_new() {
    let configuration = json!({"port": 8080, "host": "localhost"});
    let validation = json!({"valid": true, "details": []});

    let doc = ConfigurationDocument::new(configuration.clone(), validation.clone());

    assert_eq!(doc.configuration, configuration);
    assert_eq!(doc.validation, validation);
}

#[test]
fn configuration_document_serialize_deserialize() {
    let configuration = json!({
        "database": {
            "host": "localhost",
            "port": 5432
        },
        "cache": {
            "enabled": true,
            "ttl": 300
        }
    });
    let validation = json!({
        "valid": true,
        "details": []
    });

    let doc = ConfigurationDocument::new(configuration.clone(), validation.clone());
    let serialized = serde_json::to_string(&doc).unwrap();
    let deserialized: ConfigurationDocument = serde_json::from_str(&serialized).unwrap();

    assert_eq!(deserialized.configuration, configuration);
    assert_eq!(deserialized.validation, validation);
}

#[test]
fn configuration_document_with_invalid_validation() {
    let configuration = json!({"port": "not-a-number"});
    let validation = json!({
        "valid": false,
        "details": [
            {
                "valid": false,
                "instanceLocation": "/port",
                "schemaLocation": "#/properties/port/type",
                "error": "Value is not an integer"
            }
        ]
    });

    let doc = ConfigurationDocument::new(configuration.clone(), validation.clone());

    assert_eq!(doc.configuration, configuration);
    assert_eq!(doc.validation, validation);
    assert_eq!(doc.validation["valid"], false);
}

#[test]
fn configuration_document_clone() {
    let configuration = json!({"key": "value"});
    let validation = json!({"valid": true});

    let doc1 = ConfigurationDocument::new(configuration, validation);
    let doc2 = doc1.clone();

    assert_eq!(doc1.configuration, doc2.configuration);
    assert_eq!(doc1.validation, doc2.validation);
}

#[test]
fn configuration_document_debug() {
    let configuration = json!({"test": true});
    let validation = json!({"valid": true});
    let doc = ConfigurationDocument::new(configuration, validation);

    let debug_str = format!("{:?}", doc);
    assert!(debug_str.contains("ConfigurationDocument"));
}

#[test]
fn configuration_schema_with_complex_schema() {
    let schema = json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {
            "server": {
                "type": "object",
                "properties": {
                    "host": { "type": "string" },
                    "port": { "type": "integer", "minimum": 1, "maximum": 65535 }
                },
                "required": ["host", "port"]
            },
            "logging": {
                "type": "object",
                "properties": {
                    "level": { "type": "string", "enum": ["debug", "info", "warn", "error"] },
                    "file": { "type": "string" }
                }
            }
        },
        "required": ["server"]
    });

    let config_schema = ConfigurationSchema::new(schema.clone());
    let serialized = serde_json::to_string(&config_schema).unwrap();
    let deserialized: ConfigurationSchema = serde_json::from_str(&serialized).unwrap();

    assert_eq!(deserialized.schema, schema);
}

#[test]
fn configuration_document_with_empty_objects() {
    let configuration = json!({});
    let validation = json!({});

    let doc = ConfigurationDocument::new(configuration.clone(), validation.clone());

    assert_eq!(doc.configuration, json!({}));
    assert_eq!(doc.validation, json!({}));
}

#[test]
fn configuration_document_with_arrays() {
    let configuration = json!({
        "servers": [
            {"host": "localhost", "port": 8080},
            {"host": "127.0.0.1", "port": 8081}
        ]
    });
    let validation = json!({"valid": true});

    let doc = ConfigurationDocument::new(configuration.clone(), validation.clone());
    let serialized = serde_json::to_string(&doc).unwrap();
    let deserialized: ConfigurationDocument = serde_json::from_str(&serialized).unwrap();

    assert_eq!(deserialized.configuration, configuration);
}
