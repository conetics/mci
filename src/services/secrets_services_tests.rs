use super::*;
use serde_json::json;

#[test]
fn validate_secrets_accepts_valid_payload() {
    let schema = json!({
        "type": "object",
        "properties": {
            "api_key": { "type": "string" },
            "db_password": { "type": "string" }
        },
        "required": ["api_key", "db_password"],
        "additionalProperties": false
    });

    let secrets = json!({
        "api_key": "sk-secret-123",
        "db_password": "hunter2"
    });

    let output =
        validate_secrets(&schema, &secrets).expect("validation output should be generated");

    assert_eq!(output["valid"], json!(true));
    assert!(output.get("details").is_some());
}

#[test]
fn validate_secrets_rejects_invalid_payload() {
    let schema = json!({
        "type": "object",
        "properties": {
            "api_key": { "type": "string" },
            "enabled": { "type": "boolean" }
        },
        "required": ["api_key", "enabled"],
        "additionalProperties": false
    });

    let secrets = json!({
        "api_key": 42,
        "enabled": "not-a-bool"
    });

    let output =
        validate_secrets(&schema, &secrets).expect("validation output should be generated");

    assert_eq!(output["valid"], json!(false));
    assert!(output["details"].as_array().is_some());
    assert!(!output["details"].as_array().unwrap().is_empty());

    let first_detail = &output["details"][0];
    assert!(first_detail.get("valid").is_some());
    assert!(first_detail.get("evaluationPath").is_some());
    assert!(first_detail.get("instanceLocation").is_some());
    assert!(first_detail.get("schemaLocation").is_some());
}

#[test]
fn validate_secrets_rejects_invalid_schema() {
    let schema = json!({
        "type": 12
    });

    let secrets = json!({
        "api_key": "sk-123"
    });

    let result = validate_secrets(&schema, &secrets);
    assert!(result.is_err());
}

#[test]
fn validate_secrets_rejects_missing_required_fields() {
    let schema = json!({
        "type": "object",
        "properties": {
            "api_key": { "type": "string" },
            "token": { "type": "string" }
        },
        "required": ["api_key", "token"]
    });

    let secrets = json!({
        "api_key": "sk-123"
    });

    let output =
        validate_secrets(&schema, &secrets).expect("validation output should be generated");

    assert_eq!(output["valid"], json!(false));
}

#[test]
fn validate_secrets_rejects_additional_properties() {
    let schema = json!({
        "type": "object",
        "properties": {
            "api_key": { "type": "string" }
        },
        "additionalProperties": false
    });

    let secrets = json!({
        "api_key": "sk-123",
        "extra": "not-allowed"
    });

    let output =
        validate_secrets(&schema, &secrets).expect("validation output should be generated");

    assert_eq!(output["valid"], json!(false));
}

#[test]
fn validate_secrets_accepts_empty_object_when_no_required() {
    let schema = json!({
        "type": "object",
        "properties": {
            "api_key": { "type": "string" }
        }
    });

    let secrets = json!({});

    let output =
        validate_secrets(&schema, &secrets).expect("validation output should be generated");

    assert_eq!(output["valid"], json!(true));
}

#[test]
fn bucket_for_returns_definition_secrets_bucket() {
    assert_eq!(bucket_for(SecretsTarget::Definition), "definition-secrets");
}

#[test]
fn bucket_for_returns_module_secrets_bucket() {
    assert_eq!(bucket_for(SecretsTarget::Module), "module-secrets");
}

#[test]
fn validate_secrets_handles_nested_objects() {
    let schema = json!({
        "type": "object",
        "properties": {
            "database": {
                "type": "object",
                "properties": {
                    "host": { "type": "string" },
                    "port": { "type": "integer" }
                },
                "required": ["host", "port"]
            }
        },
        "required": ["database"]
    });

    let secrets = json!({
        "database": {
            "host": "localhost",
            "port": 5432
        }
    });

    let output =
        validate_secrets(&schema, &secrets).expect("validation output should be generated");

    assert_eq!(output["valid"], json!(true));
}

#[test]
fn validate_secrets_rejects_nested_type_errors() {
    let schema = json!({
        "type": "object",
        "properties": {
            "auth": {
                "type": "object",
                "properties": {
                    "enabled": { "type": "boolean" }
                },
                "required": ["enabled"]
            }
        },
        "required": ["auth"]
    });

    let secrets = json!({
        "auth": {
            "enabled": "not-a-boolean"
        }
    });

    let output =
        validate_secrets(&schema, &secrets).expect("validation output should be generated");

    assert_eq!(output["valid"], json!(false));
}

#[test]
fn validate_secrets_handles_arrays() {
    let schema = json!({
        "type": "object",
        "properties": {
            "api_keys": {
                "type": "array",
                "items": { "type": "string" },
                "minItems": 1
            }
        },
        "required": ["api_keys"]
    });

    let secrets = json!({
        "api_keys": ["key1", "key2", "key3"]
    });

    let output =
        validate_secrets(&schema, &secrets).expect("validation output should be generated");

    assert_eq!(output["valid"], json!(true));
}

#[test]
fn validate_secrets_rejects_invalid_array_items() {
    let schema = json!({
        "type": "object",
        "properties": {
            "ports": {
                "type": "array",
                "items": { "type": "integer" }
            }
        }
    });

    let secrets = json!({
        "ports": [8080, "not-a-number", 9090]
    });

    let output =
        validate_secrets(&schema, &secrets).expect("validation output should be generated");

    assert_eq!(output["valid"], json!(false));
}

#[test]
fn validate_secrets_rejects_wrong_type_at_root() {
    let schema = json!({
        "type": "object",
        "properties": {
            "api_key": { "type": "string" }
        }
    });

    let secrets = json!("not-an-object");

    let output =
        validate_secrets(&schema, &secrets).expect("validation output should be generated");

    assert_eq!(output["valid"], json!(false));
}

#[test]
fn validate_secrets_accepts_null_for_nullable_field() {
    let schema = json!({
        "type": "object",
        "properties": {
            "api_key": { "type": ["string", "null"] }
        }
    });

    let secrets = json!({
        "api_key": null
    });

    let output =
        validate_secrets(&schema, &secrets).expect("validation output should be generated");

    assert_eq!(output["valid"], json!(true));
}

#[test]
fn validate_secrets_handles_enum_constraints() {
    let schema = json!({
        "type": "object",
        "properties": {
            "environment": {
                "type": "string",
                "enum": ["development", "staging", "production"]
            }
        },
        "required": ["environment"]
    });

    let valid_secrets = json!({
        "environment": "production"
    });

    let output = validate_secrets(&schema, &valid_secrets)
        .expect("validation output should be generated");

    assert_eq!(output["valid"], json!(true));

    let invalid_secrets = json!({
        "environment": "unknown"
    });

    let output = validate_secrets(&schema, &invalid_secrets)
        .expect("validation output should be generated");

    assert_eq!(output["valid"], json!(false));
}

#[test]
fn validate_secrets_handles_pattern_constraints() {
    let schema = json!({
        "type": "object",
        "properties": {
            "api_key": {
                "type": "string",
                "pattern": "^sk-[a-zA-Z0-9]{32}$"
            }
        },
        "required": ["api_key"]
    });

    let valid_secrets = json!({
        "api_key": "sk-abcdefghijklmnopqrstuvwxyz123456"
    });

    let output = validate_secrets(&schema, &valid_secrets)
        .expect("validation output should be generated");

    assert_eq!(output["valid"], json!(true));

    let invalid_secrets = json!({
        "api_key": "invalid-key"
    });

    let output = validate_secrets(&schema, &invalid_secrets)
        .expect("validation output should be generated");

    assert_eq!(output["valid"], json!(false));
}

#[test]
fn validate_secrets_handles_min_max_length() {
    let schema = json!({
        "type": "object",
        "properties": {
            "password": {
                "type": "string",
                "minLength": 8,
                "maxLength": 128
            }
        },
        "required": ["password"]
    });

    let valid_secrets = json!({
        "password": "validpass123"
    });

    let output = validate_secrets(&schema, &valid_secrets)
        .expect("validation output should be generated");

    assert_eq!(output["valid"], json!(true));

    let too_short = json!({
        "password": "short"
    });

    let output =
        validate_secrets(&schema, &too_short).expect("validation output should be generated");

    assert_eq!(output["valid"], json!(false));
}

#[test]
fn secrets_target_enum_equality() {
    assert_eq!(SecretsTarget::Definition, SecretsTarget::Definition);
    assert_eq!(SecretsTarget::Module, SecretsTarget::Module);
    assert_ne!(SecretsTarget::Definition, SecretsTarget::Module);
}

#[test]
fn secrets_target_debug_format() {
    let def_target = SecretsTarget::Definition;
    let mod_target = SecretsTarget::Module;

    assert_eq!(format!("{:?}", def_target), "Definition");
    assert_eq!(format!("{:?}", mod_target), "Module");
}