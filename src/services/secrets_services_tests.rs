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

    let output = validate_secrets(&schema, &secrets)
        .expect("validation output should be generated");

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

    let output = validate_secrets(&schema, &secrets)
        .expect("validation output should be generated");

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

    let output = validate_secrets(&schema, &secrets)
        .expect("validation output should be generated");

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

    let output = validate_secrets(&schema, &secrets)
        .expect("validation output should be generated");

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

    let output = validate_secrets(&schema, &secrets)
        .expect("validation output should be generated");

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
