use super::*;
use serde_json::json;

#[test]
fn validate_configuration_accepts_valid_payload() {
    let schema = json!({
        "type": "object",
        "properties": {
            "name": { "type": "string" },
            "enabled": { "type": "boolean" }
        },
        "required": ["name", "enabled"],
        "additionalProperties": false
    });

    let configuration = json!({
        "name": "module-a",
        "enabled": true
    });

    let output = validate_configuration(&schema, &configuration)
        .expect("validation output should be generated");

    assert_eq!(output["valid"], json!(true));
    assert!(output.get("details").is_some());
}

#[test]
fn validate_configuration_rejects_invalid_payload() {
    let schema = json!({
        "type": "object",
        "properties": {
            "name": { "type": "string" },
            "enabled": { "type": "boolean" }
        },
        "required": ["name", "enabled"],
        "additionalProperties": false
    });

    let configuration = json!({
        "name": 42,
        "enabled": "yes"
    });

    let output = validate_configuration(&schema, &configuration)
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
fn validate_configuration_rejects_invalid_schema() {
    let schema = json!({
        "type": 12
    });

    let configuration = json!({
        "name": "module-a"
    });

    let result = validate_configuration(&schema, &configuration);
    assert!(result.is_err());
}
