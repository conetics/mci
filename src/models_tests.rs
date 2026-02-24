use super::*;
use serde_json::json;

#[test]
fn test_validate_digest_valid_sha256() {
    let digest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert!(validate_digest(digest).is_ok());
}

#[test]
fn test_validate_digest_missing_colon() {
    let digest = "sha256e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let result = validate_digest(digest);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "invalid_digest_format");
}

#[test]
fn test_validate_digest_excess_colon() {
    let digest = "sha256::e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let result = validate_digest(digest);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "invalid_hash_format");
}

#[test]
fn test_validate_digest_unsupported_algorithm() {
    let digest = "md5:098f6bcd4621d373cade4e832627b4f6";
    let result = validate_digest(digest);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "unsupported_digest_algorithm");
}

#[test]
fn test_validate_digest_invalid_hash_format() {
    let digest = "sha256:invalid_hash";
    let result = validate_digest(digest);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "invalid_hash_format");
}

#[test]
fn test_update_definition_rejects_unknown_digest_field() {
    let payload = json!({
        "digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    });

    let result: Result<UpdateDefinitionRequest, _> = serde_json::from_value(payload);
    assert!(result.is_err());
}

#[test]
fn test_update_definition_rejects_unknown_file_url_field() {
    let payload = json!({
        "file_url": "http://example.com/file.json"
    });

    let result: Result<UpdateDefinitionRequest, _> = serde_json::from_value(payload);
    assert!(result.is_err());
}

#[test]
fn test_update_definition_metadata_only_accepted() {
    let req = UpdateDefinitionRequest {
        name: Some("New Name".to_string()),
        is_enabled: None,
        type_: None,
        description: None,
        source_url: None,
    };
    assert!(req.validate().is_ok());
}

#[test]
fn test_update_definition_into_changeset_forces_digest_none() {
    let req = UpdateDefinitionRequest {
        is_enabled: Some(true),
        type_: Some("my-type".to_string()),
        name: Some("My name".to_string()),
        description: Some("desc".to_string()),
        source_url: Some("http://example.com/source.json".to_string()),
    };

    let update = req.into_changeset();
    assert_eq!(update.digest, None);
}

#[test]
fn test_update_module_rejects_unknown_digest_field() {
    let payload = json!({
        "digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    });

    let result: Result<UpdateModuleRequest, _> = serde_json::from_value(payload);
    assert!(result.is_err());
}

#[test]
fn test_update_module_rejects_unknown_file_url_field() {
    let payload = json!({
        "file_url": "http://example.com/module.wasm"
    });

    let result: Result<UpdateModuleRequest, _> = serde_json::from_value(payload);
    assert!(result.is_err());
}

#[test]
fn test_update_module_into_changeset_forces_digest_none() {
    let req = UpdateModuleRequest {
        is_enabled: Some(true),
        name: Some("mod-name".to_string()),
        description: Some("mod-desc".to_string()),
        source_url: Some("http://example.com/module-registry.json".to_string()),
    };

    let update = req.into_changeset();
    assert_eq!(update.digest, None);
}
