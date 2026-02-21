use super::*;

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
fn test_update_definition_digest_without_file_url_rejected() {
    let req = UpdateDefinitionRequest {
        digest: Some(
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        ),
        is_enabled: None,
        type_: None,
        name: None,
        description: None,
        file_url: None,
        source_url: None,
    };
    let result = req.validate();
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(
        errors
            .to_string()
            .contains("digest cannot be updated without also providing file_url"),
        "expected digest_requires_file_url error, got: {}",
        errors
    );
}

#[test]
fn test_update_definition_file_url_without_digest_accepted() {
    let req = UpdateDefinitionRequest {
        file_url: Some("http://example.com/file.json".to_string()),
        is_enabled: None,
        type_: None,
        name: None,
        description: None,
        digest: None,
        source_url: None,
    };
    assert!(req.validate().is_ok());
}

#[test]
fn test_update_definition_file_url_with_digest_accepted() {
    let req = UpdateDefinitionRequest {
        file_url: Some("http://example.com/file.json".to_string()),
        digest: Some(
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        ),
        is_enabled: None,
        type_: None,
        name: None,
        description: None,
        source_url: None,
    };
    assert!(req.validate().is_ok());
}

#[test]
fn test_update_definition_no_digest_no_file_url_accepted() {
    let req = UpdateDefinitionRequest {
        name: Some("New Name".to_string()),
        is_enabled: None,
        type_: None,
        description: None,
        file_url: None,
        digest: None,
        source_url: None,
    };
    assert!(req.validate().is_ok());
}
