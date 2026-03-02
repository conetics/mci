use super::*;
use serde_json::json;

#[test]
fn validate_digest_accepts_valid_sha256() {
	let digest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
	assert!(validate_digest(digest).is_ok());
}

#[test]
fn validate_digest_rejects_missing_colon() {
	let digest = "sha256e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
	let result = validate_digest(digest);
	assert!(result.is_err());
	assert_eq!(result.unwrap_err().code, "invalid_digest_format");
}

#[test]
fn validate_digest_rejects_extra_colon() {
	let digest = "sha256::e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
	let result = validate_digest(digest);
	assert!(result.is_err());
	assert_eq!(result.unwrap_err().code, "invalid_hash_format");
}

#[test]
fn validate_digest_rejects_unsupported_algorithm() {
	let digest = "md5:098f6bcd4621d373cade4e832627b4f6";
	let result = validate_digest(digest);
	assert!(result.is_err());
	assert_eq!(result.unwrap_err().code, "unsupported_digest_algorithm");
}

#[test]
fn validate_digest_rejects_invalid_hash_format() {
	let digest = "sha256:invalid_hash";
	let result = validate_digest(digest);
	assert!(result.is_err());
	assert_eq!(result.unwrap_err().code, "invalid_hash_format");
}

#[test]
fn update_definition_request_rejects_unknown_digest_field() {
	let payload = json!({
		"digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	});

	let result: Result<UpdateDefinitionRequest, _> = serde_json::from_value(payload);
	assert!(result.is_err());
}

#[test]
fn update_definition_request_rejects_unknown_file_url_field() {
	let payload = json!({
		"file_url": "http://example.com/file.json"
	});

	let result: Result<UpdateDefinitionRequest, _> = serde_json::from_value(payload);
	assert!(result.is_err());
}

#[test]
fn update_definition_request_allows_metadata_only_changes() {
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
fn update_definition_request_into_changeset_forces_digest_none() {
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
