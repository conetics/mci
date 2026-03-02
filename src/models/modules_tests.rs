use super::*;
use serde_json::json;

#[test]
fn update_module_request_rejects_unknown_digest_field() {
	let payload = json!({
		"digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	});

	let result: Result<UpdateModuleRequest, _> = serde_json::from_value(payload);
	assert!(result.is_err());
}

#[test]
fn update_module_request_rejects_unknown_file_url_field() {
	let payload = json!({
		"file_url": "http://example.com/module.wasm"
	});

	let result: Result<UpdateModuleRequest, _> = serde_json::from_value(payload);
	assert!(result.is_err());
}

#[test]
fn update_module_request_into_changeset_forces_digest_none() {
	let req = UpdateModuleRequest {
		is_enabled: Some(true),
		name: Some("mod-name".to_string()),
		description: Some("mod-desc".to_string()),
		source_url: Some("http://example.com/module-registry.json".to_string()),
	};

	let update = req.into_changeset();
	assert_eq!(update.digest, None);
}
