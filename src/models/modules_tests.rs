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

fn valid_new_module() -> NewModule {
    NewModule {
        id: "my-module".into(),
        type_: ModuleType::Language,
        name: "My Module".into(),
        description: "A test module.".into(),
        digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
        source_url: None,
    }
}

#[test]
fn new_module_valid_passes_validation() {
    use validator::Validate;
    assert!(valid_new_module().validate().is_ok());
}

#[test]
fn new_module_id_too_short_rejected() {
    use validator::Validate;
    let m = NewModule {
        id: "ab".into(),
        ..valid_new_module()
    };
    assert!(m.validate().is_err());
}

#[test]
fn new_module_id_too_long_rejected() {
    use validator::Validate;
    let m = NewModule {
        id: "a".repeat(65),
        ..valid_new_module()
    };
    assert!(m.validate().is_err());
}

#[test]
fn new_module_id_rejects_invalid_chars() {
    use validator::Validate;
    let m = NewModule {
        id: "bad@module".into(),
        ..valid_new_module()
    };
    assert!(m.validate().is_err());
}

#[test]
fn new_module_name_too_short_rejected() {
    use validator::Validate;
    let m = NewModule {
        name: "ab".into(),
        ..valid_new_module()
    };
    assert!(m.validate().is_err());
}

#[test]
fn new_module_description_too_long_rejected() {
    use validator::Validate;
    let m = NewModule {
        description: "a".repeat(501),
        ..valid_new_module()
    };
    assert!(m.validate().is_err());
}

#[test]
fn new_module_invalid_digest_rejected() {
    use validator::Validate;
    let m = NewModule {
        digest: "not-a-digest".into(),
        ..valid_new_module()
    };
    assert!(m.validate().is_err());
}

#[test]
fn new_module_invalid_source_url_rejected() {
    use validator::Validate;
    let m = NewModule {
        source_url: Some("not-a-url".into()),
        ..valid_new_module()
    };
    assert!(m.validate().is_err());
}

#[test]
fn new_module_valid_source_url_passes() {
    use validator::Validate;
    let m = NewModule {
        source_url: Some("https://example.com/module-registry.json".into()),
        ..valid_new_module()
    };
    assert!(m.validate().is_ok());
}
