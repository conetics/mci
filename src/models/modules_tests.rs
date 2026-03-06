use super::*;
use serde_json::json;
use validator::Validate;

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
    assert!(valid_new_module().validate().is_ok());
}

#[test]
fn new_module_id_too_short_rejected() {
    let m = NewModule {
        id: "ab".into(),
        ..valid_new_module()
    };
    assert!(m.validate().is_err());
}

#[test]
fn new_module_id_too_long_rejected() {
    let m = NewModule {
        id: "a".repeat(65),
        ..valid_new_module()
    };
    assert!(m.validate().is_err());
}

#[test]
fn new_module_id_rejects_invalid_chars() {
    let m = NewModule {
        id: "bad@module".into(),
        ..valid_new_module()
    };
    assert!(m.validate().is_err());
}

#[test]
fn new_module_name_too_short_rejected() {
    let m = NewModule {
        name: "ab".into(),
        ..valid_new_module()
    };
    assert!(m.validate().is_err());
}

#[test]
fn new_module_description_too_long_rejected() {
    let m = NewModule {
        description: "a".repeat(501),
        ..valid_new_module()
    };
    assert!(m.validate().is_err());
}

#[test]
fn new_module_invalid_digest_rejected() {
    let m = NewModule {
        digest: "not-a-digest".into(),
        ..valid_new_module()
    };
    assert!(m.validate().is_err());
}

#[test]
fn new_module_invalid_source_url_rejected() {
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

#[test]
fn module_type_serializes_to_lowercase() {
    assert_eq!(
        serde_json::to_string(&ModuleType::Language).unwrap(),
        "\"language\""
    );
    assert_eq!(
        serde_json::to_string(&ModuleType::Sandbox).unwrap(),
        "\"sandbox\""
    );
    assert_eq!(
        serde_json::to_string(&ModuleType::Interceptor).unwrap(),
        "\"interceptor\""
    );
    assert_eq!(
        serde_json::to_string(&ModuleType::Proxy).unwrap(),
        "\"proxy\""
    );
    assert_eq!(
        serde_json::to_string(&ModuleType::Hook).unwrap(),
        "\"hook\""
    );
}

#[test]
fn module_type_deserializes_from_lowercase() {
    assert_eq!(
        serde_json::from_str::<ModuleType>("\"language\"").unwrap(),
        ModuleType::Language
    );
    assert_eq!(
        serde_json::from_str::<ModuleType>("\"sandbox\"").unwrap(),
        ModuleType::Sandbox
    );
    assert_eq!(
        serde_json::from_str::<ModuleType>("\"interceptor\"").unwrap(),
        ModuleType::Interceptor
    );
    assert_eq!(
        serde_json::from_str::<ModuleType>("\"proxy\"").unwrap(),
        ModuleType::Proxy
    );
    assert_eq!(
        serde_json::from_str::<ModuleType>("\"hook\"").unwrap(),
        ModuleType::Hook
    );
}

#[test]
fn module_type_deserialize_rejects_uppercase() {
    let result = serde_json::from_str::<ModuleType>("\"Language\"");
    assert!(result.is_err());
}

#[test]
fn module_type_clone_and_copy() {
    let t1 = ModuleType::Language;
    let t2 = t1;
    let t3 = t1;
    assert_eq!(t1, t2);
    assert_eq!(t1, t3);
}

#[test]
fn module_type_debug() {
    let debug_str = format!("{:?}", ModuleType::Language);
    assert!(debug_str.contains("Language"));
}

#[test]
fn update_module_request_allows_all_none() {
    let req = UpdateModuleRequest {
        is_enabled: None,
        name: None,
        description: None,
        source_url: None,
    };
    assert!(req.validate().is_ok());
}

#[test]
fn update_module_request_name_too_short_rejected() {
    use validator::Validate;
    let req = UpdateModuleRequest {
        name: Some("ab".into()),
        is_enabled: None,
        description: None,
        source_url: None,
    };
    assert!(req.validate().is_err());
}

#[test]
fn update_module_request_description_too_long_rejected() {
    use validator::Validate;
    let req = UpdateModuleRequest {
        description: Some("a".repeat(501)),
        is_enabled: None,
        name: None,
        source_url: None,
    };
    assert!(req.validate().is_err());
}

#[test]
fn update_module_request_invalid_source_url_rejected() {
    use validator::Validate;
    let req = UpdateModuleRequest {
        source_url: Some("not-a-url".into()),
        is_enabled: None,
        name: None,
        description: None,
    };
    assert!(req.validate().is_err());
}

#[test]
fn update_module_allows_setting_enabled() {
    let update = UpdateModule {
        is_enabled: Some(false),
        ..Default::default()
    };
    assert_eq!(update.is_enabled, Some(false));
}

#[test]
fn new_module_id_accepts_namespace_format() {
    use validator::Validate;
    let m = NewModule {
        id: "namespace.sub.item".into(),
        ..valid_new_module()
    };
    assert!(m.validate().is_ok());
}

#[test]
fn new_module_description_can_be_empty() {
    use validator::Validate;
    let m = NewModule {
        description: "".into(),
        ..valid_new_module()
    };
    assert!(m.validate().is_ok());
}

#[test]
fn new_module_source_url_none_is_valid() {
    use validator::Validate;
    let m = NewModule {
        source_url: None,
        ..valid_new_module()
    };
    assert!(m.validate().is_ok());
}

#[test]
fn module_has_all_required_fields() {
    let module = Module {
        id: "test-module".into(),
        type_: ModuleType::Sandbox,
        is_enabled: false,
        name: "Test Module".into(),
        description: "Test Description".into(),
        digest: "sha256:abc123".into(),
        source_url: Some("https://example.com".into()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    assert_eq!(module.id, "test-module");
    assert_eq!(module.type_, ModuleType::Sandbox);
    assert!(!module.is_enabled);
}

#[test]
fn update_module_request_from_trait() {
    let req = UpdateModuleRequest {
        is_enabled: Some(true),
        name: Some("New Name".to_string()),
        description: Some("New Description".to_string()),
        source_url: Some("https://example.com".to_string()),
    };
    let update: UpdateModule = req.into();
    assert_eq!(update.is_enabled, Some(true));
    assert_eq!(update.name, Some("New Name".to_string()));
    assert_eq!(update.digest, None);
}

#[test]
fn new_module_accepts_all_module_types() {
    use validator::Validate;
    let types = vec![
        ModuleType::Language,
        ModuleType::Sandbox,
        ModuleType::Interceptor,
        ModuleType::Proxy,
        ModuleType::Hook,
    ];

    for module_type in types {
        let m = NewModule {
            type_: module_type,
            ..valid_new_module()
        };
        assert!(m.validate().is_ok());
    }
}
