use super::*;
use serde_json::json;

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

fn valid_new_definition() -> NewDefinition {
    NewDefinition {
        id: "my-def-id".into(),
        type_: "api-type".into(),
        name: "My Definition".into(),
        description: "A test definition.".into(),
        digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
        source_url: None,
    }
}

#[test]
fn new_definition_valid_passes_validation() {
    use validator::Validate;
    assert!(valid_new_definition().validate().is_ok());
}

#[test]
fn new_definition_id_too_short_rejected() {
    use validator::Validate;
    let d = NewDefinition {
        id: "ab".into(),
        ..valid_new_definition()
    };
    assert!(d.validate().is_err());
}

#[test]
fn new_definition_id_too_long_rejected() {
    use validator::Validate;
    let d = NewDefinition {
        id: "a".repeat(65),
        ..valid_new_definition()
    };
    assert!(d.validate().is_err());
}

#[test]
fn new_definition_id_rejects_invalid_chars() {
    use validator::Validate;
    let d = NewDefinition {
        id: "bad@id".into(),
        ..valid_new_definition()
    };
    assert!(d.validate().is_err());
}

#[test]
fn new_definition_id_accepts_dots_and_dashes() {
    use validator::Validate;
    let d = NewDefinition {
        id: "my.def-id".into(),
        ..valid_new_definition()
    };
    assert!(d.validate().is_ok());
}

#[test]
fn new_definition_type_rejects_dots() {
    use validator::Validate;
    let d = NewDefinition {
        type_: "api.type".into(),
        ..valid_new_definition()
    };
    assert!(d.validate().is_err());
}

#[test]
fn new_definition_name_too_short_rejected() {
    use validator::Validate;
    let d = NewDefinition {
        name: "ab".into(),
        ..valid_new_definition()
    };
    assert!(d.validate().is_err());
}

#[test]
fn new_definition_description_too_long_rejected() {
    use validator::Validate;
    let d = NewDefinition {
        description: "a".repeat(501),
        ..valid_new_definition()
    };
    assert!(d.validate().is_err());
}

#[test]
fn new_definition_invalid_digest_rejected() {
    use validator::Validate;
    let d = NewDefinition {
        digest: "not-a-valid-digest".into(),
        ..valid_new_definition()
    };
    assert!(d.validate().is_err());
}

#[test]
fn new_definition_invalid_source_url_rejected() {
    use validator::Validate;
    let d = NewDefinition {
        source_url: Some("not-a-url".into()),
        ..valid_new_definition()
    };
    assert!(d.validate().is_err());
}

#[test]
fn new_definition_valid_source_url_passes() {
    use validator::Validate;
    let d = NewDefinition {
        source_url: Some("https://example.com/registry.json".into()),
        ..valid_new_definition()
    };
    assert!(d.validate().is_ok());
}

#[test]
fn update_definition_request_allows_all_none() {
    let req = UpdateDefinitionRequest {
        is_enabled: None,
        type_: None,
        name: None,
        description: None,
        source_url: None,
    };
    assert!(req.validate().is_ok());
}

#[test]
fn update_definition_request_type_too_short_rejected() {
    use validator::Validate;
    let req = UpdateDefinitionRequest {
        type_: Some("ab".into()),
        is_enabled: None,
        name: None,
        description: None,
        source_url: None,
    };
    assert!(req.validate().is_err());
}

#[test]
fn update_definition_request_name_too_short_rejected() {
    use validator::Validate;
    let req = UpdateDefinitionRequest {
        name: Some("ab".into()),
        is_enabled: None,
        type_: None,
        description: None,
        source_url: None,
    };
    assert!(req.validate().is_err());
}

#[test]
fn update_definition_request_description_too_long_rejected() {
    use validator::Validate;
    let req = UpdateDefinitionRequest {
        description: Some("a".repeat(501)),
        is_enabled: None,
        type_: None,
        name: None,
        source_url: None,
    };
    assert!(req.validate().is_err());
}

#[test]
fn update_definition_request_invalid_source_url_rejected() {
    use validator::Validate;
    let req = UpdateDefinitionRequest {
        source_url: Some("not-a-url".into()),
        is_enabled: None,
        type_: None,
        name: None,
        description: None,
    };
    assert!(req.validate().is_err());
}

#[test]
fn update_definition_allows_setting_enabled() {
    let update = UpdateDefinition {
        is_enabled: Some(false),
        ..Default::default()
    };
    assert_eq!(update.is_enabled, Some(false));
}

#[test]
fn new_definition_type_accepts_valid_identifier() {
    use validator::Validate;
    let d = NewDefinition {
        type_: "valid-type".into(),
        ..valid_new_definition()
    };
    assert!(d.validate().is_ok());
}

#[test]
fn new_definition_id_accepts_namespace_format() {
    use validator::Validate;
    let d = NewDefinition {
        id: "namespace.sub.item".into(),
        ..valid_new_definition()
    };
    assert!(d.validate().is_ok());
}

#[test]
fn new_definition_description_can_be_empty() {
    use validator::Validate;
    let d = NewDefinition {
        description: "".into(),
        ..valid_new_definition()
    };
    assert!(d.validate().is_ok());
}

#[test]
fn new_definition_source_url_none_is_valid() {
    use validator::Validate;
    let d = NewDefinition {
        source_url: None,
        ..valid_new_definition()
    };
    assert!(d.validate().is_ok());
}

#[test]
fn definition_has_all_required_fields() {
    let def = Definition {
        id: "test-id".into(),
        type_: "test-type".into(),
        is_enabled: true,
        name: "Test Name".into(),
        description: "Test Description".into(),
        digest: "sha256:abc123".into(),
        source_url: Some("https://example.com".into()),
    };
    assert_eq!(def.id, "test-id");
    assert_eq!(def.type_, "test-type");
    assert!(def.is_enabled);
}

#[test]
fn update_definition_request_from_trait() {
    let req = UpdateDefinitionRequest {
        is_enabled: Some(true),
        type_: Some("new-type".to_string()),
        name: Some("New Name".to_string()),
        description: Some("New Description".to_string()),
        source_url: Some("https://example.com".to_string()),
    };
    let update: UpdateDefinition = req.into();
    assert_eq!(update.is_enabled, Some(true));
    assert_eq!(update.type_, Some("new-type".to_string()));
    assert_eq!(update.name, Some("New Name".to_string()));
    assert_eq!(update.digest, None);
}
