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
