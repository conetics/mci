use super::apply_patch;
use json_patch::Patch;
use serde_json::{from_value, json};

#[test]
fn returns_patched_configuration_without_mutating_original() {
    let config = json!({"host": "localhost", "port": 8080, "debug": false});
    let ops: Patch = from_value(json!([
        { "op": "replace", "path": "/port", "value": 9090 },
        { "op": "replace", "path": "/debug", "value": true }
    ]))
    .unwrap();

    let result = apply_patch(&config, &ops).unwrap();

    assert_eq!(
        result,
        json!({"host": "localhost", "port": 9090, "debug": true})
    );
    assert_eq!(
        config,
        json!({"host": "localhost", "port": 8080, "debug": false})
    );
}

#[test]
fn patches_empty_base_document() {
    let config = json!({});
    let ops: Patch = from_value(json!([
        { "op": "add", "path": "/enabled", "value": true },
        { "op": "add", "path": "/retries", "value": 3 }
    ]))
    .unwrap();

    let result = apply_patch(&config, &ops).unwrap();

    assert_eq!(result, json!({"enabled": true, "retries": 3}));
}

#[test]
fn propagates_error_on_invalid_operation() {
    let config = json!({"port": 8080});
    let ops: Patch = from_value(json!([
        { "op": "remove", "path": "/nonexistent" }
    ]))
    .unwrap();

    let err = apply_patch(&config, &ops).unwrap_err();

    assert!(
        err.to_string().contains("Failed to apply JSON patch"),
        "expected anyhow context in error, got: {}",
        err
    );
}
