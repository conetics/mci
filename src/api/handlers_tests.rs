use super::*;
use validator::Validate;

#[test]
fn install_definition_request_accepts_valid_url() {
    let request = InstallDefinitionRequest {
        source: "https://example.com/definition.json".to_string(),
    };

    assert!(request.validate().is_ok());
}

#[test]
fn install_definition_request_accepts_http_url() {
    let request = InstallDefinitionRequest {
        source: "http://example.com/definition.json".to_string(),
    };

    assert!(request.validate().is_ok());
}

#[test]
fn install_definition_request_rejects_invalid_url() {
    let request = InstallDefinitionRequest {
        source: "not-a-valid-url".to_string(),
    };

    assert!(request.validate().is_err());
}

#[test]
fn install_definition_request_rejects_empty_string() {
    let request = InstallDefinitionRequest {
        source: "".to_string(),
    };

    assert!(request.validate().is_err());
}

#[test]
fn install_definition_request_accepts_url_with_query_params() {
    let request = InstallDefinitionRequest {
        source: "https://example.com/def.json?version=1.0&tag=latest".to_string(),
    };

    assert!(request.validate().is_ok());
}

#[test]
fn install_definition_request_accepts_url_with_port() {
    let request = InstallDefinitionRequest {
        source: "https://example.com:8080/definition.json".to_string(),
    };

    assert!(request.validate().is_ok());
}

#[test]
fn install_definition_request_accepts_localhost() {
    let request = InstallDefinitionRequest {
        source: "http://localhost:3000/def.json".to_string(),
    };

    assert!(request.validate().is_ok());
}

#[test]
fn install_definition_request_accepts_ip_address() {
    let request = InstallDefinitionRequest {
        source: "http://192.168.1.1/definition.json".to_string(),
    };

    assert!(request.validate().is_ok());
}

#[test]
fn install_definition_request_rejects_file_url() {
    let request = InstallDefinitionRequest {
        source: "file:///path/to/file.json".to_string(),
    };

    assert!(request.validate().is_err());
}

#[test]
fn install_definition_request_rejects_ftp_url() {
    let request = InstallDefinitionRequest {
        source: "ftp://example.com/definition.json".to_string(),
    };

    assert!(request.validate().is_err());
}

#[test]
fn install_definition_request_debug_format() {
    let request = InstallDefinitionRequest {
        source: "https://example.com/def.json".to_string(),
    };

    let debug_str = format!("{:?}", request);

    assert!(debug_str.contains("InstallDefinitionRequest"));
    assert!(debug_str.contains("https://example.com/def.json"));
}

#[test]
fn install_module_request_accepts_valid_url() {
    let request = InstallModuleRequest {
        source: "https://example.com/module.wasm".to_string(),
    };

    assert!(request.validate().is_ok());
}

#[test]
fn install_module_request_accepts_http_url() {
    let request = InstallModuleRequest {
        source: "http://example.com/module.wasm".to_string(),
    };

    assert!(request.validate().is_ok());
}

#[test]
fn install_module_request_rejects_invalid_url() {
    let request = InstallModuleRequest {
        source: "not-a-valid-url".to_string(),
    };

    assert!(request.validate().is_err());
}

#[test]
fn install_module_request_rejects_empty_string() {
    let request = InstallModuleRequest {
        source: "".to_string(),
    };

    assert!(request.validate().is_err());
}

#[test]
fn install_module_request_accepts_url_with_query_params() {
    let request = InstallModuleRequest {
        source: "https://example.com/module.wasm?version=2.0".to_string(),
    };

    assert!(request.validate().is_ok());
}

#[test]
fn install_module_request_accepts_url_with_fragment() {
    let request = InstallModuleRequest {
        source: "https://example.com/module.wasm#section".to_string(),
    };

    assert!(request.validate().is_ok());
}

#[test]
fn install_module_request_accepts_ipv6_url() {
    let request = InstallModuleRequest {
        source: "http://[::1]:8080/module.wasm".to_string(),
    };

    assert!(request.validate().is_ok());
}

#[test]
fn install_module_request_rejects_relative_url() {
    let request = InstallModuleRequest {
        source: "/relative/path/module.wasm".to_string(),
    };

    assert!(request.validate().is_err());
}

#[test]
fn install_module_request_rejects_protocol_relative_url() {
    let request = InstallModuleRequest {
        source: "//example.com/module.wasm".to_string(),
    };

    assert!(request.validate().is_err());
}

#[test]
fn install_module_request_debug_format() {
    let request = InstallModuleRequest {
        source: "https://example.com/module.wasm".to_string(),
    };

    let debug_str = format!("{:?}", request);

    assert!(debug_str.contains("InstallModuleRequest"));
    assert!(debug_str.contains("https://example.com/module.wasm"));
}

#[test]
fn install_definition_request_accepts_long_url() {
    let long_path = "a".repeat(1000);
    let request = InstallDefinitionRequest {
        source: format!("https://example.com/{}.json", long_path),
    };

    assert!(request.validate().is_ok());
}

#[test]
fn install_module_request_accepts_long_url() {
    let long_path = "b".repeat(1000);
    let request = InstallModuleRequest {
        source: format!("https://example.com/{}.wasm", long_path),
    };

    assert!(request.validate().is_ok());
}

#[test]
fn install_definition_request_accepts_url_with_auth() {
    let request = InstallDefinitionRequest {
        source: "https://user:pass@example.com/def.json".to_string(),
    };

    assert!(request.validate().is_ok());
}

#[test]
fn install_module_request_accepts_url_with_auth() {
    let request = InstallModuleRequest {
        source: "https://user:pass@example.com/module.wasm".to_string(),
    };

    assert!(request.validate().is_ok());
}