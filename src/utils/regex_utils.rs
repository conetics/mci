use regex::Regex;
use std::sync::LazyLock;

pub static NAMESPACE_ID_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_.-]+$").unwrap());

pub static TYPE_IDENTIFIER_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_-]+$").unwrap());

pub static SHA256_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-f0-9]{64}$").unwrap());

#[cfg(test)]
mod tests {
    use super::*;

    fn is_valid_namespace_id(id: &str) -> bool {
        NAMESPACE_ID_REGEX.is_match(id)
    }

    fn is_valid_type_identifier(id: &str) -> bool {
        TYPE_IDENTIFIER_REGEX.is_match(id)
    }

    fn is_valid_sha256(hash: &str) -> bool {
        SHA256_REGEX.is_match(hash)
    }

    #[test]
    fn test_namespace_id() {
        assert!(is_valid_namespace_id("my-namespace"));
        assert!(is_valid_namespace_id("my_namespace"));
        assert!(is_valid_namespace_id("my.namespace"));
        assert!(is_valid_namespace_id("namespace123"));
        assert!(is_valid_namespace_id("a"));

        assert!(!is_valid_namespace_id("my namespace"));
        assert!(!is_valid_namespace_id("my@namespace"));
        assert!(!is_valid_namespace_id(""));
    }

    #[test]
    fn test_type_identifier() {
        assert!(is_valid_type_identifier("type"));
        assert!(is_valid_type_identifier("MyType"));
        assert!(is_valid_type_identifier("a"));
        assert!(is_valid_type_identifier("type123"));
        assert!(is_valid_type_identifier("my-type"));
        assert!(is_valid_type_identifier("my_type"));

        assert!(!is_valid_type_identifier("my.type"));
        assert!(!is_valid_type_identifier("my type"));
        assert!(!is_valid_type_identifier("my@type"));
        assert!(!is_valid_type_identifier(""));
    }

    #[test]
    fn test_sha256_hash() {
        assert!(is_valid_sha256(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));

        assert!(!is_valid_sha256("abc"));
        assert!(!is_valid_sha256(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85"
        ));

        assert!(!is_valid_sha256(
            "g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
        assert!(!is_valid_sha256(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85!"
        ));
        assert!(!is_valid_sha256(
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        ));
        assert!(!is_valid_sha256(""));
    }
}
