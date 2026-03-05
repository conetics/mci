use super::*;

mod test_validate_digest {
    use super::*;

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
    fn validate_digest_rejects_hash_too_short() {
        let digest = "sha256:abc";
        let result = validate_digest(digest);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "invalid_hash_format");
    }

    #[test]
    fn validate_digest_rejects_hash_too_long() {
        let digest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855abc";
        let result = validate_digest(digest);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "invalid_hash_format");
    }

    #[test]
    fn validate_digest_rejects_uppercase_hash() {
        let digest = "sha256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
        let result = validate_digest(digest);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "invalid_hash_format");
    }

    #[test]
    fn validate_digest_rejects_hash_with_special_chars() {
        let digest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85@";
        let result = validate_digest(digest);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "invalid_hash_format");
    }

    #[test]
    fn validate_digest_accepts_all_lowercase_hex() {
        let digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(validate_digest(digest).is_ok());
    }

    #[test]
    fn validate_digest_error_includes_algorithm_param() {
        let digest = "sha256:invalid";
        let result = validate_digest(digest);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err
            .params
            .contains_key(&std::borrow::Cow::from("algorithm")));
    }

    #[test]
    fn validate_digest_error_includes_value_param() {
        let digest = "sha256:invalid";
        let result = validate_digest(digest);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.params.contains_key(&std::borrow::Cow::from("value")));
    }

    #[test]
    fn validate_digest_rejects_empty_algorithm() {
        let digest = ":e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let result = validate_digest(digest);
        assert!(result.is_err());
    }

    #[test]
    fn validate_digest_rejects_empty_hash() {
        let digest = "sha256:";
        let result = validate_digest(digest);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "invalid_hash_format");
    }
}
