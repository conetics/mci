use super::*;

#[cfg(test)]
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
}
