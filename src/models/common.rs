use crate::utils;
use std::borrow;
use validator::ValidationError;

pub(super) fn validate_digest(digest: &str) -> Result<(), ValidationError> {
    let (algorithm, hash) = digest.split_once(':').ok_or_else(|| {
        let mut error = ValidationError::new("invalid_digest_format");
        error.add_param(borrow::Cow::from("value"), &digest);
        error
    })?;
    let hash_regex = match algorithm {
        "sha256" => &utils::regex::SHA256,
        _ => {
            let mut error = ValidationError::new("unsupported_digest_algorithm");
            error.add_param(borrow::Cow::from("value"), &digest);
            error.add_param(borrow::Cow::from("algorithm"), &algorithm);
            return Err(error);
        }
    };

    if hash_regex.is_match(hash) {
        Ok(())
    } else {
        let mut error = ValidationError::new("invalid_hash_format");
        error.add_param(borrow::Cow::from("value"), &digest);
        error.add_param(borrow::Cow::from("algorithm"), &algorithm);
        Err(error)
    }
}

#[cfg(test)]
#[path = "common_tests.rs"]
mod tests;
