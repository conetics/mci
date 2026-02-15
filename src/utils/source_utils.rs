use crate::errors::AppError;
use anyhow::Result;
use serde::Deserialize;
use std::path::Path;
use url::Url;

#[derive(Debug, Deserialize)]
pub enum SortBy {
    Id,
    Type,
    Name,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefinitionSource {
    Http(String),
    File(String),
}

impl DefinitionSource {
    pub fn parse(input: &str) -> Result<Self, AppError> {
        if input.contains("://") {
            match Url::parse(input) {
                Ok(url) => match url.scheme() {
                    "http" | "https" => Ok(Self::Http(input.to_string())),
                    "file" => Ok(Self::File(input.to_string())),
                    scheme => Err(AppError::unsupported_scheme(scheme)),
                },
                Err(_) => Err(AppError::invalid_definition_source(input)),
            }
        } else {
            let path = Path::new(input);
            if path.components().count() > 0 {
                Ok(Self::File(input.to_string()))
            } else {
                Err(AppError::invalid_definition_source(input))
            }
        }
    }
}

mod test {
    use super::*;

    #[test]
    fn test_http_url() {
        let result = DefinitionSource::parse("http://example.com/definition.json");
        assert_eq!(
            result.unwrap(),
            DefinitionSource::Http("http://example.com/definition.json".to_string())
        );
    }

    #[test]
    fn test_https_url() {
        let result = DefinitionSource::parse("https://example.com/definition.json");
        assert_eq!(
            result.unwrap(),
            DefinitionSource::Http("https://example.com/definition.json".to_string())
        );
    }

    #[test]
    fn test_file_url() {
        let result = DefinitionSource::parse("file:///path/to/definition.json");
        assert_eq!(
            result.unwrap(),
            DefinitionSource::File("file:///path/to/definition.json".to_string())
        );
    }

    #[test]
    fn test_relative_path() {
        let result = DefinitionSource::parse("./definitions/my-def.json");
        assert_eq!(
            result.unwrap(),
            DefinitionSource::File("./definitions/my-def.json".to_string())
        );
    }

    #[test]
    fn test_relative_path_without_dot() {
        let result = DefinitionSource::parse("definitions/my-def.json");
        assert_eq!(
            result.unwrap(),
            DefinitionSource::File("definitions/my-def.json".to_string())
        );
    }

    #[test]
    fn test_absolute_path() {
        let result = DefinitionSource::parse("/etc/definitions/my-def.json");
        assert_eq!(
            result.unwrap(),
            DefinitionSource::File("/etc/definitions/my-def.json".to_string())
        );
    }

    #[test]
    fn test_absolute_path_windows() {
        let result = DefinitionSource::parse("C:\\definitions\\my-def.json");
        assert_eq!(
            result.unwrap(),
            DefinitionSource::File("C:\\definitions\\my-def.json".to_string())
        );
    }

    #[test]
    fn test_parent_directory_path() {
        let result = DefinitionSource::parse("../definitions/my-def.json");
        assert_eq!(
            result.unwrap(),
            DefinitionSource::File("../definitions/my-def.json".to_string())
        );
    }

    #[test]
    fn test_single_filename() {
        let result = DefinitionSource::parse("definition.json");
        assert_eq!(
            result.unwrap(),
            DefinitionSource::File("definition.json".to_string())
        );
    }

    #[test]
    fn test_current_directory() {
        let result = DefinitionSource::parse(".");
        assert_eq!(
            result.unwrap(),
            DefinitionSource::File(".".to_string())
        );
    }

    #[test]
    fn test_unsupported_scheme_ftp() {
        let result = DefinitionSource::parse("ftp://example.com/definition.json");
        assert!(result.is_err());

        match result.unwrap_err() {
            AppError::UnsupportedScheme(scheme) => assert_eq!(scheme, "ftp"),
            _ => panic!("Expected UnsupportedScheme error"),
        }
    }

    #[test]
    fn test_unsupported_scheme_s3() {
        let result = DefinitionSource::parse("s3://bucket/definition.json");
        assert!(result.is_err());

        match result.unwrap_err() {
            AppError::UnsupportedScheme(scheme) => assert_eq!(scheme, "s3"),
            _ => panic!("Expected UnsupportedScheme error"),
        }
    }

    #[test]
    fn test_empty_string_returns_error() {
        let result = DefinitionSource::parse("");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::InvalidDefinitionSource(_)));
    }

    #[test]
    fn test_http_url_with_query_params() {
        let result = DefinitionSource::parse("https://example.com/def.json?version=1.0");
        assert_eq!(
            result.unwrap(),
            DefinitionSource::Http("https://example.com/def.json?version=1.0".to_string())
        );
    }

    #[test]
    fn test_http_url_with_port() {
        let result = DefinitionSource::parse("http://localhost:8080/definition.json");
        assert_eq!(
            result.unwrap(),
            DefinitionSource::Http("http://localhost:8080/definition.json".to_string())
        );
    }
}
