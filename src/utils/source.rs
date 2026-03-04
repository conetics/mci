use crate::errors;
use anyhow::Result;
use std::path;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Http(String),
    File(path::PathBuf),
}

impl Source {
    pub fn parse(input: &str) -> Result<Self, errors::AppError> {
        if Self::has_uri_scheme(input) {
            return Self::parse_url(input);
        }
        Self::parse_file_path(input)
    }

    fn has_uri_scheme(input: &str) -> bool {
        let Some(colon_pos) = input.find(':') else {
            return false;
        };
        let scheme = &input[..colon_pos];
        if scheme.contains('/') {
            return false;
        }
        let mut chars = scheme.chars();
        let Some(first) = chars.next() else {
            return false;
        };
        first.is_ascii_alphabetic()
            && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    }

    fn parse_url(input: &str) -> Result<Self, errors::AppError> {
        let url = Url::parse(input).map_err(|_| errors::AppError::invalid_source(input))?;

        match url.scheme() {
            "http" | "https" => Ok(Self::Http(input.to_string())),
            "file" => Self::parse_file_url(url, input),
            scheme => Err(errors::AppError::unsupported_scheme(scheme)),
        }
    }

    fn parse_file_url(url: Url, input: &str) -> Result<Self, errors::AppError> {
        let path = url.to_file_path().map_err(|()| {
            errors::AppError::invalid_source(format!("Cannot convert file URL to path: {}", input))
        })?;

        Self::validate_and_create_file_source(path)
    }

    fn parse_file_path(input: &str) -> Result<Self, errors::AppError> {
        let path = path::Path::new(input);

        if path.components().count() == 0 {
            return Err(errors::AppError::invalid_source(input));
        }

        Self::validate_and_create_file_source(path.to_path_buf())
    }

    fn validate_and_create_file_source(path: path::PathBuf) -> Result<Self, errors::AppError> {
        if !path.exists() {
            return Err(errors::AppError::not_found(format!(
                "File does not exist: {}",
                path.display()
            )));
        }

        if !path.is_file() {
            return Err(errors::AppError::bad_request(format!(
                "Path is not a file: {}",
                path.display()
            )));
        }

        Ok(Self::File(path))
    }

    pub fn as_path(&self) -> Option<&path::Path> {
        match self {
            Self::File(path) => Some(path),
            Self::Http(_) => None,
        }
    }

    pub fn as_url(&self) -> Option<&str> {
        match self {
            Self::Http(url) => Some(url),
            Self::File(_) => None,
        }
    }
}

#[cfg(test)]
#[path = "source_tests.rs"]
mod test;
