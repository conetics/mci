use regex::Regex;
use std::sync;

pub static NAMESPACE_ID: sync::LazyLock<Regex> =
    sync::LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_.-]+$").unwrap());

pub static TYPE_IDENTIFIER: sync::LazyLock<Regex> =
    sync::LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_-]+$").unwrap());

pub static SHA256: sync::LazyLock<Regex> =
    sync::LazyLock::new(|| Regex::new(r"^[a-f0-9]{64}$").unwrap());

#[cfg(test)]
#[path = "regex_tests.rs"]
mod tests;
