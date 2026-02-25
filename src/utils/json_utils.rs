use anyhow::{Context, Result};
use json_patch::Patch;
use serde_json::Value as JsonValue;

pub fn apply_patch(document: &JsonValue, operations: &Patch) -> Result<JsonValue> {
    let mut patched = document.clone();
    json_patch::patch(&mut patched, operations).context("Failed to apply JSON patch")?;
    Ok(patched)
}

#[cfg(test)]
#[path = "json_utils_tests.rs"]
mod tests;
