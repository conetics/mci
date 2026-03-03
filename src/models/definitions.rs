use super::common::validate_digest;
use crate::schema;
use crate::utils::regex;
use diesel::{AsChangeset, Insertable, Queryable, Selectable};
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = schema::definitions)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Definition {
    pub id: String,
    pub type_: String,
    pub is_enabled: bool,
    pub name: String,
    pub description: String,
    pub digest: String,
    pub source_url: Option<String>,
}

#[derive(Insertable, Deserialize, Validate)]
#[diesel(table_name = schema::definitions)]
pub struct NewDefinition {
    #[validate(length(min = 3, max = 64), regex(path = *regex::NAMESPACE_ID))]
    pub id: String,
    #[validate(length(min = 3, max = 64), regex(path = *regex::TYPE_IDENTIFIER))]
    pub type_: String,
    #[validate(length(min = 3, max = 64))]
    pub name: String,
    #[validate(length(max = 500))]
    pub description: String,
    #[validate(custom(function = "validate_digest"))]
    pub digest: String,
    #[validate(url)]
    pub source_url: Option<String>,
}

#[derive(AsChangeset, Default, Deserialize, Validate)]
#[diesel(table_name = schema::definitions)]
pub struct UpdateDefinition {
    pub is_enabled: Option<bool>,
    #[validate(length(min = 3, max = 64), regex(path = *regex::TYPE_IDENTIFIER))]
    pub type_: Option<String>,
    #[validate(length(min = 3, max = 64))]
    pub name: Option<String>,
    #[validate(length(max = 500))]
    pub description: Option<String>,
    #[validate(custom(function = "validate_digest"))]
    pub digest: Option<String>,
    #[validate(url)]
    pub source_url: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct UpdateDefinitionRequest {
    pub is_enabled: Option<bool>,
    #[validate(length(min = 3, max = 64), regex(path = *regex::TYPE_IDENTIFIER))]
    pub type_: Option<String>,
    #[validate(length(min = 3, max = 64))]
    pub name: Option<String>,
    #[validate(length(max = 500))]
    pub description: Option<String>,
    #[validate(url)]
    pub source_url: Option<String>,
}

impl From<UpdateDefinitionRequest> for UpdateDefinition {
    fn from(req: UpdateDefinitionRequest) -> Self {
        UpdateDefinition {
            is_enabled: req.is_enabled,
            type_: req.type_,
            name: req.name,
            description: req.description,
            digest: None,
            source_url: req.source_url,
        }
    }
}

impl UpdateDefinitionRequest {
    pub fn into_changeset(self) -> UpdateDefinition {
        self.into()
    }
}

#[cfg(test)]
#[path = "definitions_tests.rs"]
mod tests;
