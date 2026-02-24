use crate::{
    schema::{definitions, modules, sql_types},
    utils::regex_utils,
};
use diesel::{
    deserialize::{self, FromSql},
    pg::{Pg, PgValue},
    prelude::*,
    serialize::{self, IsNull, Output, ToSql},
    AsExpression, FromSqlRow,
};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, io::Write};
use validator::{Validate, ValidationError};

fn validate_digest(digest: &str) -> Result<(), ValidationError> {
    let (algorithm, hash) = digest.split_once(':').ok_or_else(|| {
        let mut error = ValidationError::new("invalid_digest_format");
        error.add_param(Cow::from("value"), &digest);
        error
    })?;
    let hash_regex = match algorithm {
        "sha256" => &regex_utils::SHA256,
        _ => {
            let mut error = ValidationError::new("unsupported_digest_algorithm");
            error.add_param(Cow::from("value"), &digest);
            error.add_param(Cow::from("algorithm"), &algorithm);
            return Err(error);
        }
    };

    if hash_regex.is_match(hash) {
        Ok(())
    } else {
        let mut error = ValidationError::new("invalid_hash_format");
        error.add_param(Cow::from("value"), &digest);
        error.add_param(Cow::from("algorithm"), &algorithm);
        Err(error)
    }
}

#[derive(Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = definitions)]
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
#[diesel(table_name = definitions)]
pub struct NewDefinition {
    #[validate(length(min = 3, max = 64), regex(path = *regex_utils::NAMESPACE_ID))]
    pub id: String,

    #[validate(length(min = 3, max = 64), regex(path = *regex_utils::TYPE_IDENTIFIER))]
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
#[diesel(table_name = definitions)]
pub struct UpdateDefinition {
    pub is_enabled: Option<bool>,

    #[validate(length(min = 3, max = 64), regex(path = *regex_utils::TYPE_IDENTIFIER))]
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

    #[validate(length(min = 3, max = 64), regex(path = *regex_utils::TYPE_IDENTIFIER))]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, AsExpression, FromSqlRow)]
#[diesel(sql_type = sql_types::ModuleType)]
#[serde(rename_all = "lowercase")]
pub enum ModuleType {
    Language,
    Sandbox,
    Interceptor,
    Proxy,
    Hook,
}

impl ToSql<sql_types::ModuleType, Pg> for ModuleType {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
        let value = match self {
            ModuleType::Language => "language",
            ModuleType::Sandbox => "sandbox",
            ModuleType::Interceptor => "interceptor",
            ModuleType::Proxy => "proxy",
            ModuleType::Hook => "hook",
        };
        out.write_all(value.as_bytes())?;
        Ok(IsNull::No)
    }
}

impl FromSql<sql_types::ModuleType, Pg> for ModuleType {
    fn from_sql(bytes: PgValue<'_>) -> deserialize::Result<Self> {
        match bytes.as_bytes() {
            b"language" => Ok(ModuleType::Language),
            b"sandbox" => Ok(ModuleType::Sandbox),
            b"interceptor" => Ok(ModuleType::Interceptor),
            b"proxy" => Ok(ModuleType::Proxy),
            b"hook" => Ok(ModuleType::Hook),
            _ => Err("Unrecognized enum variant for ModuleType".into()),
        }
    }
}

#[derive(Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = modules)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Module {
    pub id: String,
    pub type_: ModuleType,
    pub is_enabled: bool,
    pub name: String,
    pub description: String,
    pub digest: String,
    pub source_url: Option<String>,
}

#[derive(Insertable, Deserialize, Validate)]
#[diesel(table_name = modules)]
pub struct NewModule {
    #[validate(length(min = 3, max = 64), regex(path = *regex_utils::NAMESPACE_ID))]
    pub id: String,

    pub type_: ModuleType,

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
#[diesel(table_name = modules)]
pub struct UpdateModule {
    pub is_enabled: Option<bool>,

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
pub struct UpdateModuleRequest {
    pub is_enabled: Option<bool>,

    #[validate(length(min = 3, max = 64))]
    pub name: Option<String>,

    #[validate(length(max = 500))]
    pub description: Option<String>,

    #[validate(url)]
    pub source_url: Option<String>,
}

impl From<UpdateModuleRequest> for UpdateModule {
    fn from(req: UpdateModuleRequest) -> Self {
        UpdateModule {
            is_enabled: req.is_enabled,
            name: req.name,
            description: req.description,
            digest: None,
            source_url: req.source_url,
        }
    }
}

impl UpdateModuleRequest {
    pub fn into_changeset(self) -> UpdateModule {
        self.into()
    }
}

#[cfg(test)]
#[path = "models_tests.rs"]
mod tests;
