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
#[validate(schema(function = "validate_update_request"))]
pub struct UpdateDefinitionRequest {
    pub is_enabled: Option<bool>,

    #[validate(length(min = 3, max = 64), regex(path = *regex_utils::TYPE_IDENTIFIER))]
    pub type_: Option<String>,

    #[validate(length(min = 3, max = 64))]
    pub name: Option<String>,

    #[validate(length(max = 500))]
    pub description: Option<String>,

    #[validate(url)]
    pub file_url: Option<String>,

    #[validate(custom(function = "validate_digest"))]
    pub digest: Option<String>,

    #[validate(url)]
    pub source_url: Option<String>,
}

impl UpdateDefinitionRequest {
    pub fn into_changeset(self) -> UpdateDefinition {
        UpdateDefinition {
            is_enabled: self.is_enabled,
            type_: self.type_,
            name: self.name,
            description: self.description,
            digest: self.digest,
            source_url: self.source_url,
        }
    }
}

fn validate_digest_with_file_url(
    digest: &Option<String>,
    file_url: &Option<String>,
) -> Result<(), ValidationError> {
    if digest.is_some() && file_url.is_none() {
        let mut error = ValidationError::new("digest_requires_file_url");
        error.message = Some("digest cannot be updated without also providing file_url".into());
        return Err(error);
    }
    Ok(())
}

fn validate_update_request(req: &UpdateDefinitionRequest) -> Result<(), ValidationError> {
    validate_digest_with_file_url(&req.digest, &req.file_url)
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
#[validate(schema(function = "validate_module_update_request"))]
pub struct UpdateModuleRequest {
    pub is_enabled: Option<bool>,

    #[validate(length(min = 3, max = 64))]
    pub name: Option<String>,

    #[validate(length(max = 500))]
    pub description: Option<String>,

    #[validate(url)]
    pub file_url: Option<String>,

    #[validate(custom(function = "validate_digest"))]
    pub digest: Option<String>,

    #[validate(url)]
    pub source_url: Option<String>,
}

impl UpdateModuleRequest {
    pub fn into_changeset(self) -> UpdateModule {
        UpdateModule {
            is_enabled: self.is_enabled,
            name: self.name,
            description: self.description,
            digest: self.digest,
            source_url: self.source_url,
        }
    }
}

fn validate_module_update_request(req: &UpdateModuleRequest) -> Result<(), ValidationError> {
    validate_digest_with_file_url(&req.digest, &req.file_url)
}

#[derive(Serialize)]
pub struct Build {
    pub id: i32,
    pub name: String,
    pub status: String,
}

#[cfg(test)]
#[path = "models_tests.rs"]
mod tests;
