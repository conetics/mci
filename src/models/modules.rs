use crate::schema;
use crate::utils;
use diesel::deserialize;
use diesel::pg;
use diesel::serialize;
use diesel::{AsChangeset, AsExpression, FromSqlRow, Insertable, Queryable, Selectable};
use serde::{Deserialize, Serialize};
use std::borrow;
use std::io::Write;
use validator::{Validate, ValidationError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, AsExpression, FromSqlRow)]
#[diesel(sql_type = schema::sql_types::ModuleType)]
#[serde(rename_all = "lowercase")]
pub enum ModuleType {
    Language,
    Sandbox,
    Interceptor,
    Proxy,
    Hook,
}

impl serialize::ToSql<schema::sql_types::ModuleType, pg::Pg> for ModuleType {
    fn to_sql<'b>(&'b self, out: &mut serialize::Output<'b, '_, pg::Pg>) -> serialize::Result {
        let value = match self {
            ModuleType::Language => "language",
            ModuleType::Sandbox => "sandbox",
            ModuleType::Interceptor => "interceptor",
            ModuleType::Proxy => "proxy",
            ModuleType::Hook => "hook",
        };
        out.write_all(value.as_bytes())?;
        Ok(serialize::IsNull::No)
    }
}

impl deserialize::FromSql<schema::sql_types::ModuleType, pg::Pg> for ModuleType {
    fn from_sql(bytes: pg::PgValue<'_>) -> deserialize::Result<Self> {
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

fn validate_digest(digest: &str) -> Result<(), ValidationError> {
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

#[derive(Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = schema::modules)]
#[diesel(check_for_backend(pg::Pg))]
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
#[diesel(table_name = schema::modules)]
pub struct NewModule {
    #[validate(length(min = 3, max = 64), regex(path = *utils::regex::NAMESPACE_ID))]
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
#[diesel(table_name = schema::modules)]
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
#[path = "modules_tests.rs"]
mod tests;
