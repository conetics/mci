use crate::models::processes::{ProcessInstance, ProcessPhase};
use crate::schema;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = schema::routines)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Routine {
    pub pid: Uuid,
    pub name: String,
    pub description: String,
    pub environment: String,
    pub env_config: JsonValue,
    pub priority: i16,
    pub timeout_ms: Option<i64>,
    pub retry_max_attempts: i16,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Routine {
    pub fn into_process(self) -> ProcessInstance {
        ProcessInstance {
            pid: self.pid,
            name: self.name,
            description: self.description,
            environment: self.environment,
            env_config: self.env_config,
            priority: self.priority as u8,
            timeout_ms: self.timeout_ms.map(|v| v as u64),
            retry_max_attempts: self.retry_max_attempts as u8,
            phase: ProcessPhase::Idle,
            exit_status: None,
            attempt: 0,
            started_at: None,
            finished_at: None,
            channels: None,
            created_at: self.created_at,
        }
    }

    pub fn from_process(process: &ProcessInstance) -> Self {
        Self {
            pid: process.pid,
            name: process.name.clone(),
            description: process.description.clone(),
            environment: process.environment.clone(),
            env_config: process.env_config.clone(),
            priority: process.priority as i16,
            timeout_ms: process.timeout_ms.map(|v| v as i64),
            retry_max_attempts: process.retry_max_attempts as i16,
            created_at: process.created_at,
            updated_at: process.created_at,
        }
    }
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = schema::routines)]
pub struct NewRoutine {
    pub pid: Uuid,
    pub name: String,
    pub description: String,
    pub environment: String,
    pub env_config: JsonValue,
    pub priority: i16,
    pub timeout_ms: Option<i64>,
    pub retry_max_attempts: Option<i16>,
}

#[derive(Debug, Clone, AsChangeset, Default)]
#[diesel(table_name = schema::routines)]
pub struct RoutineChangeset {
    pub name: Option<String>,
    pub description: Option<String>,
    pub environment: Option<String>,
    pub env_config: Option<JsonValue>,
    pub priority: Option<i16>,
    pub timeout_ms: Option<Option<i64>>,
    pub retry_max_attempts: Option<i16>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct NewRoutineRequest {
    #[validate(length(min = 3, max = 64))]
    pub name: String,
    #[validate(length(max = 500))]
    pub description: Option<String>,
    #[validate(length(min = 3, max = 64))]
    pub environment: String,
    pub env_config: Option<JsonValue>,
    pub priority: Option<u8>,
    pub timeout_ms: Option<u64>,
    #[validate(range(min = 1))]
    pub retry_max_attempts: Option<u8>,
}

impl NewRoutineRequest {
    pub fn into_new_routine(self, pid: Uuid) -> NewRoutine {
        NewRoutine {
            pid,
            name: self.name,
            description: self.description.unwrap_or_default(),
            environment: self.environment,
            env_config: self
                .env_config
                .unwrap_or_else(|| JsonValue::Object(Default::default())),
            priority: self.priority.unwrap_or(128) as i16,
            timeout_ms: self.timeout_ms.map(|v| v as i64),
            retry_max_attempts: self.retry_max_attempts.map(|v| v as i16),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct UpdateRoutineRequest {
    #[validate(length(min = 3, max = 64))]
    pub name: Option<String>,
    #[validate(length(max = 500))]
    pub description: Option<String>,
    #[validate(length(min = 3, max = 64))]
    pub environment: Option<String>,
    pub env_config: Option<JsonValue>,
    pub priority: Option<u8>,
    pub timeout_ms: Option<Option<u64>>,
    pub retry_max_attempts: Option<u8>,
}

impl UpdateRoutineRequest {
    pub fn into_changeset(self) -> RoutineChangeset {
        RoutineChangeset {
            name: self.name,
            description: self.description,
            environment: self.environment,
            env_config: self.env_config,
            priority: self.priority.map(|v| v as i16),
            timeout_ms: self.timeout_ms.map(|opt| opt.map(|v| v as i64)),
            retry_max_attempts: self.retry_max_attempts.map(|v| v as i16),
        }
    }
}

#[cfg(test)]
#[path = "routines_tests.rs"]
mod tests;
