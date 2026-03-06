use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tokio::sync::broadcast;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProcessPhase {
    Idle,
    Queued,
    Running,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExitStatus {
    Success,
    Failed,
}

#[derive(Debug, Clone)]
pub struct OutputChunk(pub bytes::Bytes);

#[derive(Debug)]
pub struct ProcessChannels {
    pub stdout: broadcast::Sender<OutputChunk>,
    pub stderr: broadcast::Sender<OutputChunk>,
    pub output: Option<JsonValue>,
}

impl ProcessChannels {
    pub fn new(capacity: usize) -> Self {
        Self {
            stdout: broadcast::channel(capacity).0,
            stderr: broadcast::channel(capacity).0,
            output: None,
        }
    }

    pub fn subscribe_stdout(&self) -> broadcast::Receiver<OutputChunk> {
        self.stdout.subscribe()
    }

    pub fn subscribe_stderr(&self) -> broadcast::Receiver<OutputChunk> {
        self.stderr.subscribe()
    }
}

#[derive(Debug)]
pub struct ProcessInstance {
    pub pid: Uuid,
    pub name: String,
    pub description: String,
    pub environment: String,
    pub env_config: JsonValue,
    pub priority: u8,
    pub timeout_ms: Option<u64>,
    pub retry_max_attempts: u8,
    pub phase: ProcessPhase,
    pub exit_status: Option<ExitStatus>,
    pub attempt: u8,
    pub channels: Option<ProcessChannels>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ProcessRequest {
    pub code: String,
    #[validate(length(min = 3, max = 64))]
    pub environment: String,
    pub env_config: Option<JsonValue>,
    #[validate(length(min = 3, max = 64))]
    pub name: Option<String>,
    #[validate(length(max = 500))]
    pub description: Option<String>,
    pub timeout_ms: Option<u64>,
    pub priority: Option<u8>,
    pub retry_max_attempts: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessResponse {
    pub pid: String,
    pub name: String,
    pub phase: ProcessPhase,
    pub exit_status: Option<ExitStatus>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ForkOverrides {
    #[validate(length(min = 3, max = 64))]
    pub name: Option<String>,
    #[validate(length(max = 500))]
    pub description: Option<String>,
    pub code: Option<String>,
    #[validate(length(min = 3, max = 64))]
    pub environment: Option<String>,
    pub env_config: Option<JsonValue>,
    pub timeout_ms: Option<Option<u64>>,
    pub priority: Option<u8>,
    pub retry_max_attempts: Option<u8>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(
    tag = "signal",
    content = "payload",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
pub enum Signal {
    Fork(Option<ForkOverrides>),
    Run,
    Lint,
    Save,
    Kill,
    Evict,
}

#[cfg(test)]
#[path = "processes_tests.rs"]
mod tests;
