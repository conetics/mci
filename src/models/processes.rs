use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tokio::sync::broadcast;
use uuid::Uuid;
use validator::Validate;

pub type Pid = Uuid;
pub type Priority = i16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProcessStatus {
    Idle,
    Queued,
    Running,
    Retrying,
    Success,
    Failed,
    TimedOut,
    Cancelled,
}

impl ProcessStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Success | Self::Failed | Self::TimedOut | Self::Cancelled)
    }

    pub fn is_cancellable(&self) -> bool {
        matches!(self, Self::Queued | Self::Running | Self::Retrying)
    }

    pub fn is_restartable(&self) -> bool {
        matches!(self, Self::Success | Self::Failed | Self::TimedOut | Self::Cancelled)
    }

    pub fn is_updatable(&self) -> bool {
        matches!(self, Self::Idle)
    }

    pub fn is_evictable(&self) -> bool {
        matches!(self, Self::Idle) || self.is_terminal()
    }
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
    pub pid: Pid,
    pub name: String,
    pub description: String,
    pub code_hash: String,
    pub environment: String,
    pub env_config: JsonValue,
    pub priority: Priority,
    pub timeout_ms: Option<u64>,
    pub retry_max_attempts: Option<u8>,
    pub status: ProcessStatus,
    pub attempt: Option<u8>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub channels: Option<ProcessChannels>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ProcessInstance {
    pub fn start(&mut self) {
        self.status = ProcessStatus::Queued;
        self.attempt = Some(0);
        self.channels = Some(ProcessChannels::new(128));
    }

    pub fn restart(&mut self) {
        self.status = ProcessStatus::Queued;
        self.attempt = Some(0);
        self.channels = Some(ProcessChannels::new(128));
        self.started_at = None;
        self.finished_at = None;
    }
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
    pub priority: Option<Priority>,
    pub retry_max_attempts: Option<u8>,
    pub lint: bool,
    pub save: bool,
    pub run: bool,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ProcessUpdateRequest {
    #[validate(length(min = 3, max = 64))]
    pub name: Option<String>,
    #[validate(length(max = 500))]
    pub description: Option<String>,
    pub code: Option<String>,
    #[validate(length(min = 3, max = 64))]
    pub environment: Option<String>,
    pub env_config: Option<JsonValue>,
    pub timeout_ms: Option<Option<u64>>,
    pub priority: Option<Priority>,
    pub retry_max_attempts: Option<Option<u8>>,
    pub lint: Option<bool>,
    pub save: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessResponse {
    pub pid: String,
    pub name: String,
    pub status: ProcessStatus,
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
    pub priority: Option<Priority>,
    pub retry_max_attempts: Option<Option<u8>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "signal", content = "payload", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Signal {
    Fork(Option<ForkOverrides>),
    Start,
    Kill,
    Evict,
    Restart,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignalResponse {
    pub pid: String,
    pub forked_pid: Option<String>,
    pub status: ProcessStatus,
}

#[cfg(test)]
#[path = "processes_tests.rs"]
mod tests;
