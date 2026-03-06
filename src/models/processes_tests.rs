use super::*;
use bytes::Bytes;
use chrono::{TimeZone, Utc};
use serde_json::json;
use validator::Validate;

fn valid_process_request() -> ProcessRequest {
    ProcessRequest {
        code: "fn main() {}".to_string(),
        environment: "python".to_string(),
        env_config: Some(json!({"version": "3.12"})),
        name: Some("example-process".to_string()),
        description: Some("Runs a sample process".to_string()),
        timeout_ms: Some(5_000),
        priority: Some(128),
        retry_max_attempts: Some(3),
        lint: true,
        save: true,
        run: false,
    }
}

fn valid_process_update_request() -> ProcessUpdateRequest {
    ProcessUpdateRequest {
        name: Some("updated-process".to_string()),
        description: Some("Updated description".to_string()),
        code: Some("print('updated')".to_string()),
        environment: Some("python".to_string()),
        env_config: Some(json!({"version": "3.13"})),
        timeout_ms: Some(Some(10_000)),
        priority: Some(64),
        retry_max_attempts: Some(Some(4)),
        lint: Some(false),
        save: Some(true),
    }
}

fn valid_fork_overrides() -> ForkOverrides {
    ForkOverrides {
        name: Some("forked-process".to_string()),
        description: Some("Forked description".to_string()),
        code: Some("print('forked')".to_string()),
        environment: Some("python".to_string()),
        env_config: Some(json!({"version": "3.11"})),
        timeout_ms: Some(Some(2_500)),
        priority: Some(32),
        retry_max_attempts: Some(Some(2)),
    }
}

fn sample_process_instance() -> ProcessInstance {
    ProcessInstance {
        pid: Uuid::nil(),
        name: "demo".to_string(),
        description: "demo process".to_string(),
        code_hash: "sha256:abc123".to_string(),
        environment: "python".to_string(),
        env_config: json!({"version": "3.12"}),
        priority: 42,
        timeout_ms: Some(3_000),
        retry_max_attempts: Some(2),
        status: ProcessStatus::Idle,
        attempt: None,
        started_at: Some(Utc.with_ymd_and_hms(2026, 3, 6, 1, 2, 3).unwrap()),
        finished_at: Some(Utc.with_ymd_and_hms(2026, 3, 6, 1, 5, 3).unwrap()),
        channels: None,
        created_at: Utc.with_ymd_and_hms(2026, 3, 6, 1, 0, 0).unwrap(),
        updated_at: Utc.with_ymd_and_hms(2026, 3, 6, 1, 1, 0).unwrap(),
    }
}

#[test]
fn process_status_helpers_match_expected_state_machine() {
    let cases = [
        (ProcessStatus::Idle, false, false, false, true, true),
        (ProcessStatus::Queued, false, true, false, false, false),
        (ProcessStatus::Running, false, true, false, false, false),
        (ProcessStatus::Retrying, false, true, false, false, false),
        (ProcessStatus::Success, true, false, true, false, true),
        (ProcessStatus::Failed, true, false, true, false, true),
        (ProcessStatus::TimedOut, true, false, true, false, true),
        (ProcessStatus::Cancelled, true, false, true, false, true),
    ];

    for (status, terminal, cancellable, restartable, updatable, evictable) in cases {
        assert_eq!(status.is_terminal(), terminal, "unexpected terminal state for {status:?}");
        assert_eq!(status.is_cancellable(), cancellable, "unexpected cancellable state for {status:?}");
        assert_eq!(status.is_restartable(), restartable, "unexpected restartable state for {status:?}");
        assert_eq!(status.is_updatable(), updatable, "unexpected updatable state for {status:?}");
        assert_eq!(status.is_evictable(), evictable, "unexpected evictable state for {status:?}");
    }
}

#[test]
fn process_status_serializes_and_deserializes_as_screaming_snake_case() {
    assert_eq!(serde_json::to_string(&ProcessStatus::TimedOut).unwrap(), "\"TIMED_OUT\"");
    assert_eq!(
        serde_json::from_str::<ProcessStatus>("\"CANCELLED\"").unwrap(),
        ProcessStatus::Cancelled
    );
}

#[test]
fn process_channels_initializes_without_output() {
    let channels = ProcessChannels::new(4);
    assert!(channels.output.is_none());
}

#[test]
fn process_channels_stdout_subscription_receives_sent_chunks() {
    let channels = ProcessChannels::new(4);
    let mut receiver = channels.subscribe_stdout();
    let expected = Bytes::from_static(b"stdout line");

    channels.stdout.send(OutputChunk(expected.clone())).unwrap();

    let OutputChunk(actual) = receiver.try_recv().unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn process_channels_stderr_subscription_receives_sent_chunks() {
    let channels = ProcessChannels::new(4);
    let mut receiver = channels.subscribe_stderr();
    let expected = Bytes::from_static(b"stderr line");

    channels.stderr.send(OutputChunk(expected.clone())).unwrap();

    let OutputChunk(actual) = receiver.try_recv().unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn process_instance_start_queues_process_and_creates_channels() {
    let mut process = sample_process_instance();
    process.status = ProcessStatus::Idle;
    process.attempt = None;
    process.channels = None;

    process.start();

    assert_eq!(process.status, ProcessStatus::Queued);
    assert_eq!(process.attempt, Some(0));
    assert!(process.channels.is_some());
    assert!(process.started_at.is_some());
    assert!(process.finished_at.is_some());
}

#[test]
fn process_instance_restart_resets_runtime_state() {
    let mut process = sample_process_instance();
    process.status = ProcessStatus::Failed;
    process.attempt = Some(3);
    process.channels = Some(ProcessChannels::new(8));

    process.restart();

    assert_eq!(process.status, ProcessStatus::Queued);
    assert_eq!(process.attempt, Some(0));
    assert!(process.channels.is_some());
    assert!(process.started_at.is_none());
    assert!(process.finished_at.is_none());
}

#[test]
fn process_request_valid_payload_passes_validation() {
    assert!(valid_process_request().validate().is_ok());
}

#[test]
fn process_request_environment_too_short_is_rejected() {
    let request = ProcessRequest {
        environment: "py".to_string(),
        ..valid_process_request()
    };

    assert!(request.validate().is_err());
}

#[test]
fn process_request_name_too_short_is_rejected() {
    let request = ProcessRequest {
        name: Some("ab".to_string()),
        ..valid_process_request()
    };

    assert!(request.validate().is_err());
}

#[test]
fn process_request_description_too_long_is_rejected() {
    let request = ProcessRequest {
        description: Some("a".repeat(501)),
        ..valid_process_request()
    };

    assert!(request.validate().is_err());
}

#[test]
fn process_request_allows_optional_name_and_description_to_be_absent() {
    let request = ProcessRequest {
        name: None,
        description: None,
        ..valid_process_request()
    };

    assert!(request.validate().is_ok());
}

#[test]
fn process_update_request_allows_all_fields_to_be_absent() {
    let request = ProcessUpdateRequest {
        name: None,
        description: None,
        code: None,
        environment: None,
        env_config: None,
        timeout_ms: None,
        priority: None,
        retry_max_attempts: None,
        lint: None,
        save: None,
    };

    assert!(request.validate().is_ok());
}

#[test]
fn process_update_request_valid_payload_passes_validation() {
    assert!(valid_process_update_request().validate().is_ok());
}

#[test]
fn process_update_request_environment_too_short_is_rejected() {
    let request = ProcessUpdateRequest {
        environment: Some("js".to_string()),
        ..valid_process_update_request()
    };

    assert!(request.validate().is_err());
}

#[test]
fn process_update_request_name_too_short_is_rejected() {
    let request = ProcessUpdateRequest {
        name: Some("ab".to_string()),
        ..valid_process_update_request()
    };

    assert!(request.validate().is_err());
}

#[test]
fn process_update_request_description_too_long_is_rejected() {
    let request = ProcessUpdateRequest {
        description: Some("a".repeat(501)),
        ..valid_process_update_request()
    };

    assert!(request.validate().is_err());
}

#[test]
fn process_update_request_allows_clearing_optional_limits() {
    let request = ProcessUpdateRequest {
        timeout_ms: Some(None),
        retry_max_attempts: Some(None),
        ..valid_process_update_request()
    };

    assert!(request.validate().is_ok());
}

#[test]
fn fork_overrides_valid_payload_passes_validation() {
    assert!(valid_fork_overrides().validate().is_ok());
}

#[test]
fn fork_overrides_allows_all_fields_to_be_absent() {
    let overrides = ForkOverrides {
        name: None,
        description: None,
        code: None,
        environment: None,
        env_config: None,
        timeout_ms: None,
        priority: None,
        retry_max_attempts: None,
    };

    assert!(overrides.validate().is_ok());
}

#[test]
fn fork_overrides_name_too_short_is_rejected() {
    let overrides = ForkOverrides {
        name: Some("ab".to_string()),
        ..valid_fork_overrides()
    };

    assert!(overrides.validate().is_err());
}

#[test]
fn fork_overrides_environment_too_short_is_rejected() {
    let overrides = ForkOverrides {
        environment: Some("js".to_string()),
        ..valid_fork_overrides()
    };

    assert!(overrides.validate().is_err());
}

#[test]
fn fork_overrides_description_too_long_is_rejected() {
    let overrides = ForkOverrides {
        description: Some("a".repeat(501)),
        ..valid_fork_overrides()
    };

    assert!(overrides.validate().is_err());
}

#[test]
fn fork_overrides_allows_clearing_optional_limits() {
    let overrides = ForkOverrides {
        timeout_ms: Some(None),
        retry_max_attempts: Some(None),
        ..valid_fork_overrides()
    };

    assert!(overrides.validate().is_ok());
}

#[test]
fn signal_deserializes_start_without_payload() {
    let signal: Signal = serde_json::from_value(json!({"signal": "START"})).unwrap();
    assert!(matches!(signal, Signal::Start));
}

#[test]
fn signal_deserializes_kill_without_payload() {
    let signal: Signal = serde_json::from_value(json!({"signal": "KILL"})).unwrap();
    assert!(matches!(signal, Signal::Kill));
}

#[test]
fn signal_deserializes_evict_without_payload() {
    let signal: Signal = serde_json::from_value(json!({"signal": "EVICT"})).unwrap();
    assert!(matches!(signal, Signal::Evict));
}

#[test]
fn signal_deserializes_fork_with_payload() {
    let signal: Signal = serde_json::from_value(json!({
        "signal": "FORK",
        "payload": {
            "name": "forked-process",
            "timeout_ms": null,
            "retry_max_attempts":  null
        }
    }))
    .unwrap();

    match signal {
        Signal::Fork(Some(overrides)) => {
            assert_eq!(overrides.name, Some("forked-process".to_string()));
            assert_eq!(overrides.timeout_ms, None);
            assert_eq!(overrides.retry_max_attempts, None);
        }
        other => panic!("expected fork signal, got {other:?}"),
    }
}

#[test]
fn signal_deserializes_fork_without_payload() {
    let signal: Signal = serde_json::from_value(json!({
        "signal": "FORK",
        "payload": null
    }))
    .unwrap();

    assert!(matches!(signal, Signal::Fork(None)));
}

#[test]
fn process_and_signal_responses_hold_expected_fields() {
    let process_response = ProcessResponse {
        pid: Uuid::nil().to_string(),
        name: "demo".to_string(),
        status: ProcessStatus::Queued,
    };
    let signal_response = SignalResponse {
        pid: Uuid::nil().to_string(),
        forked_pid: Some(Uuid::new_v4().to_string()),
        status: ProcessStatus::Success,
    };

    assert_eq!(process_response.name, "demo");
    assert_eq!(process_response.status, ProcessStatus::Queued);
    assert!(signal_response.forked_pid.is_some());
    assert_eq!(signal_response.status, ProcessStatus::Success);
}
