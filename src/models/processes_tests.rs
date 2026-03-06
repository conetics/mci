use super::*;
use serde_json::json;
use validator::Validate;

#[test]
fn process_phase_serializes_idle_as_screaming_snake_case() {
    assert_eq!(
        serde_json::to_string(&ProcessPhase::Idle).unwrap(),
        "\"IDLE\""
    );
}

#[test]
fn process_phase_serializes_queued_as_screaming_snake_case() {
    assert_eq!(
        serde_json::to_string(&ProcessPhase::Queued).unwrap(),
        "\"QUEUED\""
    );
}

#[test]
fn process_phase_serializes_running_as_screaming_snake_case() {
    assert_eq!(
        serde_json::to_string(&ProcessPhase::Running).unwrap(),
        "\"RUNNING\""
    );
}

#[test]
fn process_phase_deserializes_all_variants() {
    assert_eq!(
        serde_json::from_str::<ProcessPhase>("\"IDLE\"").unwrap(),
        ProcessPhase::Idle
    );
    assert_eq!(
        serde_json::from_str::<ProcessPhase>("\"QUEUED\"").unwrap(),
        ProcessPhase::Queued
    );
    assert_eq!(
        serde_json::from_str::<ProcessPhase>("\"RUNNING\"").unwrap(),
        ProcessPhase::Running
    );
}

#[test]
fn process_phase_rejects_lowercase_variant() {
    assert!(serde_json::from_str::<ProcessPhase>("\"idle\"").is_err());
    assert!(serde_json::from_str::<ProcessPhase>("\"running\"").is_err());
}

#[test]
fn process_phase_rejects_unknown_variant() {
    assert!(serde_json::from_str::<ProcessPhase>("\"PENDING\"").is_err());
}

#[test]
fn process_phase_clone_and_equality() {
    let p1 = ProcessPhase::Queued;
    let p2 = p1.clone();
    assert_eq!(p1, p2);
    assert_ne!(ProcessPhase::Idle, ProcessPhase::Running);
    assert_ne!(ProcessPhase::Running, ProcessPhase::Queued);
}

#[test]
fn process_phase_debug_format() {
    assert!(format!("{:?}", ProcessPhase::Idle).contains("Idle"));
    assert!(format!("{:?}", ProcessPhase::Running).contains("Running"));
}

#[test]
fn exit_status_serializes_success_as_screaming_snake_case() {
    assert_eq!(
        serde_json::to_string(&ExitStatus::Success).unwrap(),
        "\"SUCCESS\""
    );
}

#[test]
fn exit_status_serializes_failed_as_screaming_snake_case() {
    assert_eq!(
        serde_json::to_string(&ExitStatus::Failed).unwrap(),
        "\"FAILED\""
    );
}

#[test]
fn exit_status_deserializes_all_variants() {
    assert_eq!(
        serde_json::from_str::<ExitStatus>("\"SUCCESS\"").unwrap(),
        ExitStatus::Success
    );
    assert_eq!(
        serde_json::from_str::<ExitStatus>("\"FAILED\"").unwrap(),
        ExitStatus::Failed
    );
}

#[test]
fn exit_status_rejects_lowercase_variant() {
    assert!(serde_json::from_str::<ExitStatus>("\"success\"").is_err());
    assert!(serde_json::from_str::<ExitStatus>("\"failed\"").is_err());
}

#[test]
fn exit_status_clone_and_equality() {
    let e1 = ExitStatus::Success;
    let e2 = e1.clone();
    assert_eq!(e1, e2);
    assert_ne!(ExitStatus::Success, ExitStatus::Failed);
}

#[test]
fn exit_status_debug_format() {
    assert!(format!("{:?}", ExitStatus::Failed).contains("Failed"));
}

#[test]
fn output_chunk_clone_preserves_bytes() {
    let chunk = OutputChunk(bytes::Bytes::from("hello world"));
    let cloned = chunk.clone();
    assert_eq!(chunk.0, cloned.0);
}

#[test]
fn output_chunk_clone_empty_bytes() {
    let chunk = OutputChunk(bytes::Bytes::new());
    assert_eq!(chunk.clone().0.len(), 0);
}

#[test]
fn output_chunk_debug_format() {
    let s = format!("{:?}", OutputChunk(bytes::Bytes::from("test")));
    assert!(s.contains("OutputChunk"));
}

#[test]
fn process_channels_new_output_is_none() {
    let channels = ProcessChannels::new(16);
    assert!(channels.output.is_none());
}

#[test]
fn process_channels_subscribe_stdout_returns_receiver() {
    let channels = ProcessChannels::new(16);
    let _rx = channels.subscribe_stdout();
}

#[test]
fn process_channels_subscribe_stderr_returns_receiver() {
    let channels = ProcessChannels::new(16);
    let _rx = channels.subscribe_stderr();
}

#[test]
fn process_channels_stdout_send_and_receive() {
    let channels = ProcessChannels::new(16);
    let mut rx = channels.subscribe_stdout();
    let chunk = OutputChunk(bytes::Bytes::from("stdout data"));
    channels.stdout.send(chunk).unwrap();
    let received = rx.try_recv().unwrap();
    assert_eq!(received.0, bytes::Bytes::from("stdout data"));
}

#[test]
fn process_channels_stderr_send_and_receive() {
    let channels = ProcessChannels::new(16);
    let mut rx = channels.subscribe_stderr();
    let chunk = OutputChunk(bytes::Bytes::from("stderr data"));
    channels.stderr.send(chunk).unwrap();
    let received = rx.try_recv().unwrap();
    assert_eq!(received.0, bytes::Bytes::from("stderr data"));
}

#[test]
fn process_channels_multiple_subscribers_each_receive() {
    let channels = ProcessChannels::new(16);
    let mut rx1 = channels.subscribe_stdout();
    let mut rx2 = channels.subscribe_stdout();
    channels
        .stdout
        .send(OutputChunk(bytes::Bytes::from("broadcast")))
        .unwrap();
    assert_eq!(rx1.try_recv().unwrap().0, bytes::Bytes::from("broadcast"));
    assert_eq!(rx2.try_recv().unwrap().0, bytes::Bytes::from("broadcast"));
}

#[test]
fn process_channels_debug_format() {
    let s = format!("{:?}", ProcessChannels::new(8));
    assert!(s.contains("ProcessChannels"));
}

fn valid_process_request() -> ProcessRequest {
    ProcessRequest {
        code: "print('hello')".to_string(),
        environment: "python3.12".to_string(),
        env_config: None,
        name: Some("my-process".to_string()),
        description: None,
        timeout_ms: None,
        priority: None,
        retry_max_attempts: 3,
    }
}

#[test]
fn process_request_valid_passes_validation() {
    assert!(valid_process_request().validate().is_ok());
}

#[test]
fn process_request_environment_too_short_rejected() {
    let req = ProcessRequest {
        environment: "ab".to_string(),
        ..valid_process_request()
    };
    assert!(req.validate().is_err());
}

#[test]
fn process_request_environment_too_long_rejected() {
    let req = ProcessRequest {
        environment: "a".repeat(65),
        ..valid_process_request()
    };
    assert!(req.validate().is_err());
}

#[test]
fn process_request_environment_at_boundaries_passes() {
    let req_min = ProcessRequest {
        environment: "abc".to_string(),
        ..valid_process_request()
    };
    assert!(req_min.validate().is_ok());

    let req_max = ProcessRequest {
        environment: "a".repeat(64),
        ..valid_process_request()
    };
    assert!(req_max.validate().is_ok());
}

#[test]
fn process_request_name_too_short_rejected() {
    let req = ProcessRequest {
        name: Some("ab".to_string()),
        ..valid_process_request()
    };
    assert!(req.validate().is_err());
}

#[test]
fn process_request_name_too_long_rejected() {
    let req = ProcessRequest {
        name: Some("a".repeat(65)),
        ..valid_process_request()
    };
    assert!(req.validate().is_err());
}

#[test]
fn process_request_name_none_passes_validation() {
    let req = ProcessRequest {
        name: None,
        ..valid_process_request()
    };
    assert!(req.validate().is_ok());
}

#[test]
fn process_request_description_too_long_rejected() {
    let req = ProcessRequest {
        description: Some("a".repeat(501)),
        ..valid_process_request()
    };
    assert!(req.validate().is_err());
}

#[test]
fn process_request_description_at_max_length_passes() {
    let req = ProcessRequest {
        description: Some("a".repeat(500)),
        ..valid_process_request()
    };
    assert!(req.validate().is_ok());
}

#[test]
fn process_request_with_env_config_passes_validation() {
    let req = ProcessRequest {
        env_config: Some(json!({"key": "value", "count": 42})),
        ..valid_process_request()
    };
    assert!(req.validate().is_ok());
}

#[test]
fn process_request_with_timeout_and_priority_passes() {
    let req = ProcessRequest {
        timeout_ms: Some(30_000),
        priority: Some(64),
        ..valid_process_request()
    };
    assert!(req.validate().is_ok());
}

#[test]
fn process_response_serializes_all_fields() {
    let resp = ProcessResponse {
        pid: "abc-123".to_string(),
        name: "my-proc".to_string(),
        phase: ProcessPhase::Running,
        exit_status: None,
    };
    let v = serde_json::to_value(&resp).unwrap();
    assert_eq!(v["pid"], "abc-123");
    assert_eq!(v["name"], "my-proc");
    assert_eq!(v["phase"], "RUNNING");
    assert!(v["exit_status"].is_null());
}

#[test]
fn process_response_serializes_exit_status_when_present() {
    let resp = ProcessResponse {
        pid: "x".to_string(),
        name: "done".to_string(),
        phase: ProcessPhase::Idle,
        exit_status: Some(ExitStatus::Failed),
    };
    let v = serde_json::to_value(&resp).unwrap();
    assert_eq!(v["exit_status"], "FAILED");
}

#[test]
fn process_response_clone_preserves_fields() {
    let resp = ProcessResponse {
        pid: "p1".to_string(),
        name: "n1".to_string(),
        phase: ProcessPhase::Queued,
        exit_status: Some(ExitStatus::Success),
    };
    let cloned = resp.clone();
    assert_eq!(resp.pid, cloned.pid);
    assert_eq!(resp.phase, cloned.phase);
    assert_eq!(resp.exit_status, cloned.exit_status);
}

#[test]
fn process_response_debug_format() {
    let resp = ProcessResponse {
        pid: "p".to_string(),
        name: "n".to_string(),
        phase: ProcessPhase::Idle,
        exit_status: None,
    };
    assert!(format!("{:?}", resp).contains("ProcessResponse"));
}

fn valid_fork_overrides() -> ForkOverrides {
    ForkOverrides {
        name: Some("forked-process".to_string()),
        description: None,
        code: None,
        environment: Some("python3.12".to_string()),
        env_config: None,
        timeout_ms: None,
        priority: None,
        retry_max_attempts: None,
    }
}

fn empty_fork_overrides() -> ForkOverrides {
    ForkOverrides {
        name: None,
        description: None,
        code: None,
        environment: None,
        env_config: None,
        timeout_ms: None,
        priority: None,
        retry_max_attempts: None,
    }
}

#[test]
fn fork_overrides_all_none_passes_validation() {
    assert!(empty_fork_overrides().validate().is_ok());
}

#[test]
fn fork_overrides_valid_passes_validation() {
    assert!(valid_fork_overrides().validate().is_ok());
}

#[test]
fn fork_overrides_name_too_short_rejected() {
    let o = ForkOverrides {
        name: Some("ab".to_string()),
        ..empty_fork_overrides()
    };
    assert!(o.validate().is_err());
}

#[test]
fn fork_overrides_name_too_long_rejected() {
    let o = ForkOverrides {
        name: Some("a".repeat(65)),
        ..empty_fork_overrides()
    };
    assert!(o.validate().is_err());
}

#[test]
fn fork_overrides_description_too_long_rejected() {
    let o = ForkOverrides {
        description: Some("a".repeat(501)),
        ..empty_fork_overrides()
    };
    assert!(o.validate().is_err());
}

#[test]
fn fork_overrides_environment_too_short_rejected() {
    let o = ForkOverrides {
        environment: Some("ab".to_string()),
        ..empty_fork_overrides()
    };
    assert!(o.validate().is_err());
}

#[test]
fn fork_overrides_environment_too_long_rejected() {
    let o = ForkOverrides {
        environment: Some("a".repeat(65)),
        ..empty_fork_overrides()
    };
    assert!(o.validate().is_err());
}

#[test]
fn fork_overrides_timeout_ms_clear_with_none_inner() {
    let o = ForkOverrides {
        timeout_ms: Some(None),
        ..empty_fork_overrides()
    };
    assert!(o.validate().is_ok());
    assert_eq!(o.timeout_ms, Some(None));
}

#[test]
fn fork_overrides_timeout_ms_some_value() {
    let o = ForkOverrides {
        timeout_ms: Some(Some(5_000)),
        ..empty_fork_overrides()
    };
    assert!(o.validate().is_ok());
    assert_eq!(o.timeout_ms, Some(Some(5_000)));
}

#[test]
fn signal_deserializes_run() {
    let s: Signal = serde_json::from_value(json!({"signal": "RUN"})).unwrap();
    assert!(matches!(s, Signal::Run));
}

#[test]
fn signal_deserializes_lint() {
    let s: Signal = serde_json::from_value(json!({"signal": "LINT"})).unwrap();
    assert!(matches!(s, Signal::Lint));
}

#[test]
fn signal_deserializes_save() {
    let s: Signal = serde_json::from_value(json!({"signal": "SAVE"})).unwrap();
    assert!(matches!(s, Signal::Save));
}

#[test]
fn signal_deserializes_kill() {
    let s: Signal = serde_json::from_value(json!({"signal": "KILL"})).unwrap();
    assert!(matches!(s, Signal::Kill));
}

#[test]
fn signal_deserializes_evict() {
    let s: Signal = serde_json::from_value(json!({"signal": "EVICT"})).unwrap();
    assert!(matches!(s, Signal::Evict));
}

#[test]
fn signal_deserializes_fork_with_null_payload() {
    let s: Signal = serde_json::from_value(json!({"signal": "FORK", "payload": null})).unwrap();
    assert!(matches!(s, Signal::Fork(None)));
}

#[test]
fn signal_deserializes_fork_with_overrides() {
    let s: Signal = serde_json::from_value(json!({
        "signal": "FORK",
        "payload": {
            "name": "forked-process",
            "priority": 200u8
        }
    }))
    .unwrap();
    match s {
        Signal::Fork(Some(overrides)) => {
            assert_eq!(overrides.name, Some("forked-process".to_string()));
            assert_eq!(overrides.priority, Some(200u8));
        }
        _ => panic!("expected Fork(Some(_))"),
    }
}

#[test]
fn signal_deserializes_fork_with_code_override() {
    let s: Signal = serde_json::from_value(json!({
        "signal": "FORK",
        "payload": {
            "code": "print('forked')"
        }
    }))
    .unwrap();
    match s {
        Signal::Fork(Some(overrides)) => {
            assert_eq!(overrides.code, Some("print('forked')".to_string()));
        }
        _ => panic!("expected Fork(Some(_))"),
    }
}

#[test]
fn signal_rejects_unknown_variant() {
    let result: Result<Signal, _> = serde_json::from_value(json!({"signal": "UNKNOWN"}));
    assert!(result.is_err());
}

#[test]
fn signal_rejects_lowercase_variant() {
    let result: Result<Signal, _> = serde_json::from_value(json!({"signal": "run"}));
    assert!(result.is_err());
}
