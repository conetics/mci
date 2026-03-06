use super::*;
use crate::models::processes::{ProcessInstance, ProcessStatus};
use chrono::{TimeZone, Utc};
use serde_json::json;
use uuid::Uuid;
use validator::Validate;

const VALID_HASH: &str =
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn sample_routine() -> Routine {
    Routine {
        pid: Uuid::nil(),
        name: "sample-routine".to_string(),
        description: "A sample routine.".to_string(),
        code_hash: VALID_HASH.to_string(),
        environment: "python".to_string(),
        env_config: json!({"version": "3.12"}),
        priority: 128,
        timeout_ms: Some(5_000),
        retry_max_attempts: Some(3),
        created_at: Utc.with_ymd_and_hms(2026, 3, 6, 0, 0, 0).unwrap(),
        updated_at: Utc.with_ymd_and_hms(2026, 3, 6, 0, 1, 0).unwrap(),
    }
}

fn sample_process_instance() -> ProcessInstance {
    ProcessInstance {
        pid: Uuid::nil(),
        name: "sample-process".to_string(),
        description: "A sample process.".to_string(),
        code_hash: VALID_HASH.to_string(),
        environment: "python".to_string(),
        env_config: json!({"version": "3.12"}),
        priority: 64,
        timeout_ms: Some(3_000),
        retry_max_attempts: Some(2),
        status: ProcessStatus::Running,
        attempt: Some(1),
        started_at: Some(Utc.with_ymd_and_hms(2026, 3, 6, 1, 0, 0).unwrap()),
        finished_at: None,
        channels: None,
        created_at: Utc.with_ymd_and_hms(2026, 3, 6, 0, 30, 0).unwrap(),
        updated_at: Utc.with_ymd_and_hms(2026, 3, 6, 0, 31, 0).unwrap(),
    }
}

fn valid_new_routine_request() -> NewRoutineRequest {
    NewRoutineRequest {
        name: "my-routine".to_string(),
        description: Some("Does something useful.".to_string()),
        code_hash: VALID_HASH.to_string(),
        environment: "python".to_string(),
        env_config: Some(json!({"version": "3.12"})),
        priority: Some(128),
        timeout_ms: Some(5_000),
        retry_max_attempts: Some(3),
    }
}

fn valid_update_routine_request() -> UpdateRoutineRequest {
    UpdateRoutineRequest {
        name: Some("updated-routine".to_string()),
        description: Some("Updated description.".to_string()),
        code_hash: Some(VALID_HASH.to_string()),
        environment: Some("python".to_string()),
        env_config: Some(json!({"version": "3.13"})),
        priority: Some(64),
        timeout_ms: Some(Some(10_000)),
        retry_max_attempts: Some(Some(5)),
    }
}

#[test]
fn routine_into_process_maps_fields_and_initial_runtime_state() {
    let created_at = Utc.with_ymd_and_hms(2026, 3, 6, 2, 0, 0).unwrap();
    let updated_at = Utc.with_ymd_and_hms(2026, 3, 6, 2, 1, 0).unwrap();
    let routine = Routine {
        pid: Uuid::new_v4(),
        name: "routine-name".to_string(),
        description: "routine-description".to_string(),
        code_hash: VALID_HASH.to_string(),
        environment: "python".to_string(),
        env_config: json!({"entrypoint": "main.py"}),
        priority: 7,
        timeout_ms: Some(9_999),
        retry_max_attempts: Some(5),
        created_at,
        updated_at,
    };

    let pid = routine.pid;
    let process = routine.into_process();

    assert_eq!(process.pid, pid);
    assert_eq!(process.name, "routine-name");
    assert_eq!(process.description, "routine-description");
    assert_eq!(process.code_hash, VALID_HASH);
    assert_eq!(process.environment, "python");
    assert_eq!(process.env_config, json!({"entrypoint": "main.py"}));
    assert_eq!(process.priority, 7);
    assert_eq!(process.timeout_ms, Some(9_999));
    assert_eq!(process.retry_max_attempts, Some(5));
    assert_eq!(process.status, ProcessStatus::Idle);
    assert_eq!(process.attempt, None);
    assert!(process.started_at.is_none());
    assert!(process.finished_at.is_none());
    assert!(process.channels.is_none());
    assert_eq!(process.created_at, created_at);
    assert_eq!(process.updated_at, updated_at);
}

#[test]
fn routine_into_process_preserves_absent_optional_limits() {
    let routine = Routine {
        timeout_ms: None,
        retry_max_attempts: None,
        ..sample_routine()
    };

    let process = routine.into_process();

    assert_eq!(process.timeout_ms, None);
    assert_eq!(process.retry_max_attempts, None);
}

#[test]
fn routine_into_process_casts_storage_types_to_runtime_types() {
    let routine = Routine {
        timeout_ms: Some(30_000_i64),
        retry_max_attempts: Some(10_i16),
        ..sample_routine()
    };

    let process = routine.into_process();

    assert_eq!(process.timeout_ms, Some(30_000_u64));
    assert_eq!(process.retry_max_attempts, Some(10_u8));
}

#[test]
fn routine_from_process_maps_fields() {
    let process = sample_process_instance();
    let pid = process.pid;
    let created_at = process.created_at;
    let updated_at = process.updated_at;

    let routine = Routine::from_process(process);

    assert_eq!(routine.pid, pid);
    assert_eq!(routine.name, "sample-process");
    assert_eq!(routine.description, "A sample process.");
    assert_eq!(routine.code_hash, VALID_HASH);
    assert_eq!(routine.environment, "python");
    assert_eq!(routine.env_config, json!({"version": "3.12"}));
    assert_eq!(routine.priority, 64);
    assert_eq!(routine.created_at, created_at);
    assert_eq!(routine.updated_at, updated_at);
}

#[test]
fn routine_from_process_casts_runtime_types_to_storage_types() {
    let process = ProcessInstance {
        timeout_ms: Some(60_000_u64),
        retry_max_attempts: Some(7_u8),
        ..sample_process_instance()
    };

    let routine = Routine::from_process(process);

    assert_eq!(routine.timeout_ms, Some(60_000_i64));
    assert_eq!(routine.retry_max_attempts, Some(7_i16));
}

#[test]
fn routine_from_process_discards_runtime_only_fields() {
    let process = ProcessInstance {
        status: ProcessStatus::Failed,
        attempt: Some(3),
        started_at: Some(Utc::now()),
        finished_at: Some(Utc::now()),
        ..sample_process_instance()
    };

    let routine = Routine::from_process(process);

    assert_eq!(routine.name, "sample-process");
}

#[test]
fn routine_from_process_preserves_absent_optional_limits() {
    let process = ProcessInstance {
        timeout_ms: None,
        retry_max_attempts: None,
        ..sample_process_instance()
    };

    let routine = Routine::from_process(process);

    assert_eq!(routine.timeout_ms, None);
    assert_eq!(routine.retry_max_attempts, None);
}

#[test]
fn new_routine_request_valid_passes_validation() {
    assert!(valid_new_routine_request().validate().is_ok());
}

#[test]
fn new_routine_request_allows_optional_fields_absent() {
    let req = NewRoutineRequest {
        description: None,
        env_config: None,
        priority: None,
        timeout_ms: None,
        retry_max_attempts: None,
        ..valid_new_routine_request()
    };

    assert!(req.validate().is_ok());
}

#[test]
fn new_routine_request_name_too_short_is_rejected() {
    let req = NewRoutineRequest {
        name: "ab".to_string(),
        ..valid_new_routine_request()
    };

    assert!(req.validate().is_err());
}

#[test]
fn new_routine_request_name_too_long_is_rejected() {
    let req = NewRoutineRequest {
        name: "a".repeat(65),
        ..valid_new_routine_request()
    };

    assert!(req.validate().is_err());
}

#[test]
fn new_routine_request_environment_too_short_is_rejected() {
    let req = NewRoutineRequest {
        environment: "py".to_string(),
        ..valid_new_routine_request()
    };

    assert!(req.validate().is_err());
}

#[test]
fn new_routine_request_environment_too_long_is_rejected() {
    let req = NewRoutineRequest {
        environment: "a".repeat(65),
        ..valid_new_routine_request()
    };

    assert!(req.validate().is_err());
}

#[test]
fn new_routine_request_description_too_long_is_rejected() {
    let req = NewRoutineRequest {
        description: Some("a".repeat(501)),
        ..valid_new_routine_request()
    };

    assert!(req.validate().is_err());
}

#[test]
fn new_routine_request_invalid_code_hash_is_rejected() {
    let req = NewRoutineRequest {
        code_hash: "not-a-valid-hash".to_string(),
        ..valid_new_routine_request()
    };

    assert!(req.validate().is_err());
}

#[test]
fn new_routine_request_priority_above_max_is_rejected() {
    let req = NewRoutineRequest {
        priority: Some(256),
        ..valid_new_routine_request()
    };

    assert!(req.validate().is_err());
}

#[test]
fn new_routine_request_priority_below_min_is_rejected() {
    let req = NewRoutineRequest {
        priority: Some(-1),
        ..valid_new_routine_request()
    };

    assert!(req.validate().is_err());
}

#[test]
fn new_routine_request_timeout_ms_zero_is_rejected() {
    let req = NewRoutineRequest {
        timeout_ms: Some(0),
        ..valid_new_routine_request()
    };

    assert!(req.validate().is_err());
}

#[test]
fn new_routine_request_retry_max_attempts_zero_is_rejected() {
    let req = NewRoutineRequest {
        retry_max_attempts: Some(0),
        ..valid_new_routine_request()
    };

    assert!(req.validate().is_err());
}

#[test]
fn new_routine_request_into_new_routine_maps_all_fields() {
    let pid = Uuid::new_v4();
    let req = valid_new_routine_request();
    let new_routine = req.clone().into_new_routine(pid);

    assert_eq!(new_routine.pid, pid);
    assert_eq!(new_routine.name, req.name);
    assert_eq!(new_routine.description, req.description.unwrap());
    assert_eq!(new_routine.code_hash, req.code_hash);
    assert_eq!(new_routine.environment, req.environment);
    assert_eq!(new_routine.env_config, req.env_config.unwrap());
    assert_eq!(new_routine.priority, req.priority.unwrap());
    assert_eq!(new_routine.timeout_ms, req.timeout_ms.map(|v| v as i64));
    assert_eq!(new_routine.retry_max_attempts, req.retry_max_attempts.map(|v| v as i16));
}

#[test]
fn new_routine_request_into_new_routine_applies_defaults_for_absent_fields() {
    let pid = Uuid::new_v4();
    let req = NewRoutineRequest {
        description: None,
        env_config: None,
        priority: None,
        ..valid_new_routine_request()
    };

    let new_routine = req.into_new_routine(pid);

    assert_eq!(new_routine.description, "");
    assert_eq!(new_routine.env_config, json!({}));
    assert_eq!(new_routine.priority, 128);
}

#[test]
fn update_routine_request_valid_passes_validation() {
    assert!(valid_update_routine_request().validate().is_ok());
}

#[test]
fn update_routine_request_allows_all_fields_absent() {
    let req = UpdateRoutineRequest {
        name: None,
        description: None,
        code_hash: None,
        environment: None,
        env_config: None,
        priority: None,
        timeout_ms: None,
        retry_max_attempts: None,
    };

    assert!(req.validate().is_ok());
}

#[test]
fn update_routine_request_name_too_short_is_rejected() {
    let req = UpdateRoutineRequest {
        name: Some("ab".to_string()),
        ..valid_update_routine_request()
    };

    assert!(req.validate().is_err());
}

#[test]
fn update_routine_request_environment_too_short_is_rejected() {
    let req = UpdateRoutineRequest {
        environment: Some("js".to_string()),
        ..valid_update_routine_request()
    };

    assert!(req.validate().is_err());
}

#[test]
fn update_routine_request_description_too_long_is_rejected() {
    let req = UpdateRoutineRequest {
        description: Some("a".repeat(501)),
        ..valid_update_routine_request()
    };

    assert!(req.validate().is_err());
}

#[test]
fn update_routine_request_invalid_code_hash_is_rejected() {
    let req = UpdateRoutineRequest {
        code_hash: Some("not-a-hash".to_string()),
        ..valid_update_routine_request()
    };

    assert!(req.validate().is_err());
}

#[test]
fn update_routine_request_priority_above_max_is_rejected() {
    let req = UpdateRoutineRequest {
        priority: Some(256),
        ..valid_update_routine_request()
    };

    assert!(req.validate().is_err());
}

#[test]
fn update_routine_request_priority_below_min_is_rejected() {
    let req = UpdateRoutineRequest {
        priority: Some(-1),
        ..valid_update_routine_request()
    };

    assert!(req.validate().is_err());
}

#[test]
fn update_routine_request_allows_clearing_optional_limits() {
    let req = UpdateRoutineRequest {
        timeout_ms: Some(None),
        retry_max_attempts: Some(None),
        ..valid_update_routine_request()
    };

    assert!(req.validate().is_ok());
}

#[test]
fn update_routine_request_into_changeset_maps_all_fields() {
    let req = valid_update_routine_request();
    let changeset = req.clone().into_changeset();

    assert_eq!(changeset.name, req.name);
    assert_eq!(changeset.description, req.description);
    assert_eq!(changeset.code_hash, req.code_hash);
    assert_eq!(changeset.environment, req.environment);
    assert_eq!(changeset.env_config, req.env_config);
    assert_eq!(changeset.priority, req.priority);
    assert_eq!(changeset.timeout_ms, Some(Some(10_000_i64)));
    assert_eq!(changeset.retry_max_attempts, Some(Some(5_i16)));
}

#[test]
fn update_routine_request_into_changeset_clears_optional_limits() {
    let req = UpdateRoutineRequest {
        timeout_ms: Some(None),
        retry_max_attempts: Some(None),
        ..valid_update_routine_request()
    };

    let changeset = req.into_changeset();

    assert_eq!(changeset.timeout_ms, Some(None));
    assert_eq!(changeset.retry_max_attempts, Some(None));
}

#[test]
fn update_routine_request_into_changeset_propagates_absent_fields_as_none() {
    let req = UpdateRoutineRequest {
        name: None,
        description: None,
        code_hash: None,
        environment: None,
        env_config: None,
        priority: None,
        timeout_ms: None,
        retry_max_attempts: None,
    };

    let changeset = req.into_changeset();

    assert!(changeset.name.is_none());
    assert!(changeset.description.is_none());
    assert!(changeset.code_hash.is_none());
    assert!(changeset.environment.is_none());
    assert!(changeset.env_config.is_none());
    assert!(changeset.priority.is_none());
    assert!(changeset.timeout_ms.is_none());
    assert!(changeset.retry_max_attempts.is_none());
}
