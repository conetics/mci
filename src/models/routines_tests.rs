use super::*;
use crate::models::processes::{ExitStatus, ProcessInstance, ProcessPhase};
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;
use validator::Validate;

fn make_process_instance() -> ProcessInstance {
    ProcessInstance {
        pid: Uuid::new_v4(),
        name: "test-routine".to_string(),
        description: "A test routine.".to_string(),
        environment: "python3.12".to_string(),
        env_config: json!({}),
        priority: 128,
        timeout_ms: Some(30_000),
        retry_max_attempts: 3,
        phase: ProcessPhase::Idle,
        exit_status: None,
        attempt: 0,
        channels: None,
        created_at: Utc::now(),
        started_at: None,
        finished_at: None,
    }
}

fn make_routine() -> Routine {
    Routine {
        pid: Uuid::new_v4(),
        name: "test-routine".to_string(),
        description: "A test routine.".to_string(),
        environment: "python3.12".to_string(),
        env_config: json!({}),
        priority: 128,
        timeout_ms: Some(30_000),
        retry_max_attempts: 3,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn empty_update() -> UpdateRoutineRequest {
    UpdateRoutineRequest {
        name: None,
        description: None,
        environment: None,
        env_config: None,
        priority: None,
        timeout_ms: None,
        retry_max_attempts: None,
    }
}

#[test]
fn routine_into_process_maps_identity_fields() {
    let routine = make_routine();
    let pid = routine.pid;
    let created_at = routine.created_at;
    let process = routine.into_process();

    assert_eq!(process.pid, pid);
    assert_eq!(process.name, "test-routine");
    assert_eq!(process.description, "A test routine.");
    assert_eq!(process.environment, "python3.12");
    assert_eq!(process.env_config, json!({}));
    assert_eq!(process.created_at, created_at);
}

#[test]
fn routine_into_process_casts_numeric_fields() {
    let routine = Routine {
        priority: 64,
        retry_max_attempts: 5,
        timeout_ms: Some(10_000),
        ..make_routine()
    };
    let process = routine.into_process();

    assert_eq!(process.priority, 64u8);
    assert_eq!(process.retry_max_attempts, 5u8);
    assert_eq!(process.timeout_ms, Some(10_000u64));
}

#[test]
fn routine_into_process_phase_defaults_to_idle() {
    assert_eq!(make_routine().into_process().phase, ProcessPhase::Idle);
}

#[test]
fn routine_into_process_exit_status_defaults_to_none() {
    assert!(make_routine().into_process().exit_status.is_none());
}

#[test]
fn routine_into_process_attempt_defaults_to_zero() {
    assert_eq!(make_routine().into_process().attempt, 0);
}

#[test]
fn routine_into_process_channels_defaults_to_none() {
    assert!(make_routine().into_process().channels.is_none());
}

#[test]
fn routine_into_process_started_at_defaults_to_none() {
    assert!(make_routine().into_process().started_at.is_none());
}

#[test]
fn routine_into_process_finished_at_defaults_to_none() {
    assert!(make_routine().into_process().finished_at.is_none());
}

#[test]
fn routine_into_process_timeout_ms_none_stays_none() {
    let routine = Routine {
        timeout_ms: None,
        ..make_routine()
    };
    assert!(routine.into_process().timeout_ms.is_none());
}

#[test]
fn routine_from_process_maps_identity_fields() {
    let instance = make_process_instance();
    let pid = instance.pid;
    let routine = Routine::from_process(&instance);

    assert_eq!(routine.pid, pid);
    assert_eq!(routine.name, "test-routine");
    assert_eq!(routine.description, "A test routine.");
    assert_eq!(routine.environment, "python3.12");
    assert_eq!(routine.env_config, json!({}));
}

#[test]
fn routine_from_process_casts_numeric_fields() {
    let instance = ProcessInstance {
        priority: 200,
        retry_max_attempts: 7,
        timeout_ms: Some(60_000),
        ..make_process_instance()
    };
    let routine = Routine::from_process(&instance);

    assert_eq!(routine.priority, 200i16);
    assert_eq!(routine.retry_max_attempts, 7i16);
    assert_eq!(routine.timeout_ms, Some(60_000i64));
}

#[test]
fn routine_from_process_timeout_ms_none_stays_none() {
    let instance = ProcessInstance {
        timeout_ms: None,
        ..make_process_instance()
    };
    assert!(Routine::from_process(&instance).timeout_ms.is_none());
}

#[test]
fn routine_from_process_updated_at_equals_created_at() {
    let instance = make_process_instance();
    let routine = Routine::from_process(&instance);
    assert_eq!(routine.created_at, routine.updated_at);
}

#[test]
fn routine_roundtrip_into_and_from_process_preserves_fields() {
    let original = make_routine();
    let pid = original.pid;
    let name = original.name.clone();

    let process = original.into_process();
    let recovered = Routine::from_process(&process);

    assert_eq!(recovered.pid, pid);
    assert_eq!(recovered.name, name);
    assert_eq!(recovered.priority, 128i16);
    assert_eq!(recovered.retry_max_attempts, 3i16);
}

fn valid_new_routine_request() -> NewRoutineRequest {
    NewRoutineRequest {
        name: "my-routine".to_string(),
        description: None,
        environment: "python3.12".to_string(),
        env_config: None,
        priority: None,
        timeout_ms: None,
        retry_max_attempts: None,
    }
}

#[test]
fn new_routine_request_valid_passes_validation() {
    assert!(valid_new_routine_request().validate().is_ok());
}

#[test]
fn new_routine_request_name_too_short_rejected() {
    let req = NewRoutineRequest {
        name: "ab".to_string(),
        ..valid_new_routine_request()
    };
    assert!(req.validate().is_err());
}

#[test]
fn new_routine_request_name_too_long_rejected() {
    let req = NewRoutineRequest {
        name: "a".repeat(65),
        ..valid_new_routine_request()
    };
    assert!(req.validate().is_err());
}

#[test]
fn new_routine_request_name_at_boundaries_passes() {
    let req_min = NewRoutineRequest {
        name: "abc".to_string(),
        ..valid_new_routine_request()
    };
    assert!(req_min.validate().is_ok());

    let req_max = NewRoutineRequest {
        name: "a".repeat(64),
        ..valid_new_routine_request()
    };
    assert!(req_max.validate().is_ok());
}

#[test]
fn new_routine_request_description_too_long_rejected() {
    let req = NewRoutineRequest {
        description: Some("a".repeat(501)),
        ..valid_new_routine_request()
    };
    assert!(req.validate().is_err());
}

#[test]
fn new_routine_request_description_at_max_length_passes() {
    let req = NewRoutineRequest {
        description: Some("a".repeat(500)),
        ..valid_new_routine_request()
    };
    assert!(req.validate().is_ok());
}

#[test]
fn new_routine_request_environment_too_short_rejected() {
    let req = NewRoutineRequest {
        environment: "ab".to_string(),
        ..valid_new_routine_request()
    };
    assert!(req.validate().is_err());
}

#[test]
fn new_routine_request_environment_too_long_rejected() {
    let req = NewRoutineRequest {
        environment: "a".repeat(65),
        ..valid_new_routine_request()
    };
    assert!(req.validate().is_err());
}

#[test]
fn new_routine_request_retry_max_attempts_zero_rejected() {
    let req = NewRoutineRequest {
        retry_max_attempts: Some(0),
        ..valid_new_routine_request()
    };
    assert!(req.validate().is_err());
}

#[test]
fn new_routine_request_retry_max_attempts_one_passes() {
    let req = NewRoutineRequest {
        retry_max_attempts: Some(1),
        ..valid_new_routine_request()
    };
    assert!(req.validate().is_ok());
}

#[test]
fn new_routine_request_rejects_unknown_fields() {
    let payload = json!({
        "name": "my-routine",
        "environment": "python3.12",
        "unknown_field": "value"
    });
    let result: Result<NewRoutineRequest, _> = serde_json::from_value(payload);
    assert!(result.is_err());
}

#[test]
fn into_new_routine_sets_pid() {
    let pid = Uuid::new_v4();
    let new_routine = valid_new_routine_request().into_new_routine(pid);
    assert_eq!(new_routine.pid, pid);
}

#[test]
fn into_new_routine_description_defaults_to_empty_string() {
    let pid = Uuid::new_v4();
    let new_routine = NewRoutineRequest {
        description: None,
        ..valid_new_routine_request()
    }
    .into_new_routine(pid);
    assert_eq!(new_routine.description, "");
}

#[test]
fn into_new_routine_description_preserved_when_provided() {
    let pid = Uuid::new_v4();
    let new_routine = NewRoutineRequest {
        description: Some("a helpful description".to_string()),
        ..valid_new_routine_request()
    }
    .into_new_routine(pid);
    assert_eq!(new_routine.description, "a helpful description");
}

#[test]
fn into_new_routine_env_config_defaults_to_empty_object() {
    let pid = Uuid::new_v4();
    let new_routine = NewRoutineRequest {
        env_config: None,
        ..valid_new_routine_request()
    }
    .into_new_routine(pid);
    assert_eq!(new_routine.env_config, json!({}));
}

#[test]
fn into_new_routine_env_config_preserved_when_provided() {
    let pid = Uuid::new_v4();
    let config = json!({"key": "value"});
    let new_routine = NewRoutineRequest {
        env_config: Some(config.clone()),
        ..valid_new_routine_request()
    }
    .into_new_routine(pid);
    assert_eq!(new_routine.env_config, config);
}

#[test]
fn into_new_routine_priority_defaults_to_128() {
    let pid = Uuid::new_v4();
    let new_routine = NewRoutineRequest {
        priority: None,
        ..valid_new_routine_request()
    }
    .into_new_routine(pid);
    assert_eq!(new_routine.priority, 128i16);
}

#[test]
fn into_new_routine_priority_preserved_when_provided() {
    let pid = Uuid::new_v4();
    let new_routine = NewRoutineRequest {
        priority: Some(64),
        ..valid_new_routine_request()
    }
    .into_new_routine(pid);
    assert_eq!(new_routine.priority, 64i16);
}

#[test]
fn into_new_routine_timeout_ms_none_stays_none() {
    let pid = Uuid::new_v4();
    let new_routine = NewRoutineRequest {
        timeout_ms: None,
        ..valid_new_routine_request()
    }
    .into_new_routine(pid);
    assert!(new_routine.timeout_ms.is_none());
}

#[test]
fn into_new_routine_timeout_ms_cast_to_i64() {
    let pid = Uuid::new_v4();
    let new_routine = NewRoutineRequest {
        timeout_ms: Some(5_000),
        ..valid_new_routine_request()
    }
    .into_new_routine(pid);
    assert_eq!(new_routine.timeout_ms, Some(5_000i64));
}

#[test]
fn into_new_routine_retry_max_attempts_cast_to_i16() {
    let pid = Uuid::new_v4();
    let new_routine = NewRoutineRequest {
        retry_max_attempts: Some(5),
        ..valid_new_routine_request()
    }
    .into_new_routine(pid);
    assert_eq!(new_routine.retry_max_attempts, Some(5i16));
}

#[test]
fn into_new_routine_retry_max_attempts_none_stays_none() {
    let pid = Uuid::new_v4();
    let new_routine = NewRoutineRequest {
        retry_max_attempts: None,
        ..valid_new_routine_request()
    }
    .into_new_routine(pid);
    assert!(new_routine.retry_max_attempts.is_none());
}

#[test]
fn update_routine_request_all_none_passes_validation() {
    assert!(empty_update().validate().is_ok());
}

#[test]
fn update_routine_request_name_too_short_rejected() {
    let req = UpdateRoutineRequest {
        name: Some("ab".to_string()),
        ..empty_update()
    };
    assert!(req.validate().is_err());
}

#[test]
fn update_routine_request_name_too_long_rejected() {
    let req = UpdateRoutineRequest {
        name: Some("a".repeat(65)),
        ..empty_update()
    };
    assert!(req.validate().is_err());
}

#[test]
fn update_routine_request_description_too_long_rejected() {
    let req = UpdateRoutineRequest {
        description: Some("a".repeat(501)),
        ..empty_update()
    };
    assert!(req.validate().is_err());
}

#[test]
fn update_routine_request_environment_too_short_rejected() {
    let req = UpdateRoutineRequest {
        environment: Some("ab".to_string()),
        ..empty_update()
    };
    assert!(req.validate().is_err());
}

#[test]
fn update_routine_request_environment_too_long_rejected() {
    let req = UpdateRoutineRequest {
        environment: Some("a".repeat(65)),
        ..empty_update()
    };
    assert!(req.validate().is_err());
}

#[test]
fn update_routine_request_rejects_unknown_fields() {
    let payload = json!({
        "name": "valid-name",
        "unknown_field": true
    });
    let result: Result<UpdateRoutineRequest, _> = serde_json::from_value(payload);
    assert!(result.is_err());
}

#[test]
fn into_changeset_all_none_produces_empty_changeset() {
    let cs = empty_update().into_changeset();
    assert!(cs.name.is_none());
    assert!(cs.description.is_none());
    assert!(cs.environment.is_none());
    assert!(cs.env_config.is_none());
    assert!(cs.priority.is_none());
    assert!(cs.timeout_ms.is_none());
    assert!(cs.retry_max_attempts.is_none());
}

#[test]
fn into_changeset_maps_name() {
    let cs = UpdateRoutineRequest {
        name: Some("updated".to_string()),
        ..empty_update()
    }
    .into_changeset();
    assert_eq!(cs.name, Some("updated".to_string()));
}

#[test]
fn into_changeset_maps_priority_cast_to_i16() {
    let cs = UpdateRoutineRequest {
        priority: Some(64),
        ..empty_update()
    }
    .into_changeset();
    assert_eq!(cs.priority, Some(64i16));
}

#[test]
fn into_changeset_maps_retry_max_attempts_cast_to_i16() {
    let cs = UpdateRoutineRequest {
        retry_max_attempts: Some(10),
        ..empty_update()
    }
    .into_changeset();
    assert_eq!(cs.retry_max_attempts, Some(10i16));
}

#[test]
fn into_changeset_maps_timeout_ms_clear_with_none_inner() {
    let cs = UpdateRoutineRequest {
        timeout_ms: Some(None),
        ..empty_update()
    }
    .into_changeset();
    assert_eq!(cs.timeout_ms, Some(None));
}

#[test]
fn into_changeset_maps_timeout_ms_to_some_i64() {
    let cs = UpdateRoutineRequest {
        timeout_ms: Some(Some(10_000)),
        ..empty_update()
    }
    .into_changeset();
    assert_eq!(cs.timeout_ms, Some(Some(10_000i64)));
}

#[test]
fn into_changeset_maps_env_config() {
    let config = json!({"host": "localhost", "port": 5432});
    let cs = UpdateRoutineRequest {
        env_config: Some(config.clone()),
        ..empty_update()
    }
    .into_changeset();
    assert_eq!(cs.env_config, Some(config));
}

#[test]
fn routine_changeset_default_has_all_none_fields() {
    let cs = RoutineChangeset::default();
    assert!(cs.name.is_none());
    assert!(cs.description.is_none());
    assert!(cs.environment.is_none());
    assert!(cs.env_config.is_none());
    assert!(cs.priority.is_none());
    assert!(cs.timeout_ms.is_none());
    assert!(cs.retry_max_attempts.is_none());
}

#[test]
fn process_instance_with_exit_status_roundtrip() {
    let instance = ProcessInstance {
        exit_status: Some(ExitStatus::Success),
        ..make_process_instance()
    };
    let routine = Routine::from_process(&instance);
    let recovered = routine.into_process();
    assert!(recovered.exit_status.is_none());
}
