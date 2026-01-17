use std::process::Command;
use tracing::info;

pub async fn setup_test_db() {
    info!("Starting test database with docker-compose...");
    let output = Command::new("docker-compose")
        .args(&["up", "-d", "db"])
        .output()
        .expect("Failed to execute docker-compose command");

    if !output.status.success() {
        eprintln!("Error starting docker-compose db: {:?}", output);
        panic!("Failed to start test database");
    }

    // Give the database a moment to start up
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    info!("Test database started.");
}

pub async fn teardown_test_db() {
    info!("Tearing down test database with docker-compose...");
    let output = Command::new("docker-compose")
        .args(&["down"])
        .output()
        .expect("Failed to execute docker-compose command");

    if !output.status.success() {
        eprintln!("Error tearing down docker-compose: {:?}", output);
        panic!("Failed to tear down test database");
    }
    info!("Test database torn down.");
}
