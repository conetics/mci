pub async fn generate_certs() {
    let output = std::process::Command::new("bash")
        .arg("./scripts/generate_certs.sh")
        .output()
        .expect("Failed to execute script/generate_certs.sh");

    if !output.status.success() {
        eprintln!("Error generating certs: {:?}", output);
        panic!("Failed to generate certificates");
    }
}
