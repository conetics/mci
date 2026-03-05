use super::*;

#[cfg(test)]
mod common_tests {
    use super::*;
    use crate::services::ResourceKind;
    use anyhow::anyhow;

    const ID: &str = "test-id-123";

    fn run(config: anyhow::Result<()>, secrets: anyhow::Result<()>) {
        handle_delete_cleanup(ID, ResourceKind::Definition, config, secrets);
    }

    #[test]
    fn both_ok_completes_without_panic() {
        run(Ok(()), Ok(()));
    }

    #[test]
    fn config_err_secrets_ok_completes_without_panic() {
        run(Err(anyhow!("bucket not found")), Ok(()));
    }

    #[test]
    fn config_ok_secrets_err_completes_without_panic() {
        run(Ok(()), Err(anyhow!("access denied")));
    }

    #[test]
    fn both_err_completes_without_panic() {
        run(
            Err(anyhow!("config bucket not found")),
            Err(anyhow!("secrets access denied")),
        );
    }
}
