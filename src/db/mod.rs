use deadpool_postgres::{Config, Pool, Runtime};
use tokio_postgres::NoTls;

pub fn create_pool(database_url: &str) -> Pool {
    let pg_config = database_url.parse::<tokio_postgres::Config>().unwrap();
    let mut cfg = Config::new();

    cfg.user = pg_config.get_user().map(|s| s.to_string());
    cfg.password = pg_config
        .get_password()
        .map(|s| String::from_utf8_lossy(s).to_string());
    cfg.host = pg_config.get_hosts().first().map(|host| match host {
        tokio_postgres::config::Host::Tcp(s) => s.to_string(),
        tokio_postgres::config::Host::Unix(s) => s.to_string_lossy().to_string(),
    });
    cfg.port = pg_config.get_ports().first().map(|&p| p);
    cfg.dbname = pg_config.get_dbname().map(|s| s.to_string());

    cfg.create_pool(Some(Runtime::Tokio1), NoTls).unwrap()
}

pub async fn init_db(pool: &Pool) -> Result<(), anyhow::Error> {
    let _conn = pool.get().await?;

    Ok(())
}
