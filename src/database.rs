use diesel::{prelude, r2d2};

pub type PgPool = r2d2::Pool<r2d2::ConnectionManager<prelude::PgConnection>>;
pub type DbConnection = r2d2::PooledConnection<r2d2::ConnectionManager<prelude::PgConnection>>;

#[derive(Debug, thiserror::Error)]
pub enum CreatePoolError {
    #[error("pool_size must be greater than 0")]
    InvalidPoolSize,
}

pub fn create_pool(database_url: &str, pool_size: u32) -> Result<PgPool, CreatePoolError> {
    if pool_size == 0 {
        return Err(CreatePoolError::InvalidPoolSize);
    }

    let manager = r2d2::ConnectionManager::<prelude::PgConnection>::new(database_url);

    Ok(r2d2::Pool::builder()
        .max_size(pool_size)
        .build_unchecked(manager))
}

#[cfg(test)]
#[path = "database_tests.rs"]
mod tests;
