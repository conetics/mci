use diesel::{prelude, r2d2};

pub type PgPool = r2d2::Pool<r2d2::ConnectionManager<prelude::PgConnection>>;
pub type DbConnection = r2d2::PooledConnection<r2d2::ConnectionManager<prelude::PgConnection>>;

pub fn create_pool(database_url: &str) -> PgPool {
    let manager = r2d2::ConnectionManager::<prelude::PgConnection>::new(database_url);

    r2d2::Pool::builder()
        .max_size(10)
        .build(manager)
        .expect("Failed to create pool")
}
