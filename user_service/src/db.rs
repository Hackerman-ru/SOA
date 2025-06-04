use sqlx::{PgPool, Pool, Postgres, migrate::Migrator};
use std::path::Path;

pub async fn apply_migrations(db_pool: &PgPool) -> Result<(), sqlx::Error> {
    let migrator = Migrator::new(Path::new("./migrations")).await?;
    migrator.run(db_pool).await?;
    Ok(())
}

pub async fn get_db_pool(url: &str) -> Pool<Postgres> {
    let db_pool = PgPool::connect(url)
        .await
        .expect("Failed to connect to the database");

    apply_migrations(&db_pool)
        .await
        .expect("Failed to apply migrations");

    db_pool
}

#[allow(dead_code)]
pub async fn clear_tables(pool: &PgPool) {
    sqlx::query("TRUNCATE TABLE users RESTART IDENTITY CASCADE")
        .execute(pool)
        .await
        .expect("Failed to clear tables");
}
