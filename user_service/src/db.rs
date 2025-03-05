use dotenv::dotenv;
use sqlx::{PgPool, Pool, Postgres, migrate::Migrator};
use std::{env, path::Path};

pub async fn apply_migrations(db_pool: &PgPool) -> Result<(), sqlx::Error> {
    let migrator = Migrator::new(Path::new("./migrations")).await?;
    migrator.run(db_pool).await?;
    Ok(())
}

pub async fn get_db_pool() -> Pool<Postgres> {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db_pool = PgPool::connect(&database_url)
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
