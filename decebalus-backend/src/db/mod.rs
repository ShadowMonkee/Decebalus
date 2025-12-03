use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use std::time::Duration;

// Repositories
pub mod repository;           // real DB implementation
pub mod repository_trait;     // Repository trait
pub mod db_repository;        // trait impl for real DB
pub mod inmemory_repository;  // trait impl for in-memory testing

pub type DbPool = sqlx::SqlitePool; // <- must be pub

/// Initialize database connection pool
pub async fn init_pool(database_url: &str) -> Result<SqlitePool, sqlx::Error> {
    tracing::info!("Connecting to database: {}", database_url);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(3))
        .connect(database_url)
        .await?;

    tracing::info!("Running database migrations...");

    // Run migrations
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await?;

    tracing::info!("Database initialized successfully");

    Ok(pool)
}
