use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use std::time::Duration;

pub mod repository;

pub type DbPool = SqlitePool;

/// Initialize database connection pool
pub async fn init_pool(database_url: &str) -> Result<DbPool, sqlx::Error> {
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