use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::str::FromStr;
use std::time::Duration;

// Data access — free functions over the SqlitePool. (A former `Repository` trait +
// in-memory/DB impls were removed as dead code: nothing constructed them, and the
// tests exercise a real in-memory SQLite pool directly.)
pub mod repository;

pub type DbPool = sqlx::SqlitePool; // <- must be pub

/// Initialize database connection pool.
///
/// WAL mode + a busy timeout are essential once concurrent job load is high (many
/// brute-force attempts touch the DB for cancellation checks/logging): the default
/// rollback-journal mode serializes *all* access behind a single file lock, so under
/// load callers pile up waiting for that lock rather than for a genuinely busy pool.
pub async fn init_pool(database_url: &str) -> Result<SqlitePool, sqlx::Error> {
    tracing::info!("Connecting to database: {}", database_url);

    let connect_options = SqliteConnectOptions::from_str(database_url)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(Duration::from_secs(10));

    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(connect_options)
        .await?;

    tracing::info!("Running database migrations...");

    // Run migrations
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await?;

    tracing::info!("Database initialized successfully");

    Ok(pool)
}
