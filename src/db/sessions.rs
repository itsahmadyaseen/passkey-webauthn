use chrono::{Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::AppError;

/// Generate a cryptographically random session token (128 bits, hex-encoded).
fn generate_session_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16]; // 128 bits
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Create a new session for a user. Returns the opaque session token.
pub async fn create_session(
    pool: &PgPool,
    user_id: Uuid,
    ttl_secs: i64,
) -> Result<String, AppError> {
    let token = generate_session_token();
    let expires_at = Utc::now() + Duration::seconds(ttl_secs);

    sqlx::query("INSERT INTO sessions (id, user_id, expires_at) VALUES ($1, $2, $3)")
        .bind(&token)
        .bind(user_id)
        .bind(expires_at)
        .execute(pool)
        .await?;

    Ok(token)
}

/// Validate a session token. Returns the user ID if the session is valid and not expired.
pub async fn validate_session(pool: &PgPool, token: &str) -> Result<Option<Uuid>, AppError> {
    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT user_id FROM sessions WHERE id = $1 AND expires_at > NOW()",
    )
    .bind(token)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| r.0))
}

/// Delete a session (logout). Deletes the server-side record, not just the cookie.
pub async fn delete_session(pool: &PgPool, token: &str) -> Result<(), AppError> {
    sqlx::query("DELETE FROM sessions WHERE id = $1")
        .bind(token)
        .execute(pool)
        .await?;
    Ok(())
}

/// Cleanup expired sessions. Called periodically by a background task.
pub async fn cleanup_expired(pool: &PgPool) -> Result<u64, AppError> {
    let result = sqlx::query("DELETE FROM sessions WHERE expires_at <= NOW()")
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}
