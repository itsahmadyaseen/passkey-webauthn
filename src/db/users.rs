use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::error::AppError;

/// A user record.
#[derive(Debug, Clone, FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
}

const MAX_USERNAME_LEN: usize = 64;

/// Validate and case-fold a username.
fn normalize_username(username: &str) -> Result<String, AppError> {
    let trimmed = username.trim();
    if trimmed.is_empty() {
        return Err(AppError::BadRequest("Username cannot be empty.".into()));
    }
    if trimmed.len() > MAX_USERNAME_LEN {
        return Err(AppError::BadRequest(format!(
            "Username must be at most {} characters.",
            MAX_USERNAME_LEN
        )));
    }
    Ok(trimmed.to_lowercase())
}

/// Find an existing user by username, or create a new one.
/// Username is case-folded before lookup/storage.
pub async fn find_or_create_user(
    pool: &PgPool,
    username: &str,
    display_name: &str,
) -> Result<User, AppError> {
    let normalized = normalize_username(username)?;

    // Try to find existing user first
    let existing: Option<User> = sqlx::query_as(
        "SELECT id, username, display_name, created_at FROM users WHERE username = $1",
    )
    .bind(&normalized)
    .fetch_optional(pool)
    .await?;

    if let Some(user) = existing {
        return Ok(user);
    }

    // Create new user
    let id = Uuid::new_v4();
    let display = if display_name.trim().is_empty() {
        &normalized
    } else {
        display_name
    };

    let user: User = sqlx::query_as(
        "INSERT INTO users (id, username, display_name)
         VALUES ($1, $2, $3)
         ON CONFLICT (username) DO UPDATE SET username = users.username
         RETURNING id, username, display_name, created_at",
    )
    .bind(id)
    .bind(&normalized)
    .bind(display)
    .fetch_one(pool)
    .await?;

    Ok(user)
}

/// Find a user by their ID.
pub async fn find_user_by_id(pool: &PgPool, id: Uuid) -> Result<Option<User>, AppError> {
    let user: Option<User> = sqlx::query_as(
        "SELECT id, username, display_name, created_at FROM users WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}
