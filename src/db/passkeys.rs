use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

use crate::error::AppError;

/// A stored passkey record (what we return to the API — metadata only, no secret material).
#[derive(Debug, Clone, Serialize, FromRow)]
pub struct StoredPasskey {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: String,
    pub nickname: String,
    pub sign_count: i32,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Internal row type for loading passkeys from the DB.
#[derive(Debug, FromRow)]
struct PasskeyRow {
    #[allow(dead_code)]
    id: Uuid,
    #[allow(dead_code)]
    user_id: Uuid,
    #[allow(dead_code)]
    credential_id: String,
    passkey: serde_json::Value,
    #[allow(dead_code)]
    sign_count: i32,
    #[allow(dead_code)]
    nickname: String,
    #[allow(dead_code)]
    created_at: DateTime<Utc>,
    #[allow(dead_code)]
    last_used_at: Option<DateTime<Utc>>,
}

/// Save a new passkey for a user.
pub async fn save_passkey(
    pool: &PgPool,
    user_id: Uuid,
    passkey: &Passkey,
    nickname: &str,
) -> Result<(), AppError> {
    let id = Uuid::new_v4();
    let credential_id = base64url_encode_bytes(passkey.cred_id().as_ref());
    let passkey_json = serde_json::to_value(passkey)
        .map_err(|e| AppError::Internal(format!("Failed to serialize passkey: {}", e)))?;

    sqlx::query(
        "INSERT INTO passkeys (id, user_id, credential_id, passkey, sign_count, nickname)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(user_id)
    .bind(&credential_id)
    .bind(&passkey_json)
    .bind(0i32)
    .bind(nickname)
    .execute(pool)
    .await
    .map_err(|e| {
        if let sqlx::Error::Database(ref db_err) = e {
            if db_err.constraint() == Some("passkeys_credential_id_key")
                || db_err.constraint() == Some("idx_passkeys_credential_id")
            {
                return AppError::Conflict("This passkey is already registered.".into());
            }
        }
        AppError::from(e)
    })?;

    Ok(())
}

/// Load all passkeys for a user, returning the deserialized `Passkey` objects.
pub async fn get_passkeys_for_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<Passkey>, AppError> {
    let rows: Vec<PasskeyRow> = sqlx::query_as(
        "SELECT id, user_id, credential_id, passkey, sign_count, nickname, created_at, last_used_at
         FROM passkeys WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    let mut passkeys = Vec::with_capacity(rows.len());
    for row in rows {
        let pk: Passkey = serde_json::from_value(row.passkey)
            .map_err(|e| AppError::Internal(format!("Failed to deserialize passkey: {}", e)))?;
        passkeys.push(pk);
    }
    Ok(passkeys)
}

/// List passkeys metadata for a user (no secret key material).
pub async fn list_passkeys_for_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<StoredPasskey>, AppError> {
    let rows: Vec<StoredPasskey> = sqlx::query_as(
        "SELECT id, user_id, credential_id, nickname, sign_count, created_at, last_used_at
         FROM passkeys WHERE user_id = $1
         ORDER BY created_at ASC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Update the passkey after authentication (new counter, updated state, last_used_at).
pub async fn update_passkey_after_auth(
    pool: &PgPool,
    credential_id: &[u8],
    updated_passkey: &Passkey,
    new_counter: u32,
) -> Result<(), AppError> {
    let cred_id_b64 = base64url_encode_bytes(credential_id);
    let passkey_json = serde_json::to_value(updated_passkey)
        .map_err(|e| AppError::Internal(format!("Failed to serialize passkey: {}", e)))?;

    sqlx::query(
        "UPDATE passkeys
         SET sign_count = $1, last_used_at = NOW(), passkey = $2
         WHERE credential_id = $3",
    )
    .bind(new_counter as i32)
    .bind(&passkey_json)
    .bind(&cred_id_b64)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete a passkey by ID, scoped to the owning user.
pub async fn delete_passkey(
    pool: &PgPool,
    passkey_id: Uuid,
    user_id: Uuid,
) -> Result<bool, AppError> {
    let result = sqlx::query("DELETE FROM passkeys WHERE id = $1 AND user_id = $2")
        .bind(passkey_id)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Base64url-encode bytes (no padding). Public for use in handlers.
pub fn base64url_encode_bytes(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut result = String::with_capacity((data.len() * 4 + 2) / 3);
    let chunks = data.chunks(3);

    for chunk in chunks {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        result.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            result.push(ALPHABET[(triple & 0x3F) as usize] as char);
        }
    }

    result
}
