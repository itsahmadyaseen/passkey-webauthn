use axum::{
    extract::{Path, State},
    Json,
};
use uuid::Uuid;

use crate::db;
use crate::error::AppError;
use crate::middleware::AuthUser;
use crate::AppState;

/// GET /credentials — list the authenticated user's passkeys (metadata only).
pub async fn list_credentials(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<db::passkeys::StoredPasskey>>, AppError> {
    let passkeys = db::passkeys::list_passkeys_for_user(&state.db, auth.user_id).await?;
    Ok(Json(passkeys))
}

/// DELETE /credentials/:id — revoke a passkey (ownership-checked).
pub async fn delete_credential(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let deleted = db::passkeys::delete_passkey(&state.db, id, auth.user_id).await?;

    if !deleted {
        return Err(AppError::NotFound("Credential not found.".into()));
    }

    tracing::info!(
        user_id = %auth.user_id,
        credential_id = %id,
        "Passkey revoked"
    );

    Ok(Json(serde_json::json!({ "status": "deleted" })))
}
