use axum::{
    extract::State,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::db;
use crate::error::AppError;
use crate::AppState;

// ── Request / Response types ──────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterStartRequest {
    pub username: String,
    pub display_name: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterStartResponse {
    pub ceremony_id: Uuid,
    pub options: CreationChallengeResponse,
}

#[derive(Deserialize)]
pub struct RegisterFinishRequest {
    pub ceremony_id: Uuid,
    pub credential: RegisterPublicKeyCredential,
}

#[derive(Serialize)]
pub struct RegisterFinishResponse {
    pub status: &'static str,
}

/// Stored alongside the ceremony state so finish knows which user this belongs to.
#[derive(Serialize, Deserialize)]
pub struct RegistrationCeremonyData {
    pub user_id: Uuid,
    pub reg_state: PasskeyRegistration,
}

// ── Handlers ──────────────────────────────────────────────────────

/// POST /register/start
///
/// Begin the registration ceremony. Resolves or creates the user,
/// collects existing credential IDs for exclude_credentials, and
/// returns the browser creation options.
pub async fn register_start(
    State(state): State<AppState>,
    Json(body): Json<RegisterStartRequest>,
) -> Result<Json<RegisterStartResponse>, AppError> {
    let display_name = body.display_name.as_deref().unwrap_or(&body.username);

    // Resolve or create the user
    let user = db::users::find_or_create_user(&state.db, &body.username, display_name).await?;

    // Load existing passkeys for exclude_credentials
    let existing = db::passkeys::get_passkeys_for_user(&state.db, user.id).await?;
    let exclude = if existing.is_empty() {
        None
    } else {
        Some(existing)
    };

    // Start the ceremony
    let (options, reg_state) = state
        .ceremony
        .start_registration(user.id, &user.username, &user.display_name, exclude)?;

    // Store ceremony state + user_id together
    let ceremony_data = RegistrationCeremonyData {
        user_id: user.id,
        reg_state,
    };
    let state_bytes = serde_json::to_vec(&ceremony_data)
        .map_err(|e| AppError::Internal(format!("Failed to serialize ceremony data: {}", e)))?;
    let ceremony_id = state.challenges.insert(state_bytes);

    tracing::info!(
        username = %user.username,
        ceremony_id = %ceremony_id,
        "Registration ceremony started"
    );

    Ok(Json(RegisterStartResponse {
        ceremony_id,
        options,
    }))
}

/// POST /register/finish
///
/// Complete the registration ceremony. Loads and consumes the ceremony
/// state (single-use), validates the credential, and persists the passkey.
pub async fn register_finish(
    State(state): State<AppState>,
    Json(body): Json<RegisterFinishRequest>,
) -> Result<Json<RegisterFinishResponse>, AppError> {
    // Load and consume the ceremony state — single-use
    let state_bytes = state
        .challenges
        .consume(&body.ceremony_id)
        .ok_or(AppError::CeremonyGone)?;

    let ceremony_data: RegistrationCeremonyData = serde_json::from_slice(&state_bytes)
        .map_err(|e| AppError::Internal(format!("Failed to deserialize ceremony data: {}", e)))?;

    // Complete the ceremony — library checks challenge, origin, RP ID, type, flags
    let passkey = state
        .ceremony
        .finish_registration(&ceremony_data.reg_state, &body.credential)?;

    // Persist the passkey
    db::passkeys::save_passkey(&state.db, ceremony_data.user_id, &passkey, "My Passkey").await?;

    tracing::info!(
        user_id = %ceremony_data.user_id,
        "Passkey registered successfully"
    );

    Ok(Json(RegisterFinishResponse { status: "created" }))
}
