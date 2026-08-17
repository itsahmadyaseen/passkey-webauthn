use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::db;
use crate::error::AppError;
use crate::middleware::SESSION_COOKIE_NAME;
use crate::AppState;
use tower_cookies::{Cookie, Cookies};

// ── Request / Response types ──────────────────────────────────────

#[derive(Deserialize)]
pub struct LoginStartRequest {
    pub username: String,
}

#[derive(Serialize)]
pub struct LoginStartResponse {
    pub ceremony_id: Uuid,
    pub options: RequestChallengeResponse,
}

#[derive(Deserialize)]
pub struct LoginFinishRequest {
    pub ceremony_id: Uuid,
    pub credential: PublicKeyCredential,
}

#[derive(Serialize)]
pub struct LoginFinishResponse {
    pub status: &'static str,
}

/// Stored alongside the authentication state.
#[derive(Serialize, Deserialize)]
struct AuthCeremonyData {
    user_id: Uuid,
    auth_state: PasskeyAuthentication,
}

// ── Handlers ──────────────────────────────────────────────────────

/// POST /login/start
///
/// Begin the authentication ceremony. Loads the user's passkeys,
/// starts the ceremony, and returns the challenge options.
///
/// Returns a uniform error regardless of whether the user exists or
/// has no passkeys — prevents user enumeration.
pub async fn login_start(
    State(state): State<AppState>,
    Json(body): Json<LoginStartRequest>,
) -> Result<Json<LoginStartResponse>, AppError> {
    // Normalize username
    let username = body.username.trim().to_lowercase();

    // Find user — uniform error on failure (no enumeration)
    let user = db::users::find_or_create_user(&state.db, &username, &username).await;
    let user = match user {
        Ok(u) => u,
        Err(_) => return Err(AppError::Unauthorized),
    };

    // Load passkeys
    let passkeys = db::passkeys::get_passkeys_for_user(&state.db, user.id).await?;
    if passkeys.is_empty() {
        // No passkeys → still return Unauthorized to avoid enumeration
        return Err(AppError::Unauthorized);
    }

    // Start the ceremony
    let (options, auth_state) = state.ceremony.start_authentication(&passkeys)?;

    // Store ceremony state + user_id
    let ceremony_data = AuthCeremonyData {
        user_id: user.id,
        auth_state,
    };
    let state_bytes = serde_json::to_vec(&ceremony_data)
        .map_err(|e| AppError::Internal(format!("Failed to serialize auth ceremony: {}", e)))?;
    let ceremony_id = state.challenges.insert(state_bytes);

    tracing::info!(
        username = %user.username,
        ceremony_id = %ceremony_id,
        "Authentication ceremony started"
    );

    Ok(Json(LoginStartResponse {
        ceremony_id,
        options,
    }))
}

/// POST /login/finish
///
/// Complete the authentication ceremony. Validates the signature,
/// checks the sign counter, creates a session, and sets the cookie.
pub async fn login_finish(
    State(state): State<AppState>,
    cookies: Cookies,
    Json(body): Json<LoginFinishRequest>,
) -> Result<Json<LoginFinishResponse>, AppError> {
    // Load and consume the ceremony state
    let state_bytes = state
        .challenges
        .consume(&body.ceremony_id)
        .ok_or(AppError::CeremonyGone)?;

    let ceremony_data: AuthCeremonyData = serde_json::from_slice(&state_bytes)
        .map_err(|e| AppError::Internal(format!("Failed to deserialize auth ceremony: {}", e)))?;

    // Complete the ceremony — signature, challenge, origin, RP ID,
    // user-presence and user-verification flags all checked
    let auth_result = state
        .ceremony
        .finish_authentication(&ceremony_data.auth_state, &body.credential)?;

    // Update the passkey with the new counter and updated state.
    // Load the user's passkeys to find and update the correct one.
    let mut passkeys =
        db::passkeys::get_passkeys_for_user(&state.db, ceremony_data.user_id).await?;

    // Find the passkey that was used and apply the authentication result
    let new_counter = auth_result.counter();
    for pk in passkeys.iter_mut() {
        if pk.cred_id() == auth_result.cred_id() {
            // update_credential mutates the passkey in place if the cred_id matches
            let updated = pk.update_credential(&auth_result);

            // Persist the updated passkey regardless (updates last_used_at)
            db::passkeys::update_passkey_after_auth(
                &state.db,
                auth_result.cred_id().as_ref(),
                pk,
                new_counter,
            )
            .await?;

            tracing::debug!(
                counter = new_counter,
                was_updated = ?updated,
                "Passkey state after authentication"
            );
            break;
        }
    }

    // Create a session
    let session_token = db::sessions::create_session(
        &state.db,
        ceremony_data.user_id,
        state.config.session_ttl_secs,
    )
    .await?;

    // Set the session cookie
    let mut cookie = Cookie::new(SESSION_COOKIE_NAME, session_token);
    cookie.set_http_only(true);
    cookie.set_same_site(tower_cookies::cookie::SameSite::Lax);
    cookie.set_path("/");
    // In production, also set Secure=true
    // cookie.set_secure(true);
    cookies.add(cookie);

    tracing::info!(
        user_id = %ceremony_data.user_id,
        "User authenticated successfully"
    );

    Ok(Json(LoginFinishResponse { status: "ok" }))
}
