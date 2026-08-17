use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use tower_cookies::Cookies;
use uuid::Uuid;

use crate::error::AppError;
use crate::AppState;

pub const SESSION_COOKIE_NAME: &str = "session_id";

/// Extractor that validates the session cookie and yields the authenticated user ID.
/// Use this on any handler that requires authentication.
pub struct AuthUser {
    pub user_id: Uuid,
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Extract cookies
        let cookies = Cookies::from_request_parts(parts, state)
            .await
            .map_err(|_| AppError::Unauthorized)?;

        let session_token = cookies
            .get(SESSION_COOKIE_NAME)
            .map(|c| c.value().to_string())
            .ok_or(AppError::Unauthorized)?;

        if session_token.is_empty() {
            return Err(AppError::Unauthorized);
        }

        let user_id = crate::db::sessions::validate_session(&state.db, &session_token)
            .await?
            .ok_or(AppError::Unauthorized)?;

        Ok(AuthUser { user_id })
    }
}
