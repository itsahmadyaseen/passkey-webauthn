use axum::{extract::State, Json};
use serde::Serialize;
use tower_cookies::{Cookie, Cookies};

use crate::db;
use crate::error::AppError;
use crate::middleware::{AuthUser, SESSION_COOKIE_NAME};
use crate::AppState;

#[derive(Serialize)]
pub struct MeResponse {
    pub user_id: String,
    pub username: String,
    pub display_name: String,
}

/// GET /me — returns the currently authenticated user.
pub async fn me(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<MeResponse>, AppError> {
    let user = db::users::find_user_by_id(&state.db, auth.user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    Ok(Json(MeResponse {
        user_id: user.id.to_string(),
        username: user.username,
        display_name: user.display_name,
    }))
}

/// POST /logout — destroys the session (server-side deletion, not just cookie).
pub async fn logout(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Json<serde_json::Value>, AppError> {
    if let Some(cookie) = cookies.get(SESSION_COOKIE_NAME) {
        let token = cookie.value().to_string();
        db::sessions::delete_session(&state.db, &token).await?;
    }

    // Remove the cookie
    let mut removal = Cookie::new(SESSION_COOKIE_NAME, "");
    removal.set_path("/");
    removal.set_http_only(true);
    removal.set_max_age(tower_cookies::cookie::time::Duration::ZERO);
    cookies.add(removal);

    Ok(Json(serde_json::json!({ "status": "logged_out" })))
}
