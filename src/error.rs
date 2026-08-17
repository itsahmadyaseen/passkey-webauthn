use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use std::fmt;

/// Unified error type for the entire application.
/// Every error maps to a stable machine code + human message + HTTP status.
#[derive(Debug)]
pub enum AppError {
    /// 400 — malformed request body or missing fields
    BadRequest(String),
    /// 401 — authentication / ceremony failure (uniform, no enumeration)
    Unauthorized,
    /// 404 — route not found (not used for missing users — that's Unauthorized)
    NotFound(String),
    /// 409 — credential already registered
    Conflict(String),
    /// 410 — ceremony expired or already consumed
    CeremonyGone,
    /// 500 — unexpected internal error
    Internal(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::BadRequest(msg) => write!(f, "Bad request: {}", msg),
            AppError::Unauthorized => write!(f, "Authentication failed"),
            AppError::NotFound(msg) => write!(f, "Not found: {}", msg),
            AppError::Conflict(msg) => write!(f, "Conflict: {}", msg),
            AppError::CeremonyGone => write!(f, "Ceremony expired or already used"),
            AppError::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

#[derive(Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "BAD_REQUEST", msg),
            AppError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Authentication failed.".to_string(),
            ),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, "NOT_FOUND", msg),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, "CONFLICT", msg),
            AppError::CeremonyGone => (
                StatusCode::GONE,
                "CEREMONY_EXPIRED",
                "Ceremony expired or already used.".to_string(),
            ),
            AppError::Internal(msg) => {
                tracing::error!("Internal error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "An unexpected error occurred.".to_string(),
                )
            }
        };

        let body = ErrorEnvelope {
            error: ErrorBody { code, message },
        };

        (status, Json(body)).into_response()
    }
}

/// Convenience: convert sqlx errors into AppError::Internal
impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        AppError::Internal(format!("Database error: {}", err))
    }
}

/// Convenience: convert serde_json errors into AppError::BadRequest
impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::BadRequest(format!("JSON error: {}", err))
    }
}
