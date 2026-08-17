use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::*;
use webauthn_rs::Webauthn;
use webauthn_rs::WebauthnBuilder;

use crate::error::AppError;

/// Wraps `webauthn-rs` to provide ceremony start/finish methods.
/// Free of Axum types — testable without an HTTP server.
pub struct CeremonyService {
    webauthn: Webauthn,
}

impl CeremonyService {
    /// Build a new ceremony service for the given relying party.
    pub fn new(rp_id: &str, rp_origin: &Url) -> Result<Self, AppError> {
        let builder = WebauthnBuilder::new(rp_id, rp_origin)
            .map_err(|e| AppError::Internal(format!("WebauthnBuilder error: {}", e)))?;

        let webauthn = builder
            .rp_name("Passkey Auth Demo")
            .build()
            .map_err(|e| AppError::Internal(format!("Webauthn build error: {}", e)))?;

        Ok(Self { webauthn })
    }

    // ── Registration ──────────────────────────────────────────────

    /// Begin a passkey registration ceremony.
    ///
    /// `exclude_credentials` contains the user's already-registered credential IDs,
    /// preventing the same authenticator from silently double-registering.
    pub fn start_registration(
        &self,
        user_id: Uuid,
        username: &str,
        display_name: &str,
        existing_passkeys: Option<Vec<Passkey>>,
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration), AppError> {
        // Extract credential IDs for exclude_credentials
        let exclude_credentials: Option<Vec<CredentialID>> =
            existing_passkeys.map(|pks| pks.iter().map(|pk| pk.cred_id().clone()).collect());

        let result = self
            .webauthn
            .start_passkey_registration(user_id, username, display_name, exclude_credentials)
            .map_err(|e| {
                tracing::error!("start_passkey_registration failed: {:?}", e);
                AppError::Internal(format!("Registration start failed: {}", e))
            })?;

        Ok(result)
    }

    /// Complete a passkey registration ceremony.
    pub fn finish_registration(
        &self,
        state: &PasskeyRegistration,
        credential: &RegisterPublicKeyCredential,
    ) -> Result<Passkey, AppError> {
        self.webauthn
            .finish_passkey_registration(credential, state)
            .map_err(|e| {
                tracing::warn!("finish_passkey_registration failed: {:?}", e);
                AppError::Unauthorized
            })
    }

    // ── Authentication ────────────────────────────────────────────

    /// Begin a passkey authentication ceremony.
    pub fn start_authentication(
        &self,
        credentials: &[Passkey],
    ) -> Result<(RequestChallengeResponse, PasskeyAuthentication), AppError> {
        self.webauthn
            .start_passkey_authentication(credentials)
            .map_err(|e| {
                tracing::error!("start_passkey_authentication failed: {:?}", e);
                AppError::Internal(format!("Authentication start failed: {}", e))
            })
    }

    /// Complete a passkey authentication ceremony.
    pub fn finish_authentication(
        &self,
        state: &PasskeyAuthentication,
        credential: &PublicKeyCredential,
    ) -> Result<AuthenticationResult, AppError> {
        self.webauthn
            .finish_passkey_authentication(credential, state)
            .map_err(|e| {
                tracing::warn!("finish_passkey_authentication failed: {:?}", e);
                AppError::Unauthorized
            })
    }
}
