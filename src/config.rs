use url::Url;

/// Application configuration, fully driven by environment variables.
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub rp_id: String,
    pub rp_origin: Url,
    pub rp_name: String,
    pub database_url: String,
    pub bind_address: String,
    pub session_ttl_secs: i64,
}

impl AppConfig {
    /// Load configuration from environment variables.
    /// Panics on missing or invalid values — fail fast at startup.
    pub fn from_env() -> Self {
        let rp_id = std::env::var("RP_ID").expect("RP_ID must be set");
        let rp_origin_str = std::env::var("RP_ORIGIN").expect("RP_ORIGIN must be set");
        let rp_origin = Url::parse(&rp_origin_str).expect("RP_ORIGIN must be a valid URL");
        let rp_name = std::env::var("RP_NAME").unwrap_or_else(|_| "Passkey Auth".to_string());
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let bind_address =
            std::env::var("BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:3000".to_string());
        let session_ttl_secs = std::env::var("SESSION_TTL_SECS")
            .unwrap_or_else(|_| "86400".to_string())
            .parse::<i64>()
            .expect("SESSION_TTL_SECS must be a valid integer");

        Self {
            rp_id,
            rp_origin,
            rp_name,
            database_url,
            bind_address,
            session_ttl_secs,
        }
    }
}
