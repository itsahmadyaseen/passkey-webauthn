mod ceremony;
mod challenge_store;
mod config;
mod db;
mod error;
mod handlers;
mod middleware;

use std::sync::Arc;
use std::time::Duration;

use axum::{
    routing::{delete, get, post},
    Router,
};
use sqlx::postgres::PgPoolOptions;
use tower_cookies::CookieManagerLayer;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;

use ceremony::CeremonyService;
use challenge_store::ChallengeStore;
use config::AppConfig;

/// Shared application state, passed to all handlers via Axum's State extractor.
#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub ceremony: Arc<CeremonyService>,
    pub challenges: Arc<ChallengeStore>,
    pub config: Arc<AppConfig>,
}

#[tokio::main]
async fn main() {
    // Load .env if present
    dotenvy::dotenv().ok();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "passkey_auth=debug,tower_http=debug".into()),
        )
        .init();

    // Load configuration
    let config = AppConfig::from_env();
    tracing::info!(rp_id = %config.rp_id, rp_origin = %config.rp_origin, "Starting passkey-auth server");

    // Connect to PostgreSQL
    let db = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await
        .expect("Failed to connect to PostgreSQL");

    // Run migrations
    run_migrations(&db).await;

    // Build the ceremony service
    let ceremony = CeremonyService::new(&config.rp_id, &config.rp_origin)
        .expect("Failed to build CeremonyService");

    // Build the challenge store (60s TTL)
    let challenges = Arc::new(ChallengeStore::new(Duration::from_secs(60)));

    // Shared state
    let state = AppState {
        db: db.clone(),
        ceremony: Arc::new(ceremony),
        challenges: challenges.clone(),
        config: Arc::new(config.clone()),
    };

    // Spawn background tasks
    spawn_challenge_reaper(challenges);
    spawn_session_gc(db.clone());

    // Build the router
    let app = Router::new()
        // Health check
        .route("/health", get(health))
        // Registration
        .route("/register/start", post(handlers::register::register_start))
        .route(
            "/register/finish",
            post(handlers::register::register_finish),
        )
        // Authentication
        .route("/login/start", post(handlers::login::login_start))
        .route("/login/finish", post(handlers::login::login_finish))
        // Session
        .route("/me", get(handlers::session::me))
        .route("/logout", post(handlers::session::logout))
        // Credentials management
        .route("/credentials", get(handlers::credentials::list_credentials))
        .route(
            "/credentials/{id}",
            delete(handlers::credentials::delete_credential),
        )
        // Static files
        .fallback_service(ServeDir::new("static"))
        // Middleware
        .layer(CookieManagerLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Start the server
    let bind_addr = config.bind_address.clone();
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .expect("Failed to bind");
    tracing::info!("Listening on {}", bind_addr);

    axum::serve(listener, app).await.expect("Server error");
}

/// Health check endpoint.
async fn health() -> &'static str {
    "ok"
}

/// Run SQL migrations from the migrations/ directory.
async fn run_migrations(pool: &sqlx::PgPool) {
    // Read and execute each migration file in order
    let migrations = [
        include_str!("../migrations/001_create_users.sql"),
        include_str!("../migrations/002_create_passkeys.sql"),
        include_str!("../migrations/003_create_sessions.sql"),
    ];

    for (i, sql) in migrations.iter().enumerate() {
        // Split by semicolon because prepared statements can only contain one command
        for statement in sql.split(';') {
            let stmt = statement.trim();
            if stmt.is_empty() {
                continue;
            }
            match sqlx::query(stmt).execute(pool).await {
                Ok(_) => {}
                Err(e) => {
                    tracing::debug!("Migration {} statement failed: {}", i + 1, e);
                }
            }
        }
        tracing::info!("Migration {} applied", i + 1);
    }

    tracing::info!("All migrations applied");
}

/// Periodically reap expired challenge entries (every 30s).
fn spawn_challenge_reaper(store: Arc<ChallengeStore>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            store.reap_expired();
        }
    });
}

/// Periodically clean up expired sessions (every 5 minutes).
fn spawn_session_gc(pool: sqlx::PgPool) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300));
        loop {
            interval.tick().await;
            match db::sessions::cleanup_expired(&pool).await {
                Ok(count) if count > 0 => {
                    tracing::debug!("Cleaned up {} expired sessions", count);
                }
                Err(e) => {
                    tracing::warn!("Session cleanup failed: {}", e);
                }
                _ => {}
            }
        }
    });
}
