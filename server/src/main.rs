mod admin;
mod db;
mod logging;
mod noise;
mod queries;
mod routes;

use std::sync::Arc;

use crate::db::Database;

pub struct AppState {
    pub db: Database,
    pub noise: noise::NoiseHandler,
    pub trusted_app_key: String,
    pub notifications: tokio::sync::broadcast::Sender<freesky_shared::types::Notification>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    logging::init()?;

    let turso_url = std::env::var("TURSO_URL")
        .map_err(|_| anyhow::anyhow!("TURSO_URL must be set"))?;
    let turso_token = std::env::var("TURSO_AUTH_TOKEN").unwrap_or_default();

    let db = Database::connect(&turso_url, &turso_token).await?;
    db.run_schema().await?;
    db.create_comment_trigger().await?;

    let sk_server = load_or_generate_noise_key(&db).await?;
    let noise_handler = noise::NoiseHandler::new(sk_server);

    let trusted_app_key = load_trusted_app_key();
    tracing::info!("trusted app key: {} bytes", trusted_app_key.len());

    let (notification_tx, _notification_rx) = tokio::sync::broadcast::channel(16);

    let state = Arc::new(AppState {
        db,
        noise: noise_handler,
        trusted_app_key: trusted_app_key.clone(),
        notifications: notification_tx,
    });

    let server_pk_hex = hex::encode(state.noise.pk_server_bytes());
    tracing::info!("server public key: {server_pk_hex}");

    let http_app = axum::Router::new()
        .route("/register", axum::routing::post(routes::register))
        .route("/server-pk", axum::routing::get(routes::server_pk))
        .with_state(state.clone());

    let admin_app = axum::Router::new()
        .route("/admin/health", axum::routing::get(admin::health))
        .route("/admin/kick/{pk}", axum::routing::post(admin::kick_member))
        .route("/admin/key-rotate", axum::routing::post(admin::key_rotate))
        .with_state(state.clone());

    let http_listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:3001").await?;
    let noise_listener = tokio::net::TcpListener::bind("0.0.0.0:9443").await?;

    tracing::info!("HTTP API listening on 0.0.0.0:3000");
    tracing::info!("Admin API listening on 127.0.0.1:3001");
    tracing::info!("Noise API listening on 0.0.0.0:9443");

    let noise_handler = state.noise.clone();
    let noise_state = state.clone();
    let noise_prologue = trusted_app_key.clone();

    tokio::try_join!(
        axum::serve(http_listener, http_app),
        axum::serve(admin_listener, admin_app),
        async {
            loop {
                let (stream, addr) = noise_listener.accept().await?;
                tracing::info!("noise connection from {addr}");
                let handler = noise_handler.clone();
                let state = noise_state.clone();
                let prologue = noise_prologue.clone();
                tokio::spawn(async move {
                    if let Err(e) = handler
                        .handle_connection(stream, prologue.as_bytes(), state)
                        .await
                    {
                        tracing::error!("noise connection error: {e}");
                    }
                });
            }
            #[allow(unreachable_code)]
            Ok(())
        },
    )?;

    Ok(())
}

/// Load the trusted APK signing key SHA-1 from the `TRUSTED_APK_KEY` environment variable.
/// Format: hex string with or without colons (e.g., `ABCDEF1234567890ABCDEF1234567890ABCDEF`).
fn load_trusted_app_key() -> String {
    std::env::var("TRUSTED_APK_KEY")
        .unwrap_or_default()
        .trim()
        .to_uppercase()
        .replace(':', "")
}

async fn load_or_generate_noise_key(db: &Database) -> anyhow::Result<p256::SecretKey> {
    if let Some(bytes) = db.load_noise_key().await {
        let sk = p256::SecretKey::from_slice(&bytes)
            .map_err(|e| anyhow::anyhow!("failed to parse stored noise key: {e}"))?;
        tracing::info!("loaded noise key from database");
        Ok(sk)
    } else {
        let sk = p256::SecretKey::random(&mut rand::rngs::OsRng);
        db.store_noise_key(&sk.to_bytes()).await?;
        tracing::info!("generated new noise key, stored in database");
        Ok(sk)
    }
}
