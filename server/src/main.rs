mod admin;
mod db;
mod noise;
mod routes;

use std::sync::Arc;
use tracing_subscriber::EnvFilter;

use crate::db::Database;

pub struct AppState {
    pub db: Database,
    pub noise: noise::NoiseHandler,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let sk_server = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let noise_handler = noise::NoiseHandler::new(sk_server);

    let db = Database::open("community.db")?;

    let state = Arc::new(AppState {
        db,
        noise: noise_handler,
    });

    let server_pk_hex = hex::encode(state.noise.pk_server_bytes());
    tracing::info!("server public key: {server_pk_hex}");

    let http_app = axum::Router::new()
        .route("/register", axum::routing::post(routes::register))
        .route("/post", axum::routing::post(routes::submit_post))
        .route("/feed", axum::routing::get(routes::get_feed))
        .route("/report", axum::routing::post(routes::report_post))
        .with_state(state.clone());

    let admin_app = axum::Router::new()
        .route("/admin/health", axum::routing::get(admin::health))
        .route("/admin/kick/:pk", axum::routing::post(admin::kick_member))
        .route("/admin/key-rotate", axum::routing::post(admin::key_rotate))
        .with_state(state.clone());

    let http_listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:3001").await?;

    tracing::info!("HTTP API listening on 0.0.0.0:3000");
    tracing::info!("Admin API listening on 127.0.0.1:3001");

    tokio::try_join!(
        axum::serve(http_listener, http_app),
        axum::serve(admin_listener, admin_app),
    )?;

    Ok(())
}
