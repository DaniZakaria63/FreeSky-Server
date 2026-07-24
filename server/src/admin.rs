use axum::{Json, extract::State, http::StatusCode};
use serde::Serialize;
use std::sync::Arc;
use tracing::instrument;

use crate::AppState;

#[derive(Serialize)]
pub struct HealthResponse {
    pub ok: bool,
}

#[derive(Serialize)]
pub struct KeyRotateResponse {
    pub ok: bool,
    pub devices_updated: usize,
}

pub async fn health(State(_state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse { ok: true })
}

#[instrument(skip(_state))]
pub async fn kick_member(State(_state): State<Arc<AppState>>) -> StatusCode {
    tracing::debug!("kick_member request received");
    StatusCode::NOT_IMPLEMENTED
}

#[instrument(skip(state))]
pub async fn key_rotate(
    State(state): State<Arc<AppState>>,
) -> Result<Json<KeyRotateResponse>, StatusCode> {
    tracing::debug!("key_rotate request received");

    let devices_updated = state.db.rotate_group_key().map_err(|e| {
        tracing::error!("key rotation failed: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::info!("key rotation complete: {devices_updated} devices updated");

    Ok(Json(KeyRotateResponse {
        ok: true,
        devices_updated,
    }))
}
