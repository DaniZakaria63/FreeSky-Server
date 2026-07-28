use axum::{Json, extract::State};
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

pub async fn health(
    State(_state): State<Arc<AppState>>,
) -> Json<freesky_shared::types::ApiResponse<HealthResponse>> {
    Json(freesky_shared::types::ApiResponse::success(
        HealthResponse { ok: true },
    ))
}

#[instrument(skip(_state))]
pub async fn kick_member(
    State(_state): State<Arc<AppState>>,
) -> Json<freesky_shared::types::ApiResponse<()>> {
    tracing::debug!("kick_member request received");
    Json(freesky_shared::types::ApiResponse::error("not implemented"))
}

#[instrument(skip(state))]
pub async fn key_rotate(
    State(state): State<Arc<AppState>>,
) -> Json<freesky_shared::types::ApiResponse<KeyRotateResponse>> {
    tracing::debug!("key_rotate request received");

    let devices_updated = match state.db.rotate_group_key().await {
        Ok(n) => n,
        Err(e) => {
            tracing::error!("key rotation failed: {e}");
            return Json(freesky_shared::types::ApiResponse::error(
                "key rotation failed",
            ));
        }
    };

    tracing::info!("key rotation complete: {devices_updated} devices updated");

    Json(freesky_shared::types::ApiResponse::success(
        KeyRotateResponse {
            ok: true,
            devices_updated,
        },
    ))
}
