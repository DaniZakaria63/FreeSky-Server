use axum::{Json, extract::State, http::StatusCode};
use std::sync::Arc;
use tracing::instrument;

use crate::AppState;

#[instrument(skip(state, req))]
pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<freesky_shared::types::RegisterRequest>,
) -> Result<Json<freesky_shared::types::RegisterResponse>, StatusCode> {
    tracing::debug!("register request received");

    // Validate: pk_dev must be 65-byte SEC1 secp256r1 public key (0x04 || x || y)
    if !freesky_shared::crypto::validate_pk_dev(&req.pk_dev) {
        tracing::warn!("register rejected: invalid pk_dev (bad format or not on curve)");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Single atomic database operation (one lock, all steps together)
    let result = state.db.register_device(&req.pk_dev).map_err(|e| {
        tracing::error!("register db error: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if result.is_banned {
        tracing::warn!("register rejected: device is banned");
        return Err(StatusCode::FORBIDDEN);
    }

    tracing::info!(
        "register success: name={} color={}",
        result.name,
        result.color
    );

    Ok(Json(freesky_shared::types::RegisterResponse {
        name: result.name,
        color: result.color,
        encrypted_sk_comm: result.encrypted_sk_comm,
    }))
}

#[instrument(skip(_state))]
pub async fn submit_post(
    State(_state): State<Arc<AppState>>,
    Json(_req): Json<freesky_shared::types::PostRequest>,
) -> StatusCode {
    tracing::debug!("submit_post request received");
    StatusCode::NOT_IMPLEMENTED
}

#[instrument(skip(_state))]
pub async fn get_feed(
    State(_state): State<Arc<AppState>>,
) -> Json<freesky_shared::types::FeedResponse> {
    tracing::debug!("get_feed request received");
    Json(freesky_shared::types::FeedResponse {
        posts: vec![],
        next_cursor: None,
    })
}

#[instrument(skip(_state))]
pub async fn report_post(
    State(_state): State<Arc<AppState>>,
    Json(_req): Json<freesky_shared::types::ReportRequest>,
) -> StatusCode {
    tracing::debug!("report_post request received");
    StatusCode::NOT_IMPLEMENTED
}
