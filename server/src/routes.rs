use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;

use crate::AppState;

pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<freesky_shared::types::RegisterRequest>,
) -> Result<Json<freesky_shared::types::RegisterResponse>, StatusCode> {
    // Validate: pk_dev must be 32 bytes (X25519 public key)
    if req.pk_dev.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Reject banned devices
    if state.db.is_device_banned(&req.pk_dev).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)? {
        return Err(StatusCode::FORBIDDEN);
    }

    // Derive deterministic identity from device key
    let name = freesky_shared::crypto::derive_name(&req.pk_dev);
    let color = freesky_shared::crypto::derive_color(&req.pk_dev);

    // Get or create the community group key
    let group_key = state
        .db
        .get_or_create_group_key()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // ECIES-encrypt the group key to this device's public key
    let encrypted_sk_comm = freesky_shared::crypto::ecies_encrypt(&req.pk_dev, &group_key);

    // Insert or update the device record
    let is_new = state
        .db
        .upsert_device(&req.pk_dev, &name, color, &encrypted_sk_comm)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Update member count if this is a new device
    if is_new {
        let _ = state.db.increment_member_count();
    }

    Ok(Json(freesky_shared::types::RegisterResponse {
        name,
        color,
        encrypted_sk_comm,
    }))
}

pub async fn submit_post(
    State(_state): State<Arc<AppState>>,
    Json(_req): Json<freesky_shared::types::PostRequest>,
) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

pub async fn get_feed(
    State(_state): State<Arc<AppState>>,
) -> Json<freesky_shared::types::FeedResponse> {
    Json(freesky_shared::types::FeedResponse {
        posts: vec![],
        next_cursor: None,
    })
}

pub async fn report_post(
    State(_state): State<Arc<AppState>>,
    Json(_req): Json<freesky_shared::types::ReportRequest>,
) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}
