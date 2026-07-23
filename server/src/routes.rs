use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;

use crate::AppState;

pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<freesky_shared::types::RegisterRequest>,
) -> Result<Json<freesky_shared::types::RegisterResponse>, StatusCode> {
    // Validate: pk_dev must be 65-byte SEC1 secp256r1 public key (0x04 || x || y)
    if req.pk_dev.len() != 65 || req.pk_dev[0] != 0x04 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Single atomic database operation (one lock, all steps together)
    let result = state
        .db
        .register_device(&req.pk_dev)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if result.is_banned {
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(Json(freesky_shared::types::RegisterResponse {
        name: result.name,
        color: result.color,
        encrypted_sk_comm: result.encrypted_sk_comm,
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
