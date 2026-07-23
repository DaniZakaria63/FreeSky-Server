use axum::{Json, extract::State, http::StatusCode};
use serde::Serialize;
use std::sync::Arc;

use crate::AppState;

#[derive(Serialize)]
pub struct HealthResponse {
    pub ok: bool,
}

pub async fn health(State(_state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse { ok: true })
}

pub async fn kick_member(State(_state): State<Arc<AppState>>) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

pub async fn key_rotate(State(_state): State<Arc<AppState>>) -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}
