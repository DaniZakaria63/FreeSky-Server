use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;

use crate::AppState;

pub async fn register(
    State(_state): State<Arc<AppState>>,
    Json(_req): Json<freesky_shared::types::RegisterRequest>,
) -> Result<Json<freesky_shared::types::RegisterResponse>, StatusCode> {
    Err(StatusCode::NOT_IMPLEMENTED)
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
