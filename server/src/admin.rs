use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use serde::Serialize;
use std::sync::Arc;
use tracing::instrument;

use crate::AppState;

fn verify_app_key(
    headers: &HeaderMap,
    expected: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let provided = headers
        .get("x-app-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_uppercase()
        .replace(':', "");
    if provided.is_empty() || expected.is_empty() {
        return Ok(()); // skip check if either side unconfigured
    }
    if provided != expected {
        tracing::warn!("admin API rejected: app-key mismatch");
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"message": "invalid app key", "data": null})),
        ));
    }
    Ok(())
}

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
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Result<
    Json<freesky_shared::types::ApiResponse<HealthResponse>>,
    (StatusCode, Json<serde_json::Value>),
> {
    verify_app_key(&headers, &state.trusted_app_key)?;
    Ok(Json(freesky_shared::types::ApiResponse::success(
        HealthResponse { ok: true },
    )))
}

#[instrument(skip(state))]
pub async fn kick_member(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Result<Json<freesky_shared::types::ApiResponse<()>>, (StatusCode, Json<serde_json::Value>)> {
    verify_app_key(&headers, &state.trusted_app_key)?;
    tracing::debug!("kick_member request received");
    Ok(Json(freesky_shared::types::ApiResponse::error(
        "not implemented",
    )))
}

#[instrument(skip(state))]
pub async fn key_rotate(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Result<
    Json<freesky_shared::types::ApiResponse<KeyRotateResponse>>,
    (StatusCode, Json<serde_json::Value>),
> {
    verify_app_key(&headers, &state.trusted_app_key)?;
    tracing::debug!("key_rotate request received");

    let devices_updated = match state.db.rotate_group_key().await {
        Ok(n) => n,
        Err(e) => {
            tracing::error!("key rotation failed: {e}");
            return Ok(Json(freesky_shared::types::ApiResponse::error(
                "key rotation failed",
            )));
        }
    };

    tracing::info!("key rotation complete: {devices_updated} devices updated");

    Ok(Json(freesky_shared::types::ApiResponse::success(
        KeyRotateResponse {
            ok: true,
            devices_updated,
        },
    )))
}
