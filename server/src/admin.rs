use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::instrument;

use crate::AppState;
use freesky_shared::types::{
    AdminBanResult, AdminCommunity, AdminDevice, AdminKeyRotate, AdminReportRow, AdminStats,
    ApiResponse,
};

/// Error tuple returned by admin handlers: HTTP status + JSON envelope.
type AdminError = (StatusCode, Json<serde_json::Value>);

/// Result type for admin handlers.
type AdminResult<T> = Result<Json<ApiResponse<T>>, AdminError>;

/// Verify the `X-App-Key` header against the trusted app key.
///
/// The admin API is reachable from the internet through the Cloudflare Tunnel
/// (Zero Trust), so an unconfigured key disables the API entirely instead of
/// silently skipping authentication.
fn verify_app_key(headers: &HeaderMap, expected: &str) -> Result<(), AdminError> {
    let provided = headers
        .get("x-app-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_uppercase()
        .replace(':', "");

    if expected.is_empty() {
        tracing::error!("admin API rejected: TRUSTED_APK_KEY is not configured");
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "message": "admin API disabled: TRUSTED_APK_KEY not configured",
                "data": null
            })),
        ));
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

/// Decode and validate a hex-encoded `pk_dev` (65-byte SEC1 secp256r1 point).
fn parse_pk_hex(pk_hex: &str) -> Option<Vec<u8>> {
    let bytes = hex::decode(pk_hex.trim()).ok()?;
    freesky_shared::crypto::validate_pk_dev(&bytes).then_some(bytes)
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub ok: bool,
}

#[derive(Debug, Deserialize)]
pub struct DeviceQuery {
    pub q: Option<String>,
}

pub async fn health(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> AdminResult<HealthResponse> {
    verify_app_key(&headers, &state.trusted_app_key)?;
    Ok(Json(ApiResponse::success(HealthResponse { ok: true })))
}

#[instrument(skip(state, headers))]
pub async fn stats(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> AdminResult<AdminStats> {
    verify_app_key(&headers, &state.trusted_app_key)?;
    match state.db.admin_stats().await {
        Ok(stats) => Ok(Json(ApiResponse::success(stats))),
        Err(e) => {
            tracing::error!("admin stats failed: {e}");
            Ok(Json(ApiResponse::error("internal error")))
        }
    }
}

#[instrument(skip(state, headers))]
pub async fn reports(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> AdminResult<Vec<AdminReportRow>> {
    verify_app_key(&headers, &state.trusted_app_key)?;
    match state.db.admin_unresolved_reports().await {
        Ok(reports) => Ok(Json(ApiResponse::success(reports))),
        Err(e) => {
            tracing::error!("admin reports failed: {e}");
            Ok(Json(ApiResponse::error("internal error")))
        }
    }
}

#[instrument(skip(state, headers))]
pub async fn resolve_report(
    headers: HeaderMap,
    Path(report_id): Path<i64>,
    State(state): State<Arc<AppState>>,
) -> AdminResult<()> {
    verify_app_key(&headers, &state.trusted_app_key)?;
    match state.db.admin_resolve_report(report_id, "resolved").await {
        Ok(true) => {
            tracing::info!("report #{report_id} resolved");
            Ok(Json(ApiResponse::success(())))
        }
        Ok(false) => Ok(Json(ApiResponse::error(
            "report not found or already resolved",
        ))),
        Err(e) => {
            tracing::error!("admin resolve report failed: {e}");
            Ok(Json(ApiResponse::error("internal error")))
        }
    }
}

#[instrument(skip(state, headers))]
pub async fn community(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> AdminResult<AdminCommunity> {
    verify_app_key(&headers, &state.trusted_app_key)?;
    match state.db.admin_community().await {
        Ok(community) => Ok(Json(ApiResponse::success(community))),
        Err(e) => {
            tracing::error!("admin community failed: {e}");
            Ok(Json(ApiResponse::error("internal error")))
        }
    }
}

#[instrument(skip(state, headers))]
pub async fn devices(
    headers: HeaderMap,
    Query(params): Query<DeviceQuery>,
    State(state): State<Arc<AppState>>,
) -> AdminResult<Vec<AdminDevice>> {
    verify_app_key(&headers, &state.trusted_app_key)?;
    let query = params.q.unwrap_or_default();
    match state.db.admin_search_devices(&query, 20).await {
        Ok(devices) => Ok(Json(ApiResponse::success(devices))),
        Err(e) => {
            tracing::error!("admin device search failed: {e}");
            Ok(Json(ApiResponse::error("internal error")))
        }
    }
}

#[instrument(skip(state, headers))]
pub async fn ban(
    headers: HeaderMap,
    Path(pk_hex): Path<String>,
    State(state): State<Arc<AppState>>,
) -> AdminResult<AdminBanResult> {
    verify_app_key(&headers, &state.trusted_app_key)?;
    let Some(pk_dev) = parse_pk_hex(&pk_hex) else {
        return Ok(Json(ApiResponse::error("invalid pk_dev")));
    };
    match state.db.admin_set_banned(&pk_dev, true).await {
        Ok(true) => {
            tracing::info!("device banned: {pk_hex}");
            Ok(Json(ApiResponse::success(AdminBanResult {
                pk_hex,
                banned: true,
            })))
        }
        Ok(false) => Ok(Json(ApiResponse::error("device not found"))),
        Err(e) => {
            tracing::error!("admin ban failed: {e}");
            Ok(Json(ApiResponse::error("internal error")))
        }
    }
}

#[instrument(skip(state, headers))]
pub async fn unban(
    headers: HeaderMap,
    Path(pk_hex): Path<String>,
    State(state): State<Arc<AppState>>,
) -> AdminResult<AdminBanResult> {
    verify_app_key(&headers, &state.trusted_app_key)?;
    let Some(pk_dev) = parse_pk_hex(&pk_hex) else {
        return Ok(Json(ApiResponse::error("invalid pk_dev")));
    };
    match state.db.admin_set_banned(&pk_dev, false).await {
        Ok(true) => {
            tracing::info!("device unbanned: {pk_hex}");
            Ok(Json(ApiResponse::success(AdminBanResult {
                pk_hex,
                banned: false,
            })))
        }
        Ok(false) => Ok(Json(ApiResponse::error("device not found"))),
        Err(e) => {
            tracing::error!("admin unban failed: {e}");
            Ok(Json(ApiResponse::error("internal error")))
        }
    }
}

#[instrument(skip(state, headers))]
pub async fn kick_member(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> AdminResult<()> {
    verify_app_key(&headers, &state.trusted_app_key)?;
    tracing::debug!("kick_member request received");
    Ok(Json(ApiResponse::error("not implemented")))
}

#[instrument(skip(state, headers))]
pub async fn key_rotate(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> AdminResult<AdminKeyRotate> {
    verify_app_key(&headers, &state.trusted_app_key)?;
    tracing::debug!("key_rotate request received");

    let devices_updated = match state.db.rotate_group_key().await {
        Ok(n) => n,
        Err(e) => {
            tracing::error!("key rotation failed: {e}");
            return Ok(Json(ApiResponse::error("key rotation failed")));
        }
    };

    tracing::info!("key rotation complete: {devices_updated} devices updated");

    Ok(Json(ApiResponse::success(AdminKeyRotate {
        devices_updated,
    })))
}
