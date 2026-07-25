use axum::{Json, extract::State};
use std::sync::Arc;
use tracing::instrument;

use crate::AppState;

#[instrument(skip(state, req))]
pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<freesky_shared::types::RegisterRequest>,
) -> Json<freesky_shared::types::ApiResponse<freesky_shared::types::RegisterResponse>> {
    tracing::debug!("register request received");

    // Validate: APK signing key must match the trusted app key
    let apk_sha1 = req.apk_cert_sha1.trim().to_uppercase().replace(':', "");
    if apk_sha1 != state.trusted_app_key {
        tracing::warn!("register rejected: untrusted APK signing key");
        return Json(freesky_shared::types::ApiResponse::error(
            "untrusted APK signing key",
        ));
    }

    // Validate: pk_dev must be 65-byte SEC1 secp256r1 public key (0x04 || x || y)
    if !freesky_shared::crypto::validate_pk_dev(&req.pk_dev) {
        tracing::warn!("register rejected: invalid pk_dev (bad format or not on curve)");
        return Json(freesky_shared::types::ApiResponse::error("invalid pk_dev"));
    }

    // Single atomic database operation (one lock, all steps together)
    let result = match state.db.register_device(&req.pk_dev) {
        Ok(r) => r,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("no group key exists") {
                tracing::warn!("register rejected: no group key (admin must run key-rotate first)");
                return Json(freesky_shared::types::ApiResponse::error(
                    "no group key exists",
                ));
            } else {
                tracing::error!("register db error: {e}");
                return Json(freesky_shared::types::ApiResponse::error("internal error"));
            }
        }
    };

    if result.is_banned {
        tracing::warn!("register rejected: device is banned");
        return Json(freesky_shared::types::ApiResponse::error(
            "device is banned",
        ));
    }

    tracing::info!(
        "register success: name={} color={}",
        result.name,
        result.color
    );

    Json(freesky_shared::types::ApiResponse::success(
        freesky_shared::types::RegisterResponse {
            name: result.name,
            color: result.color,
            encrypted_sk_comm: result.encrypted_sk_comm,
        },
    ))
}

#[instrument(skip(state, req))]
pub async fn submit_post(
    State(state): State<Arc<AppState>>,
    Json(req): Json<freesky_shared::types::PostRequest>,
) -> Json<freesky_shared::types::ApiResponse<()>> {
    tracing::debug!("submit_post request received");

    // Validate: author_pk must be a valid secp256r1 SEC1 public key
    if !freesky_shared::crypto::validate_pk_dev(&req.author_pk) {
        tracing::warn!("submit_post rejected: invalid author_pk");
        return Json(freesky_shared::types::ApiResponse::error(
            "invalid author key",
        ));
    }

    // Store the post (DB layer verifies ECDSA signature + checks ban)
    match state.db.submit_post(&req) {
        Ok(result) => {
            tracing::info!("post stored: id={}", result.id);
            Json(freesky_shared::types::ApiResponse::success(()))
        }
        Err(crate::queries::PostError::InvalidSignature) => {
            tracing::warn!("submit_post rejected: invalid ECDSA signature");
            Json(freesky_shared::types::ApiResponse::error(
                "invalid signature",
            ))
        }
        Err(crate::queries::PostError::AuthorBanned) => {
            tracing::warn!("submit_post rejected: author is banned");
            Json(freesky_shared::types::ApiResponse::error(
                "author is banned",
            ))
        }
        Err(e) => {
            tracing::error!("submit_post db error: {e}");
            Json(freesky_shared::types::ApiResponse::error("internal error"))
        }
    }
}

#[instrument(skip(_state))]
pub async fn get_feed(
    State(_state): State<Arc<AppState>>,
) -> Json<freesky_shared::types::ApiResponse<freesky_shared::types::FeedResponse>> {
    tracing::debug!("get_feed request received");
    Json(freesky_shared::types::ApiResponse::success(
        freesky_shared::types::FeedResponse {
            posts: vec![],
            next_cursor: None,
        },
    ))
}

#[instrument(skip(_state))]
pub async fn report_post(
    State(_state): State<Arc<AppState>>,
    Json(_req): Json<freesky_shared::types::ReportRequest>,
) -> Json<freesky_shared::types::ApiResponse<()>> {
    tracing::debug!("report_post request received");
    Json(freesky_shared::types::ApiResponse::error("not implemented"))
}
