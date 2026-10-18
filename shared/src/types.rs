use serde::{Deserialize, Serialize};

pub type PkDev = Vec<u8>;
pub type Signature = Vec<u8>;

/// Unified API response wrapper.
///
/// All endpoints return this structure with HTTP 200.
/// `message` describes the result; `data` contains the payload (None on error).
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub message: String,
    pub data: Option<T>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            message: "success".to_string(),
            data: Some(data),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            data: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub pk_dev: PkDev,
    pub apk_cert_sha1: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub name: String,
    pub color: u8,
    pub encrypted_sk_comm: Vec<u8>,
    pub server_noise_pk: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PostRequest {
    pub ciphertext_comm: Vec<u8>,
    pub author_pk: PkDev,
    pub author_sig: Signature,
    pub timestamp: i64,
    pub mls_epoch: u64,
    #[serde(default)]
    pub parent_id: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FeedRequest {
    /// Cursor = timestamp of oldest post in previous batch. None = start from newest.
    pub cursor: Option<i64>,
    /// Max posts to return. Server clamps to [1, MAX_FEED_LIMIT]. None = default.
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FeedResponse {
    pub posts: Vec<PostEntry>,
    pub next_cursor: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PostEntry {
    pub id: i64,
    pub ciphertext_comm: Vec<u8>,
    pub author_pk: PkDev,
    pub author_sig: Signature,
    pub timestamp: i64,
    pub mls_epoch: u64,
    pub parent_id: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportRequest {
    pub post_id: i64,
    pub reporter_pk: PkDev,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThreadRequest {
    pub post_id: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThreadResponse {
    pub post: PostEntry,
    pub replies: Vec<PostEntry>,
}

/// Unsolicited notification pushed from server to connected clients over Noise.
///
/// The client distinguishes notifications from request responses by the
/// `type` field — responses use `message`/`data`, notifications use `type`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    #[serde(rename = "type")]
    pub notification_type: String,
    pub timestamp: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("device not found or banned")]
    Unauthorized,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("not found")]
    NotFound,
    #[error("internal error: {0}")]
    Internal(String),
}

// ─── Admin API ───
//
// Wire types for the admin API (server <-> admin TUI). The TUI runs on the
// server itself and every request carries `X-App-Key`. The API is bound to
// loopback and never published.

/// Aggregate counters shown on the admin dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminStats {
    pub total_users: i64,
    pub active_users: i64,
    pub banned_users: i64,
    pub total_posts: i64,
    pub today_posts: i64,
    pub total_reports: i64,
    pub unresolved_reports: i64,
}

/// An unresolved report row as shown in the admin TUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminReportRow {
    pub id: i64,
    pub reason: Option<String>,
    pub reported_at: i64,
    pub user_name: String,
}

/// Community metadata for the admin TUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminCommunity {
    pub member_count: i64,
    pub created_at: i64,
    pub has_group_key: bool,
}

/// A device row returned by admin user search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminDevice {
    /// 65-byte SEC1 uncompressed public key, hex-encoded (130 chars).
    pub pk_hex: String,
    pub user_name: String,
    pub user_color: u8,
    pub registered_at: i64,
    pub banned_at: Option<i64>,
    pub last_seen_at: Option<i64>,
    pub post_count: i64,
}

/// Result of a ban/unban request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminBanResult {
    pub pk_hex: String,
    pub banned: bool,
}

/// Result of a key rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminKeyRotate {
    pub devices_updated: usize,
}
