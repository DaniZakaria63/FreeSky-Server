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
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportRequest {
    pub post_id: i64,
    pub reporter_pk: PkDev,
    pub reason: Option<String>,
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
