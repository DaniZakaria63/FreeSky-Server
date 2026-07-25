use std::time::Duration;

use anyhow::Result;
use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::Deserialize;
use snow::{Builder, TransportState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::AppState;

/// Noise IK responder using secp256r1 (P-256) for DH, matching the Android
/// device identity curve (AndroidKeyStore constraint).
///
/// Pattern: `Noise_IK_P256_ChaChaPoly_BLAKE2s`
/// Prologue: SHA-256 of APK signing cert (app key) — binds handshake to the app.
#[derive(Clone)]
pub struct NoiseHandler {
    sk_server: SecretKey,
    pk_server_bytes: Vec<u8>,
}

impl NoiseHandler {
    pub fn new(sk_server: SecretKey) -> Self {
        let pk_server_bytes = sk_server
            .public_key()
            .to_encoded_point(false)
            .to_bytes()
            .to_vec();
        Self {
            sk_server,
            pk_server_bytes,
        }
    }

    /// Returns the server's public key as 65-byte SEC1 uncompressed (0x04 || x || y).
    pub fn pk_server_bytes(&self) -> &[u8] {
        &self.pk_server_bytes
    }

    /// Perform Noise IK handshake as the responder.
    ///
    /// Reads the client's ephemeral key, sends the server's response, and returns
    /// the transport state for encrypted message exchange.
    pub async fn handshake(
        &self,
        stream: &mut TcpStream,
        prologue: &[u8],
    ) -> Result<TransportState> {
        let pattern = "Noise_IK_P256_ChaChaPoly_BLAKE2s"
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid noise pattern: {:?}", e))?;

        let sk_bytes = self.sk_server.to_bytes();
        let builder = Builder::new(pattern)
            .prologue(prologue)?
            .local_private_key(&sk_bytes)?;

        let mut handshake = builder.build_responder()?;

        // Read msg1: accumulate bytes until snow can parse (IK pattern ~146B)
        let mut buf = [0u8; 4096];
        let mut offset = 0;
        loop {
            let n = timeout(Duration::from_secs(10), stream.read(&mut buf[offset..]))
                .await
                .map_err(|_| anyhow::anyhow!("handshake read timeout"))??;
            if n == 0 {
                anyhow::bail!("connection closed during handshake");
            }
            offset += n;
            match handshake.read_message(&buf[..offset], &mut []) {
                Ok(_) => break,
                Err(snow::Error::Input) if offset < 4096 => continue,
                Err(e) => anyhow::bail!("handshake msg1 error: {e}"),
            }
        }

        let mut msg2 = [0u8; 4096];
        let len = handshake.write_message(&[], &mut msg2)?;
        stream.write_all(&msg2[..len]).await?;

        let transport = handshake.into_transport_mode()?;
        Ok(transport)
    }

    /// Handle a full Noise connection: handshake + encrypted API message loop.
    ///
    /// After the Noise IK handshake, the client sends length-prefixed encrypted
    /// JSON requests. The server decrypts, routes to the appropriate handler,
    /// encrypts the response, and sends it back.
    ///
    /// Message format (after handshake):
    ///   [2-byte BE length][encrypted payload]
    ///
    /// The payload is a JSON-serialized `NoiseApiRequest`.
    /// The response is a JSON-serialized `ApiResponse` (same format as HTTP API).
    pub async fn handle_connection(
        &self,
        mut stream: TcpStream,
        prologue: &[u8],
        state: std::sync::Arc<AppState>,
    ) -> Result<()> {
        let mut transport = self.handshake(&mut stream, prologue).await?;
        tracing::info!("noise handshake complete");

        let mut buf = vec![0u8; 65536];
        let mut out = vec![0u8; 65536];

        loop {
            // Read 2-byte length header
            let mut len_buf = [0u8; 2];
            if stream.read_exact(&mut len_buf).await.is_err() {
                tracing::debug!("noise client disconnected");
                break;
            }
            let msg_len = u16::from_be_bytes(len_buf) as usize;

            if msg_len > buf.len() {
                tracing::warn!("noise message too large: {msg_len} bytes");
                break;
            }

            // Read encrypted message
            if stream.read_exact(&mut buf[..msg_len]).await.is_err() {
                tracing::warn!("noise read failed");
                break;
            }

            // Decrypt
            let plaintext_len = match transport.read_message(&buf[..msg_len], &mut out) {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!("noise decrypt failed: {e}");
                    break;
                }
            };

            // Parse JSON request
            let request: NoiseApiRequest = match serde_json::from_slice(&out[..plaintext_len]) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("noise request parse failed: {e}");
                    let response = serde_json::json!({
                        "message": "invalid request",
                        "data": null
                    });
                    let response_json = serde_json::to_vec(&response)?;
                    let encrypted_len = transport.write_message(&response_json, &mut buf)?;
                    let len = (encrypted_len as u16).to_be_bytes();
                    stream.write_all(&len).await?;
                    stream.write_all(&buf[..encrypted_len]).await?;
                    continue;
                }
            };

            // Route to handler
            let response = route_noise_request(&state, request);

            // Serialize response
            let response_json = serde_json::to_vec(&response)
                .map_err(|e| anyhow::anyhow!("failed to serialize response: {e}"))?;

            // Encrypt response
            let encrypted_len = transport.write_message(&response_json, &mut buf)?;

            // Send length + encrypted response
            let len = (encrypted_len as u16).to_be_bytes();
            stream.write_all(&len).await?;
            stream.write_all(&buf[..encrypted_len]).await?;
        }

        Ok(())
    }
}

/// API requests over Noise transport.
///
/// Uses serde's internally tagged enum to route based on the `method` field.
#[derive(Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
enum NoiseApiRequest {
    Register(freesky_shared::types::RegisterRequest),
    Post(freesky_shared::types::PostRequest),
    Feed(freesky_shared::types::FeedRequest),
    Report(freesky_shared::types::ReportRequest),
}

/// Route a Noise API request to the appropriate handler.
///
/// Returns a `serde_json::Value` with `{ message, data }` structure,
/// matching the HTTP API's `ApiResponse` format.
fn route_noise_request(
    state: &std::sync::Arc<AppState>,
    request: NoiseApiRequest,
) -> serde_json::Value {
    match request {
        NoiseApiRequest::Register(req) => {
            // Validate APK signing key
            let apk_sha1 = req.apk_cert_sha1.trim().to_uppercase().replace(':', "");
            if apk_sha1 != state.trusted_app_key {
                tracing::warn!("noise register rejected: untrusted APK signing key");
                return serde_json::json!({ "message": "untrusted APK signing key", "data": null });
            }

            // Validate pk_dev
            if !freesky_shared::crypto::validate_pk_dev(&req.pk_dev) {
                tracing::warn!("noise register rejected: invalid pk_dev");
                return serde_json::json!({ "message": "invalid pk_dev", "data": null });
            }

            // Register device
            match state.db.register_device(&req.pk_dev) {
                Ok(result) if !result.is_banned => {
                    tracing::info!(
                        "noise register success: name={} color={}",
                        result.name,
                        result.color
                    );
                    let server_noise_pk = state.noise.pk_server_bytes().to_vec();
                    serde_json::json!({
                        "message": "success",
                        "data": {
                            "name": result.name,
                            "color": result.color,
                            "encrypted_sk_comm": result.encrypted_sk_comm,
                            "server_noise_pk": server_noise_pk
                        }
                    })
                }
                Ok(_) => {
                    tracing::warn!("noise register rejected: device is banned");
                    serde_json::json!({ "message": "device is banned", "data": null })
                }
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("no group key exists") {
                        tracing::warn!("noise register rejected: no group key");
                        serde_json::json!({ "message": "no group key exists", "data": null })
                    } else {
                        tracing::error!("noise register db error: {e}");
                        serde_json::json!({ "message": "internal error", "data": null })
                    }
                }
            }
        }
        NoiseApiRequest::Post(req) => {
            // Validate author_pk
            if !freesky_shared::crypto::validate_pk_dev(&req.author_pk) {
                tracing::warn!("noise post rejected: invalid author_pk");
                return serde_json::json!({ "message": "invalid author key", "data": null });
            }

            // Submit post
            match state.db.submit_post(&req) {
                Ok(result) => {
                    tracing::info!("noise post stored: id={}", result.id);
                    serde_json::json!({ "message": "success", "data": null })
                }
                Err(crate::queries::PostError::InvalidSignature) => {
                    tracing::warn!("noise post rejected: invalid ECDSA signature");
                    serde_json::json!({ "message": "invalid signature", "data": null })
                }
                Err(crate::queries::PostError::AuthorBanned) => {
                    tracing::warn!("noise post rejected: author is banned");
                    serde_json::json!({ "message": "author is banned", "data": null })
                }
                Err(e) => {
                    tracing::error!("noise post db error: {e}");
                    serde_json::json!({ "message": "internal error", "data": null })
                }
            }
        }
        NoiseApiRequest::Feed(req) => {
            tracing::debug!(
                cursor = ?req.cursor,
                limit = ?req.limit,
                "noise feed request"
            );
            match state.db.fetch_feed(req.cursor, req.limit) {
                Ok(result) => {
                    tracing::info!(
                        "noise feed served: {} posts, next_cursor={:?}",
                        result.posts.len(),
                        result.next_cursor
                    );
                    serde_json::json!({
                        "message": "success",
                        "data": {
                            "posts": result.posts,
                            "next_cursor": result.next_cursor
                        }
                    })
                }
                Err(e) => {
                    tracing::error!("noise feed db error: {e}");
                    serde_json::json!({ "message": "internal error", "data": null })
                }
            }
        }
        NoiseApiRequest::Report(_req) => {
            tracing::debug!("noise report request");
            serde_json::json!({ "message": "not implemented", "data": null })
        }
    }
}
