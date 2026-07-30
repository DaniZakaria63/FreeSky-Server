use std::time::Duration;

use anyhow::Result;
use blake2::Blake2s256;
use blake2::Digest;
use chacha20poly1305::AeadInPlace;
use chacha20poly1305::KeyInit;
use p256::SecretKey;
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::generic_array::GenericArray;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::Deserialize;
use snow::{Builder, TransportState};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::AppState;

fn blake2s(data: &[u8]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(data);
    h.finalize().into()
}

fn hmac_blake2s(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let hashed_key = if key.len() > BLOCK_SIZE {
        blake2s(key)
    } else {
        let mut arr = [0u8; 32];
        arr[..key.len()].copy_from_slice(key);
        arr
    };
    let mut k_pad = [0u8; BLOCK_SIZE];
    let hk_len = hashed_key.len().min(BLOCK_SIZE);
    k_pad[..hk_len].copy_from_slice(&hashed_key[..hk_len]);
    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= k_pad[i];
        opad[i] ^= k_pad[i];
    }
    let inner = blake2s(&[&ipad[..], data].concat());
    blake2s(&[&opad[..], &inner[..]].concat())
}

fn noise_hkdf(ck: &[u8], input: &[u8], count: usize) -> Vec<Vec<u8>> {
    let temp = hmac_blake2s(ck, input).to_vec();
    let out1 = hmac_blake2s(&temp, &[1u8]).to_vec();
    if count == 1 {
        return vec![out1];
    }
    let mut in2 = out1.clone();
    in2.push(2u8);
    let out2 = hmac_blake2s(&temp, &in2).to_vec();
    vec![out1, out2]
}

/// Debug: compute expected Noise NK responder state from msg1 bytes.
/// Logs intermediate values to help diagnose handshake failures.
fn debug_noise_state(msg1: &[u8], sk_server: &SecretKey, prologue: &[u8]) {
    if msg1.len() < 65 {
        tracing::error!("DEBUG_NOISE: msg1 too short ({} bytes, need >=65)", msg1.len());
        return;
    }
    let epk = &msg1[..65];
    let pk_server = sk_server.public_key().to_encoded_point(false).to_bytes().to_vec();

    tracing::error!("DEBUG_NOISE: server_pk    = {}", hex::encode(&pk_server));

    let protocol_name = b"Noise_NK_P256_ChaChaPoly_BLAKE2s";
    let h = if protocol_name.len() <= 32 {
        let mut arr = [0u8; 32];
        arr[..protocol_name.len()].copy_from_slice(protocol_name);
        arr
    } else {
        blake2s(protocol_name)
    };
    let mut h = h;
    let ck = h;
    tracing::error!("DEBUG_NOISE: h_0 (name copy)  = {}", hex::encode(h));
    tracing::error!("DEBUG_NOISE: ck_0 = {}", hex::encode(ck));

    // mixHash(prologue)
    h = blake2s(&[&h[..], prologue].concat());
    tracing::error!("DEBUG_NOISE: h_1 (prologue)  = {}", hex::encode(h));

    // Pre-message: mixHash(rs)
    let rs = &pk_server;
    h = blake2s(&[&h[..], rs].concat());
    tracing::error!("DEBUG_NOISE: h_2 (+ rs)      = {}", hex::encode(h));

    // Token E: mixHash(re)
    h = blake2s(&[&h[..], epk].concat());
    tracing::error!("DEBUG_NOISE: h_3 (+ re)      = {}", hex::encode(h));
    tracing::error!("DEBUG_NOISE: re (eph pk)     = {}", hex::encode(epk));

    // Token Dh(Es): mixKey(DH(s_priv, re))
    let shared = {
        let s_scalar = sk_server.to_nonzero_scalar();
        let re_pk = match p256::PublicKey::from_sec1_bytes(epk) {
            Ok(pk) => pk,
            Err(_) => {
                tracing::error!("DEBUG_NOISE: failed to parse re PK from SEC1");
                return;
            }
        };
        diffie_hellman(s_scalar, re_pk.as_affine())
    };
    let shared_bytes = shared.raw_secret_bytes();
    tracing::error!("DEBUG_NOISE: shared (DH)     = {}", hex::encode(shared_bytes));

    let hkdf_out = noise_hkdf(&ck, shared_bytes, 2);
    tracing::error!("DEBUG_NOISE: new_ck          = {}", hex::encode(&hkdf_out[0]));
    tracing::error!("DEBUG_NOISE: cipher_key      = {}", hex::encode(&hkdf_out[1]));

    // Decrypt: EncryptAndHash uses nonce=0, AAD=h_3
    if msg1.len() >= 81 {
        let tag = &msg1[65..81];
        tracing::error!("DEBUG_NOISE: tag (from msg1) = {}", hex::encode(tag));

        let result = chacha20poly1305::ChaCha20Poly1305::new(
            GenericArray::from_slice(&hkdf_out[1]),
        )
        .decrypt_in_place_detached(
            &[0u8; 12].into(),
            &h,
            &mut [][..],
            GenericArray::from_slice(tag),
        );
        match result {
            Ok(()) => tracing::error!("DEBUG_NOISE: tag DECRYPTION SUCCESSFUL"),
            Err(e) => tracing::error!("DEBUG_NOISE: tag DECRYPTION FAILED: {e:?}"),
        }
    } else {
        tracing::error!("DEBUG_NOISE: msg1 too short for tag (need 81, got {})", msg1.len());
    }
}

/// Noise NK responder using secp256r1 (P-256) for DH, matching the Android
/// device identity curve (AndroidKeyStore constraint).
///
/// Pattern: `Noise_NK_P256_ChaChaPoly_BLAKE2s`
/// Prologue: SHA-256 of APK signing cert (app key) — binds handshake to the app.
///
/// NK pattern: the initiator (client) knows the responder's (server) static key.
/// msg1 = e, es (ephemeral + DH(ephemeral,server_static), no initiator static key)
/// msg2 = e, ee (responder ephemeral + DH(ephemeral,responder_ephemeral))
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

    /// Perform Noise NK handshake as the responder.
    ///
    /// Reads the client's ephemeral key, sends the server's response, and returns
    /// the transport state for encrypted message exchange.
    pub async fn handshake(
        &self,
        stream: &mut TcpStream,
        prologue: &[u8],
    ) -> Result<TransportState> {
        let pattern = "Noise_NK_P256_ChaChaPoly_BLAKE2s"
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid noise pattern: {:?}", e))?;

        let sk_bytes = self.sk_server.to_bytes();
        let builder = Builder::new(pattern)
            .prologue(prologue)?
            .local_private_key(&sk_bytes)?;

        let mut handshake = builder.build_responder()?;

        // Read msg1: accumulate bytes until snow can parse (NK msg1 ~81B)
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
                Err(e) => {
                    debug_noise_state(&buf[..offset], &self.sk_server, prologue);
                    anyhow::bail!("handshake msg1 error: {e}");
                }
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
    /// After the Noise NK handshake, the client sends length-prefixed encrypted
    /// JSON requests. The server decrypts, routes to the appropriate handler,
    /// encrypts the response, and sends it back.
    ///
    /// The server also pushes unsolicited notifications (e.g. "new_post") to
    /// the client over the same encrypted channel when other clients publish.
    /// This is achieved with `tokio::select!` on a split stream: the read half
    /// receives client requests, while a `broadcast::Receiver` delivers server
    /// notifications. Both write to the write half.
    ///
    /// Message format (after handshake):
    ///   [2-byte BE length][encrypted payload]
    ///
    /// The payload is a JSON-serialized `NoiseApiRequest` (client → server)
    /// or `ApiResponse` / `Notification` (server → client).
    pub async fn handle_connection(
        &self,
        mut stream: TcpStream,
        prologue: &[u8],
        state: std::sync::Arc<AppState>,
    ) -> Result<()> {
        let mut transport = self.handshake(&mut stream, prologue).await?;
        tracing::info!("noise handshake complete");

        // Split the stream so we can read and write concurrently.
        // The read half is wrapped in a BufReader for cancellation-safe
        // reads in the select! loop (partial reads are buffered).
        let (read_half, write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let mut writer = write_half;

        // Subscribe to the server-wide notification broadcast channel.
        let mut notification_rx = state.notifications.subscribe();

        let mut buf = vec![0u8; 65536];
        let mut out = vec![0u8; 65536];
        let mut read_buf = vec![0u8; 65536 + 2];
        let mut read_pos = 0;

        loop {
            tokio::select! {
                // ── Incoming data from client ──
                n = reader.read(&mut read_buf[read_pos..]) => {
                    match n {
                        Ok(0) => {
                            tracing::debug!("noise client disconnected");
                            break;
                        }
                        Ok(n) => {
                            read_pos += n;
                            // Process as many complete messages as available.
                            loop {
                                if read_pos < 2 {
                                    break;
                                }
                                let msg_len = u16::from_be_bytes([
                                    read_buf[0],
                                    read_buf[1],
                                ]) as usize;
                                if read_pos < 2 + msg_len {
                                    break;
                                }

                                // Decrypt the message.
                                let encrypted = &read_buf[2..2 + msg_len];
                                let plaintext_len = match transport.read_message(encrypted, &mut out) {
                                    Ok(n) => n,
                                    Err(e) => {
                                        tracing::warn!("noise decrypt failed: {e}");
                                        read_buf.copy_within(2 + msg_len..read_pos, 0);
                                        read_pos -= 2 + msg_len;
                                        continue;
                                    }
                                };

                                // Parse JSON request.
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
                                        writer.write_all(&len).await?;
                                        writer.write_all(&buf[..encrypted_len]).await?;

                                        read_buf.copy_within(2 + msg_len..read_pos, 0);
                                        read_pos -= 2 + msg_len;
                                        continue;
                                    }
                                };

                                // Route to handler.
                                let response = route_noise_request(&state, request).await;

                                // Encrypt and send response.
                                let response_json = serde_json::to_vec(&response)
                                    .map_err(|e| anyhow::anyhow!("failed to serialize response: {e}"))?;
                                let encrypted_len = transport.write_message(&response_json, &mut buf)?;
                                let len = (encrypted_len as u16).to_be_bytes();
                                writer.write_all(&len).await?;
                                writer.write_all(&buf[..encrypted_len]).await?;

                                // Shift remaining data to front of buffer.
                                read_buf.copy_within(2 + msg_len..read_pos, 0);
                                read_pos -= 2 + msg_len;
                            }
                        }
                        Err(e) => {
                            tracing::warn!("noise read error: {e}");
                            break;
                        }
                    }
                }

                // ── Outgoing notification from server ──
                notification = notification_rx.recv() => {
                    let notification = match notification {
                        Ok(n) => n,
                        Err(_) => {
                            tracing::debug!("notification channel closed");
                            break;
                        }
                    };
                    let notification_json = serde_json::to_vec(&notification)?;
                    let encrypted_len = transport.write_message(&notification_json, &mut buf)?;
                    let len = (encrypted_len as u16).to_be_bytes();
                    writer.write_all(&len).await?;
                    writer.write_all(&buf[..encrypted_len]).await?;
                }
            }
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
    Thread(freesky_shared::types::ThreadRequest),
}

/// Route a Noise API request to the appropriate handler.
///
/// Returns a `serde_json::Value` with `{ message, data }` structure,
/// matching the HTTP API's `ApiResponse` format.
async fn route_noise_request(
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
            match state.db.register_device(&req.pk_dev).await {
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
            match state.db.submit_post(&req).await {
                Ok(result) => {
                    tracing::info!("noise post stored: id={}", result.id);

                    // Broadcast notification to all connected clients so they
                    // know to fetch the feed for new posts.
                    let notification = freesky_shared::types::Notification {
                        notification_type: "new_post".to_string(),
                        timestamp: req.timestamp,
                    };
                    let _ = state.notifications.send(notification);

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
            match state.db.fetch_feed(req.cursor, req.limit).await {
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
        NoiseApiRequest::Thread(req) => {
            tracing::debug!(post_id = req.post_id, "noise thread request");
            match state.db.fetch_thread(req.post_id).await {
                Ok(result) => {
                    serde_json::json!({
                        "message": "success",
                        "data": {
                            "post": result.post,
                            "replies": result.replies
                        }
                    })
                }
                Err(crate::queries::PostError::NotFound) => {
                    serde_json::json!({ "message": "post not found", "data": null })
                }
                Err(e) => {
                    tracing::error!("noise thread db error: {e}");
                    serde_json::json!({ "message": "internal error", "data": null })
                }
            }
        }
        NoiseApiRequest::Report(req) => {
            tracing::debug!(post_id = req.post_id, "noise report request");
            match state.db.submit_report(&req).await {
                Ok(_) => {
                    serde_json::json!({ "message": "success", "data": null })
                }
                Err(crate::queries::PostError::NotFound) => {
                    serde_json::json!({ "message": "post not found", "data": null })
                }
                Err(e) => {
                    tracing::error!("noise report db error: {e}");
                    serde_json::json!({ "message": "internal error", "data": null })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use snow::Builder;

    #[test]
    fn nk_p256_msg1_size() {
        let prologue = b"TESTPROLOGUE12345";
        let responder_key = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let responder_pk = responder_key
            .public_key()
            .to_encoded_point(false)
            .to_bytes()
            .to_vec();
        let pattern: snow::params::NoiseParams = "Noise_NK_P256_ChaChaPoly_BLAKE2s"
            .parse()
            .unwrap();

        let mut initiator = snow::Builder::new(pattern.clone())
            .prologue(prologue)
            .unwrap()
            .local_private_key(&p256::SecretKey::random(&mut rand::rngs::OsRng).to_bytes())
            .unwrap()
            .remote_public_key(&responder_pk)
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut responder = snow::Builder::new(pattern)
            .prologue(prologue)
            .unwrap()
            .local_private_key(&responder_key.to_bytes())
            .unwrap()
            .build_responder()
            .unwrap();

        let mut msg1 = [0u8; 512];
        let len1 = initiator.write_message(&[], &mut msg1).unwrap();
        assert_eq!(len1, 81);
        let mut buf1 = [0u8; 512];
        responder.read_message(&msg1[..len1], &mut buf1).unwrap();
        let mut msg2 = [0u8; 512];
        let len2 = responder.write_message(&[], &mut msg2).unwrap();
        assert_eq!(len2, 81);
    }

    #[test]
    fn nk_p256_handshake_snow_to_snow() {
        let prologue = b"TESTPROLOGUE12345";
        let responder_key = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let responder_pk = responder_key
            .public_key()
            .to_encoded_point(false)
            .to_bytes()
            .to_vec();
        let pattern: snow::params::NoiseParams = "Noise_NK_P256_ChaChaPoly_BLAKE2s"
            .parse()
            .unwrap();
        let mut responder = Builder::new(pattern.clone())
            .prologue(prologue)
            .unwrap()
            .local_private_key(&responder_key.to_bytes())
            .unwrap()
            .build_responder()
            .unwrap();
        let mut initiator = Builder::new(pattern)
            .prologue(prologue)
            .unwrap()
            .local_private_key(&p256::SecretKey::random(&mut rand::rngs::OsRng).to_bytes())
            .unwrap()
            .remote_public_key(&responder_pk)
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut msg1 = [0u8; 512];
        let len1 = initiator.write_message(&[], &mut msg1).unwrap();
        let mut buf1 = [0u8; 512];
        responder.read_message(&msg1[..len1], &mut buf1).unwrap();
        let mut msg2 = [0u8; 512];
        let len2 = responder.write_message(&[], &mut msg2).unwrap();
        let mut buf2 = [0u8; 512];
        initiator.read_message(&msg2[..len2], &mut buf2).unwrap();
        let mut init_transport = initiator.into_transport_mode().unwrap();
        let mut resp_transport = responder.into_transport_mode().unwrap();
        let mut enc = [0u8; 512];
        let elen = init_transport.write_message(b"hello", &mut enc).unwrap();
        let mut dec = [0u8; 512];
        let dlen = resp_transport.read_message(&enc[..elen], &mut dec).unwrap();
        assert_eq!(&dec[..dlen], b"hello");
    }

    /// Replicates Android's Noise NK initiator logic exactly (NoiseProtocol.kt).
    /// Feeds msg1 into a snow responder to verify interop.
    #[test]
    fn nk_p256_manual_initiator_vs_snow_responder() {
        use blake2::Blake2s256;
        use blake2::Digest;
        use chacha20poly1305::{AeadInPlace, KeyInit};
        use p256::ecdh::diffie_hellman;
        use p256::elliptic_curve::generic_array::GenericArray;

        fn blake2s(data: &[u8]) -> [u8; 32] {
            let mut h = Blake2s256::new();
            h.update(data);
            h.finalize().into()
        }

        fn hmac_blake2s(key: &[u8], data: &[u8]) -> [u8; 32] {
            const BLOCK_SIZE: usize = 64;
            let hashed_key = if key.len() > BLOCK_SIZE {
                blake2s(key)
            } else {
                let mut arr = [0u8; 32];
                arr[..key.len()].copy_from_slice(key);
                arr
            };
            let mut k_pad = [0u8; BLOCK_SIZE];
            let hk_len = hashed_key.len().min(BLOCK_SIZE);
            k_pad[..hk_len].copy_from_slice(&hashed_key[..hk_len]);
            let mut ipad = [0x36u8; BLOCK_SIZE];
            let mut opad = [0x5cu8; BLOCK_SIZE];
            for i in 0..BLOCK_SIZE {
                ipad[i] ^= k_pad[i];
                opad[i] ^= k_pad[i];
            }
            let inner = blake2s(&[&ipad[..], data].concat());
            blake2s(&[&opad[..], &inner[..]].concat())
        }

        fn noise_hkdf(ck: &[u8], input: &[u8], count: usize) -> Vec<Vec<u8>> {
            let temp = hmac_blake2s(ck, input).to_vec();
            let out1 = hmac_blake2s(&temp, &[1u8]).to_vec();
            if count == 1 {
                return vec![out1];
            }
            let mut in2 = out1.clone();
            in2.push(2u8);
            let out2 = hmac_blake2s(&temp, &in2).to_vec();
            vec![out1, out2]
        }

        let prologue = b"TESTPROLOGUE12345";

        let responder_sk = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let responder_pk_bytes = responder_sk
            .public_key()
            .to_encoded_point(false)
            .to_bytes()
            .to_vec();

        let eph_sk = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let eph_pk_bytes = eph_sk
            .public_key()
            .to_encoded_point(false)
            .to_bytes()
            .to_vec();

        let protocol_name = b"Noise_NK_P256_ChaChaPoly_BLAKE2s";
        let h_init: [u8; 32] = if protocol_name.len() <= 32 {
            let mut padded = [0u8; 32];
            padded[..protocol_name.len()].copy_from_slice(protocol_name);
            padded
        } else {
            blake2s(protocol_name)
        };
        let mut h = h_init;
        let mut ck = h;

        h = blake2s(&[&h[..], prologue].concat());
        h = blake2s(&[&h[..], &responder_pk_bytes].concat());
        h = blake2s(&[&h[..], &eph_pk_bytes].concat());

        let shared = {
            let eph_scalar = eph_sk.to_nonzero_scalar();
            let rs_pk = p256::PublicKey::from_sec1_bytes(&responder_pk_bytes).unwrap();
            diffie_hellman(eph_scalar, rs_pk.as_affine())
        };
        let hkdf_out = noise_hkdf(&ck, shared.raw_secret_bytes(), 2);
        ck = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hkdf_out[0]);
            arr
        };
        let cipher_key = &hkdf_out[1];

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&0u64.to_le_bytes());
        let tag = chacha20poly1305::ChaCha20Poly1305::new(
            &GenericArray::from_slice(cipher_key),
        )
        .encrypt_in_place_detached(&nonce_bytes.into(), &h, &mut [][..])
        .unwrap();

        h = blake2s(&[&h[..], &tag].concat());

        let msg1 = [&eph_pk_bytes[..], &tag].concat();
        assert_eq!(msg1.len(), 81);

        let pattern: snow::params::NoiseParams = "Noise_NK_P256_ChaChaPoly_BLAKE2s"
            .parse()
            .unwrap();
        let mut snow_resp = snow::Builder::new(pattern)
            .prologue(prologue)
            .unwrap()
            .local_private_key(&responder_sk.to_bytes())
            .unwrap()
            .build_responder()
            .unwrap();

        let mut buf1 = [0u8; 512];
        snow_resp
            .read_message(&msg1, &mut buf1)
            .expect("manual initiator -> snow responder msg1 decrypt");

        let mut msg2 = [0u8; 512];
        let len2 = snow_resp.write_message(&[], &mut msg2).unwrap();
        assert_eq!(len2, 81);

        let re_bytes = &msg2[..65];
        h = blake2s(&[&h[..], re_bytes].concat());

        let re_pk = p256::PublicKey::from_sec1_bytes(re_bytes).unwrap();
        let shared2 = {
            let eph_scalar = eph_sk.to_nonzero_scalar();
            diffie_hellman(eph_scalar, re_pk.as_affine())
        };
        let hkdf_out2 = noise_hkdf(&ck, shared2.raw_secret_bytes(), 2);
        ck = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hkdf_out2[0]);
            arr
        };
        let cipher_key2 = &hkdf_out2[1];

        let enc_payload = &msg2[65..len2];
        chacha20poly1305::ChaCha20Poly1305::new(
            &GenericArray::from_slice(cipher_key2),
        )
        .decrypt_in_place_detached(&[0u8; 12].into(), &h, &mut [][..], enc_payload.into())
        .expect("msg2 decrypt failed");

        let _ = blake2s(&[&h[..], enc_payload].concat());

        let split_out = noise_hkdf(&ck, &[], 2);

        let mut transport = snow_resp.into_transport_mode().unwrap();
        let mut enc = [0u8; 512];
        let elen = transport.write_message(b"hello from server", &mut enc).unwrap();
        let (ct, tag_bytes) = enc[..elen].split_at(elen - 16);
        chacha20poly1305::ChaCha20Poly1305::new(
            &GenericArray::from_slice(&split_out[1]),
        )
        .decrypt_in_place_detached(
            &[0u8; 12].into(),
            &[],
            &mut ct.to_vec(),
            GenericArray::from_slice(tag_bytes),
        )
        .expect("transport decrypt failed");
    }
}
