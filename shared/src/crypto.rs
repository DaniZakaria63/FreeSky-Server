use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use p256::PublicKey;
use p256::SecretKey;
use p256::ecdh::EphemeralSecret;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// HKDF salt for ECIES key derivation (PROTOCOL_SYNC.md §3.2).
/// Domain-separates the ECIES shared secret from other ECDH uses.
const ECIES_HKDF_SALT: &[u8] = b"freesky-ecies-v1";

/// HKDF info for ECIES key derivation (PROTOCOL_SYNC.md §3.2).
/// Labels the derived key as a "group key" for context binding.
const ECIES_HKDF_INFO: &[u8] = b"freesky-group-key";

pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

pub fn derive_name(pk_dev: &[u8]) -> String {
    let hash = sha256_hash(pk_dev);
    let truncated = &hash[..12];
    hex::encode(truncated)
}

pub fn derive_color(pk_dev: &[u8]) -> u8 {
    let hash = sha256_hash(pk_dev);
    hash[0] % 16
}

/// Validate that `pk_dev` is a valid secp256r1 SEC1 uncompressed public key.
///
/// Checks both the format (65 bytes, 0x04 prefix) and that the point
/// lies on the NIST P-256 curve. Returns `true` if valid.
pub fn validate_pk_dev(pk_dev: &[u8]) -> bool {
    if pk_dev.len() != 65 || pk_dev[0] != 0x04 {
        return false;
    }
    PublicKey::from_sec1_bytes(pk_dev).is_ok()
}

/// ECIES encrypt: encrypt `plaintext` to `recipient_pk` (65-byte SEC1 secp256r1).
///
/// Format: ephemeral_pk (65 bytes SEC1) || nonce (12 bytes) || ciphertext (plaintext_len + 16)
///
/// Returns an error if `recipient_pk` is not a valid secp256r1 SEC1 public key,
/// rather than panicking. This prevents mutex poisoning in the DB layer.
pub fn ecies_encrypt(recipient_pk: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
    let recipient = PublicKey::from_sec1_bytes(recipient_pk)
        .map_err(|_| "invalid secp256r1 SEC1 public key")?;

    let ephemeral = EphemeralSecret::random(&mut rand::rngs::OsRng);
    let ephemeral_pk = PublicKey::from(&ephemeral);
    let ephemeral_pk_bytes = ephemeral_pk.to_encoded_point(false).to_bytes();

    let shared_secret = ephemeral.diffie_hellman(&recipient);
    let shared_bytes = shared_secret.raw_secret_bytes();

    let hk = Hkdf::<Sha256>::new(Some(ECIES_HKDF_SALT), shared_bytes);
    let mut aes_key = [0u8; 32];
    hk.expand(ECIES_HKDF_INFO, &mut aes_key)
        .map_err(|_| "HKDF expand failed")?;

    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| "AES-256-GCM encryption failed")?;

    let mut result = Vec::with_capacity(65 + 12 + ciphertext.len());
    result.extend_from_slice(&ephemeral_pk_bytes);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// ECIES decrypt: decrypt data encrypted with [`ecies_encrypt`].
///
/// Wire format: ephemeral_pk (65 bytes SEC1) || nonce (12 bytes) || ciphertext
///
/// The `recipient_sk` is the recipient's secp256r1 private key. This is used
/// by devices to decrypt the group key, and by the server for future admin ops.
pub fn ecies_decrypt(recipient_sk: &SecretKey, encrypted: &[u8]) -> Result<Vec<u8>, &'static str> {
    if encrypted.len() < 65 + 12 + 16 {
        return Err("encrypted data too short");
    }

    let epk_bytes = &encrypted[..65];
    let nonce_bytes = &encrypted[65..65 + 12];
    let ciphertext = &encrypted[65 + 12..];

    let ephemeral_pk =
        PublicKey::from_sec1_bytes(epk_bytes).map_err(|_| "invalid ephemeral public key")?;

    let shared_secret =
        p256::ecdh::diffie_hellman(recipient_sk.to_nonzero_scalar(), ephemeral_pk.as_affine());
    let shared_bytes = shared_secret.raw_secret_bytes();

    let hk = Hkdf::<Sha256>::new(Some(ECIES_HKDF_SALT), shared_bytes);
    let mut aes_key = [0u8; 32];
    hk.expand(ECIES_HKDF_INFO, &mut aes_key)
        .map_err(|_| "HKDF expand failed")?;

    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "AES-256-GCM decryption failed")?;

    Ok(plaintext)
}

/// Verify an ECDSA secp256r1 signature over SHA-256(message).
///
/// `author_pk` must be a 65-byte SEC1 uncompressed public key.
/// `author_sig` must be a DER-encoded ECDSA signature (SHA256withECDSA).
/// Returns `true` if the signature is valid.
///
/// This matches the Android `Signature.sign("SHA256withECDSA", message)` flow:
/// both sides compute SHA-256(message) and verify the ECDSA signature.
pub fn ecdsa_verify(author_pk: &[u8], message: &[u8], author_sig: &[u8]) -> bool {
    let verifying_key = match VerifyingKey::from_sec1_bytes(author_pk) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = match Signature::from_der(author_sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    verifying_key.verify(message, &sig).is_ok()
}
