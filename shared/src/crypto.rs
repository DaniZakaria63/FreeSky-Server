use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey};

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

/// ECIES encrypt: encrypt `plaintext` to `recipient_pk` using X25519 + ChaCha20Poly1305.
///
/// Format: ephemeral_pk (32 bytes) || ciphertext (plaintext_len + 16 bytes)
///
/// The ephemeral key is generated fresh per call, so the shared secret is unique
/// each time. A zero nonce is safe because the encryption key (derived from the
/// unique shared secret) is never reused.
pub fn ecies_encrypt(recipient_pk: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(&recipient_pk[..32]);
    let recipient_pk = PublicKey::from(pk_bytes);

    let ephemeral = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let ephemeral_pk = PublicKey::from(&ephemeral);
    let shared_secret = ephemeral.diffie_hellman(&recipient_pk);

    // Derive encryption key from shared secret via SHA-256
    let key_bytes = sha256_hash(shared_secret.as_bytes());
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));

    // Zero nonce — safe because ephemeral key is unique per encryption
    let nonce = Nonce::from_slice(&[0u8; 12]);
    let ciphertext = cipher.encrypt(nonce, plaintext).expect("encryption failed");

    let mut result = Vec::with_capacity(32 + ciphertext.len());
    result.extend_from_slice(&ephemeral_pk.to_bytes());
    result.extend_from_slice(&ciphertext);
    result
}
