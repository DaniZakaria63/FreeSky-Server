use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;
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

pub fn ecies_encrypt(recipient_pk: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let recipient = PublicKey::from_sec1_bytes(recipient_pk)
        .expect("invalid secp256r1 SEC1 public key");

    let ephemeral = EphemeralSecret::random(&mut rand::rngs::OsRng);
    let ephemeral_pk = PublicKey::from(&ephemeral);
    let ephemeral_pk_bytes = ephemeral_pk.to_encoded_point(false).to_bytes();

    let shared_secret = ephemeral.diffie_hellman(&recipient);
    let shared_bytes = shared_secret.raw_secret_bytes();

    let hk = Hkdf::<Sha256>::new(Some(ECIES_HKDF_SALT), shared_bytes);
    let mut aes_key = [0u8; 32];
    hk.expand(ECIES_HKDF_INFO, &mut aes_key)
        .expect("HKDF expand should succeed for 32 bytes");

    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("AES-256-GCM encryption failed");

    let mut result = Vec::with_capacity(65 + 12 + ciphertext.len());
    result.extend_from_slice(&ephemeral_pk_bytes);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    result
}