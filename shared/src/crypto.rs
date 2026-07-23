use sha2::{Digest, Sha256};

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
