use anyhow::Result;
use chrono::Utc;
use rand::RngCore;
use rand::rngs::OsRng;
use rusqlite::{Connection, params};

use crate::db::Database;

/// Result of a device registration attempt.
pub struct RegisterResult {
    pub name: String,
    pub color: u8,
    pub encrypted_sk_comm: Vec<u8>,
    pub is_banned: bool,
}

// ─── Private helper functions ───
// Each takes &Connection — no locking, just SQL operations.
// The caller (register_device) holds the lock for the entire transaction.

/// Check if a device is banned.
fn check_banned(conn: &Connection, pk_dev: &[u8]) -> bool {
    let banned_at: Option<i64> = conn
        .query_row(
            "SELECT banned_at FROM devices WHERE pk_dev = ?",
            params![pk_dev],
            |row| row.get(0),
        )
        .ok()
        .flatten();
    banned_at.is_some()
}

/// Get the existing community group key, or create one if this is the first device.
fn get_or_create_group_key(conn: &Connection, now: i64) -> Result<Vec<u8>> {
    let existing: Option<Vec<u8>> = conn
        .query_row(
            "SELECT mls_group_state FROM community WHERE id = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .ok();

    if let Some(key) = existing {
        return Ok(key);
    }

    // First device — generate a new group key using the OS CSPRNG
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    conn.execute(
        "INSERT INTO community (id, mls_group_state, created_at, member_count) VALUES (1, ?, ?, 0)",
        params![key.as_slice(), now],
    )?;
    Ok(key.to_vec())
}

/// Insert a new device or update an existing one's encrypted group key.
/// Returns `true` if the device was newly inserted.
fn upsert_device(
    conn: &Connection,
    pk_dev: &[u8],
    name: &str,
    color: u8,
    encrypted_sk_comm: &[u8],
    now: i64,
) -> Result<bool> {
    let exists: bool = conn
        .query_row(
            "SELECT 1 FROM devices WHERE pk_dev = ?",
            params![pk_dev],
            |_| Ok(true),
        )
        .unwrap_or(false);

    if exists {
        conn.execute(
            "UPDATE devices SET encrypted_sk_comm = ?, last_seen_at = ? WHERE pk_dev = ?",
            params![encrypted_sk_comm, now, pk_dev],
        )?;
        Ok(false)
    } else {
        conn.execute(
            "INSERT INTO devices (pk_dev, user_name, user_color, encrypted_sk_comm, registered_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)",
            params![pk_dev, name, color, encrypted_sk_comm, now, now],
        )?;
        Ok(true)
    }
}

/// Increment the community member count.
fn increment_member_count(conn: &Connection) -> Result<()> {
    conn.execute(
        "UPDATE community SET member_count = member_count + 1 WHERE id = 1",
        [],
    )?;
    Ok(())
}

// ─── Public API ───

impl Database {
    /// Atomically register a device: check ban, get/create group key,
    /// ECIES-encrypt it, upsert the device, and update member count.
    ///
    /// All operations happen under a single mutex lock (one transaction).
    pub fn register_device(&self, pk_dev: &[u8]) -> Result<RegisterResult> {
        let conn = self.conn(); // ← Single lock for the entire operation
        let now = Utc::now().timestamp();

        // 1. Check if device is banned
        if check_banned(&conn, pk_dev) {
            return Ok(RegisterResult {
                name: String::new(),
                color: 0,
                encrypted_sk_comm: Vec::new(),
                is_banned: true,
            });
        }

        // 2. Derive deterministic identity from device key
        let name = freesky_shared::crypto::derive_name(pk_dev);
        let color = freesky_shared::crypto::derive_color(pk_dev);

        // 3. Get or create the community group key
        let group_key = get_or_create_group_key(&conn, now)?;

        // 4. ECIES-encrypt the group key to this device's public key
        let encrypted_sk_comm = freesky_shared::crypto::ecies_encrypt(pk_dev, &group_key)
            .map_err(|e| anyhow::anyhow!("ECIES encrypt failed: {e}"))?;

        // 5. Insert or update the device record
        let is_new = upsert_device(&conn, pk_dev, &name, color, &encrypted_sk_comm, now)?;

        // 6. Increment member count for new devices
        if is_new {
            increment_member_count(&conn)?;
        }

        Ok(RegisterResult {
            name,
            color,
            encrypted_sk_comm,
            is_banned: false,
        })
    }
}
