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

/// Get the existing community group key.
///
/// The key must already exist (created via `rotate_group_key`). If no key
/// exists, returns an error — the admin must trigger key-rotate first.
fn get_group_key(conn: &Connection) -> Result<Vec<u8>> {
    let key: Vec<u8> = conn
        .query_row(
            "SELECT mls_group_state FROM community WHERE id = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(|e| anyhow::anyhow!("no group key exists: {e}"))?;
    Ok(key)
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

/// Get all registered device public keys (excluding banned devices).
fn get_all_device_keys(conn: &Connection) -> Result<Vec<Vec<u8>>> {
    let mut stmt = conn.prepare("SELECT pk_dev FROM devices WHERE banned_at IS NULL")?;
    let rows = stmt
        .query_map([], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Create or rotate the community group key.
///
/// Generates a new 32-byte group key, re-ECIES-encrypts it for every
/// non-banned device, and stores it in `community.mls_group_state`.
///
/// If no community row exists yet, inserts one. Otherwise updates the existing row.
///
/// Returns the number of devices that received the new key.
fn rotate_group_key_inner(conn: &Connection, now: i64) -> Result<usize> {
    // 1. Generate a new group key
    let mut new_key = [0u8; 32];
    OsRng.fill_bytes(&mut new_key);

    // 2. Get all non-banned device keys
    let device_keys = get_all_device_keys(conn)?;

    // 3. Re-ECIES the new key for each device
    for pk_dev in &device_keys {
        let encrypted = freesky_shared::crypto::ecies_encrypt(pk_dev, &new_key)
            .map_err(|e| anyhow::anyhow!("ECIES encrypt failed for device: {e}"))?;
        conn.execute(
            "UPDATE devices SET encrypted_sk_comm = ?, last_seen_at = ? WHERE pk_dev = ?",
            params![encrypted, now, pk_dev],
        )?;
    }

    // 4. Insert or update the community group state
    let existing: Option<Vec<u8>> = conn
        .query_row(
            "SELECT mls_group_state FROM community WHERE id = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .ok();

    if existing.is_some() {
        conn.execute(
            "UPDATE community SET mls_group_state = ? WHERE id = 1",
            params![new_key.as_slice()],
        )?;
    } else {
        conn.execute(
            "INSERT INTO community (id, mls_group_state, created_at, member_count) VALUES (1, ?, ?, ?)",
            params![new_key.as_slice(), now, device_keys.len() as i64],
        )?;
    }

    Ok(device_keys.len())
}

// ─── Public API ───

impl Database {
    /// Atomically register a device: check ban, get group key,
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

        // 3. Get the community group key (must exist — admin creates via key-rotate)
        let group_key = get_group_key(&conn)?;

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

    /// Rotate the community group key.
    ///
    /// Generates a new 32-byte group key, re-ECIES-encrypts it for every
    /// non-banned device, and updates the `community.mls_group_state`.
    ///
    /// Returns the number of devices that received the new key.
    pub fn rotate_group_key(&self) -> Result<usize> {
        let conn = self.conn();
        let now = Utc::now().timestamp();
        rotate_group_key_inner(&conn, now)
    }
}
