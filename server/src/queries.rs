use anyhow::Result;
use chrono::Utc;
use rand::RngCore;
use rand::rngs::OsRng;
use rusqlite::{Connection, params};

use crate::db::Database;

/// Errors that can occur during post submission.
#[derive(Debug, thiserror::Error)]
pub enum PostError {
    #[error("invalid ECDSA signature")]
    InvalidSignature,
    #[error("author is banned")]
    AuthorBanned,
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
}

/// Result of a post submission.
#[derive(Debug)]
pub struct PostResult {
    pub id: i64,
}

/// Result of a device registration attempt.
pub struct RegisterResult {
    pub name: String,
    pub color: u8,
    pub encrypted_sk_comm: Vec<u8>,
    pub is_banned: bool,
}

/// Result of a feed fetch.
pub struct FeedResult {
    pub posts: Vec<freesky_shared::types::PostEntry>,
    pub next_cursor: Option<i64>,
}

// ─── Private helper functions ───
// Each takes &Connection — no locking, just SQL operations.
// The caller (register_device) holds the lock for the entire transaction.

/// Maximum number of posts returned per feed fetch (matches Android's OKHTTP page size).
pub const MAX_FEED_LIMIT: u32 = 100;

/// Default page size when the client doesn't specify one.
pub const DEFAULT_FEED_LIMIT: u32 = 50;

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

/// Verify ECDSA signature and store a post.
///
/// 1. Verifies the ECDSA secp256r1 signature over SHA-256(ciphertext_comm)
/// 2. Checks if the author is banned
/// 3. Inserts the post into the `posts` table
fn submit_post_inner(
    conn: &Connection,
    req: &freesky_shared::types::PostRequest,
) -> Result<PostResult, PostError> {
    // 1. Verify ECDSA signature (SHA256withECDSA over ciphertext_comm)
    if !freesky_shared::crypto::ecdsa_verify(&req.author_pk, &req.ciphertext_comm, &req.author_sig)
    {
        return Err(PostError::InvalidSignature);
    }

    // 2. Check if author is banned
    if check_banned(conn, &req.author_pk) {
        return Err(PostError::AuthorBanned);
    }

    // 3. Insert the post
    conn.execute(
        "INSERT INTO posts (ciphertext_comm, author_pk, author_sig, timestamp, mls_epoch) VALUES (?, ?, ?, ?, ?)",
        params![
            req.ciphertext_comm,
            req.author_pk,
            req.author_sig,
            req.timestamp,
            req.mls_epoch,
        ],
    )?;

    let id = conn.last_insert_rowid();

    Ok(PostResult { id })
}

/// Fetch a page of community posts, newest-first.
///
/// Pagination is cursor-based on `timestamp`. The cursor is the timestamp of
/// the oldest post in the previous batch; the next batch returns posts strictly
/// older than the cursor. `cursor=None` starts from the newest post.
///
/// `limit` is clamped to [1, MAX_FEED_LIMIT]; None → DEFAULT_FEED_LIMIT.
///
/// `next_cursor` is the timestamp of the last returned post, or None if the
/// batch was empty (no more posts to paginate).
fn fetch_feed_inner(
    conn: &Connection,
    cursor: Option<i64>,
    limit: Option<u32>,
) -> Result<FeedResult> {
    let clamped = limit.unwrap_or(DEFAULT_FEED_LIMIT).clamp(1, MAX_FEED_LIMIT);

    // Build "WHERE timestamp < ?" only when a cursor is present.
    let sql = if cursor.is_some() {
        "SELECT id, ciphertext_comm, author_pk, author_sig, timestamp, mls_epoch
         FROM posts WHERE timestamp < ? ORDER BY timestamp DESC, id DESC LIMIT ?"
    } else {
        "SELECT id, ciphertext_comm, author_pk, author_sig, timestamp, mls_epoch
         FROM posts ORDER BY timestamp DESC, id DESC LIMIT ?"
    };

    let mut stmt = conn.prepare(sql)?;
    let mapped = if let Some(c) = cursor {
        stmt.query_map(params![c, clamped as i64], map_post_entry)?
    } else {
        stmt.query_map(params![clamped as i64], map_post_entry)?
    };

    let mut posts: Vec<freesky_shared::types::PostEntry> = Vec::with_capacity(clamped as usize);
    let mut last_ts: Option<i64> = None;
    for entry in mapped {
        let entry = entry?;
        last_ts = Some(entry.timestamp);
        posts.push(entry);
    }

    // Only expose a next cursor if we returned a full batch (likely more rows).
    let next_cursor = last_ts.filter(|_| posts.len() as u32 >= clamped);

    Ok(FeedResult { posts, next_cursor })
}

/// Row mapper: builds a `PostEntry` from a SELECT in column order
/// `id, ciphertext_comm, author_pk, author_sig, timestamp, mls_epoch`.
fn map_post_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<freesky_shared::types::PostEntry> {
    let mls_epoch_i: i64 = row.get(5)?;
    Ok(freesky_shared::types::PostEntry {
        id: row.get(0)?,
        ciphertext_comm: row.get(1)?,
        author_pk: row.get(2)?,
        author_sig: row.get(3)?,
        timestamp: row.get(4)?,
        mls_epoch: mls_epoch_i as u64,
    })
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

    /// Submit a post: verify ECDSA signature, check ban, store in DB.
    ///
    /// Returns the post ID on success, or a `PostError` on failure.
    pub fn submit_post(
        &self,
        req: &freesky_shared::types::PostRequest,
    ) -> Result<PostResult, PostError> {
        let conn = self.conn();
        submit_post_inner(&conn, req)
    }

    /// Fetch a page of community posts, newest-first, cursor-paginated.
    ///
    /// `cursor` = timestamp of the oldest post in the previous batch (None → newest).
    /// `limit` is clamped to [1, MAX_FEED_LIMIT]; None → DEFAULT_FEED_LIMIT.
    /// Returns posts and a `next_cursor` for the next fetch (None when exhausted).
    pub fn fetch_feed(&self, cursor: Option<i64>, limit: Option<u32>) -> Result<FeedResult> {
        let conn = self.conn();
        fetch_feed_inner(&conn, cursor, limit)
    }
}

#[cfg(test)]
#[path = "queries_test.rs"]
mod tests;
