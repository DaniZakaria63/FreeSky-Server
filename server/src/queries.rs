use anyhow::Result;
use chrono::Utc;
use rand::Rng;
use rusqlite::params;

use crate::db::Database;

impl Database {
    /// Check if a device is banned.
    pub fn is_device_banned(&self, pk_dev: &[u8]) -> Result<bool> {
        let conn = self.conn();
        let banned_at: Option<i64> = conn
            .query_row(
                "SELECT banned_at FROM devices WHERE pk_dev = ?",
                params![pk_dev],
                |row| row.get(0),
            )
            .ok()
            .flatten();
        Ok(banned_at.is_some())
    }

    /// Get the existing community group key, or create one if this is the first device.
    /// The group key is stored in the `mls_group_state` column (32 bytes for now;
    /// will hold serialized MLS group state when openmls is integrated).
    pub fn get_or_create_group_key(&self) -> Result<Vec<u8>> {
        let conn = self.conn();
        let now = Utc::now().timestamp();

        // Try to read existing group key
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

        // First device — generate a new group key
        let group_key: [u8; 32] = rand::thread_rng().r#gen();
        conn.execute(
            "INSERT INTO community (id, mls_group_state, created_at, member_count) VALUES (1, ?, ?, 0)",
            params![group_key.as_slice(), now],
        )?;
        Ok(group_key.to_vec())
    }

    /// Insert a new device or update an existing one's encrypted group key.
    /// Returns `true` if the device was newly inserted, `false` if it already existed.
    pub fn upsert_device(
        &self,
        pk_dev: &[u8],
        name: &str,
        color: u8,
        encrypted_sk_comm: &[u8],
    ) -> Result<bool> {
        let conn = self.conn();
        let now = Utc::now().timestamp();

        // Check if device already exists
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
    pub fn increment_member_count(&self) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE community SET member_count = member_count + 1 WHERE id = 1",
            [],
        )?;
        Ok(())
    }
}
