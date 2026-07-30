use anyhow::Result;
use chrono::Utc;
use rand::RngCore;
use rand::rngs::OsRng;

use crate::db::Database;

#[derive(Debug, thiserror::Error)]
pub enum PostError {
    #[error("invalid ECDSA signature")]
    InvalidSignature,
    #[error("author is banned")]
    AuthorBanned,
    #[error("not found")]
    NotFound,
    #[error("database error: {0}")]
    Database(String),
}

#[derive(Debug)]
pub struct PostResult {
    pub id: i64,
}

pub struct RegisterResult {
    pub name: String,
    pub color: u8,
    pub encrypted_sk_comm: Vec<u8>,
    pub is_banned: bool,
}

pub struct FeedResult {
    pub posts: Vec<freesky_shared::types::PostEntry>,
    pub next_cursor: Option<i64>,
}

#[derive(Debug)]
pub struct ThreadResult {
    pub post: freesky_shared::types::PostEntry,
    pub replies: Vec<freesky_shared::types::PostEntry>,
}

pub struct CreateCommentTriggerResult(pub bool);

pub const MAX_FEED_LIMIT: u32 = 100;
pub const DEFAULT_FEED_LIMIT: u32 = 50;

impl Database {
    async fn check_banned(&self, pk_dev: &[u8]) -> bool {
        let conn = match self.db.connect() {
            Ok(c) => c,
            Err(_) => return false,
        };
        let mut rows = match conn
            .query(
                "SELECT banned_at FROM devices WHERE pk_dev = ?",
                [pk_dev.to_vec()],
            )
            .await
        {
            Ok(r) => r,
            Err(_) => return false,
        };
        match rows.next().await.ok().flatten() {
            Some(row) => row.get::<Option<Vec<u8>>>(0).ok().flatten().is_some(),
            None => false,
        }
    }

    async fn get_group_key(&self) -> Result<Vec<u8>> {
        let conn = self.db.connect()?;
        let mut rows = conn
            .query("SELECT mls_group_state FROM community WHERE id = 1", ())
            .await?;
        let row = rows
            .next()
            .await?
            .ok_or_else(|| anyhow::anyhow!("no group key exists"))?;
        let key = row
            .get::<Vec<u8>>(0)
            .map_err(|e| anyhow::anyhow!("no group key exists: {e}"))?;
        Ok(key)
    }

    async fn upsert_device(
        &self,
        pk_dev: &[u8],
        name: &str,
        color: u8,
        encrypted_sk_comm: &[u8],
        now: i64,
    ) -> Result<bool> {
        let conn = self.db.connect()?;
        let mut rows = conn
            .query("SELECT 1 FROM devices WHERE pk_dev = ?", [pk_dev.to_vec()])
            .await?;
        let exists = rows.next().await?.is_some();

        if exists {
            conn.execute(
                "UPDATE devices SET encrypted_sk_comm = ?, last_seen_at = ? WHERE pk_dev = ?",
                (encrypted_sk_comm.to_vec(), now, pk_dev.to_vec()),
            )
            .await?;
            Ok(false)
        } else {
            conn.execute(
                "INSERT INTO devices (pk_dev, user_name, user_color, encrypted_sk_comm, registered_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)",
                (pk_dev.to_vec(), name.to_string(), color as i64, encrypted_sk_comm.to_vec(), now, now),
            )
            .await?;
            Ok(true)
        }
    }

    async fn increment_member_count(&self) -> Result<()> {
        let conn = self.db.connect()?;
        conn.execute(
            "UPDATE community SET member_count = member_count + 1 WHERE id = 1",
            (),
        )
        .await?;
        Ok(())
    }

    async fn get_all_device_keys(&self) -> Result<Vec<Vec<u8>>> {
        let conn = self.db.connect()?;
        let mut rows = conn
            .query("SELECT pk_dev FROM devices WHERE banned_at IS NULL", ())
            .await?;
        let mut keys: Vec<Vec<u8>> = Vec::new();
        while let Some(row) = rows.next().await? {
            if let Ok(key) = row.get::<Vec<u8>>(0) {
                keys.push(key);
            }
        }
        Ok(keys)
    }

    async fn rotate_group_key_inner(&self, now: i64) -> Result<usize> {
        let mut new_key = [0u8; 32];
        OsRng.fill_bytes(&mut new_key);
        let device_keys = self.get_all_device_keys().await?;

        for pk_dev in &device_keys {
            let encrypted = freesky_shared::crypto::ecies_encrypt(pk_dev, &new_key)
                .map_err(|e| anyhow::anyhow!("ECIES encrypt failed: {e}"))?;
            let conn = self.db.connect()?;
            conn.execute(
                "UPDATE devices SET encrypted_sk_comm = ?, last_seen_at = ? WHERE pk_dev = ?",
                (encrypted, now, pk_dev.clone()),
            )
            .await?;
        }

        let conn = self.db.connect()?;
        let mut rows = conn
            .query("SELECT mls_group_state FROM community WHERE id = 1", ())
            .await?;
        let exists = rows.next().await?.is_some();

        if exists {
            conn.execute(
                "UPDATE community SET mls_group_state = ? WHERE id = 1",
                [new_key.to_vec()],
            )
            .await?;
        } else {
            conn.execute(
                "INSERT INTO community (id, mls_group_state, created_at, member_count) VALUES (1, ?, ?, ?)",
                (new_key.to_vec(), now, device_keys.len() as i64),
            )
            .await?;
        }
        Ok(device_keys.len())
    }

    async fn ensure_device_registered(&self, pk_dev: &[u8]) -> std::result::Result<(), PostError> {
        let conn = self
            .db
            .connect()
            .map_err(|e| PostError::Database(e.to_string()))?;
        let mut existing = conn
            .query("SELECT 1 FROM devices WHERE pk_dev = ?", [pk_dev.to_vec()])
            .await
            .map_err(|e| PostError::Database(e.to_string()))?;
        if existing.next().await.map_err(|e| PostError::Database(e.to_string()))?.is_some() {
            return Ok(());
        }
        drop(existing);

        self.register_device(pk_dev).await.map_err(|e| {
            let msg = e.to_string();
            if msg.contains("no group key") {
                // Cannot register — no group key is a setup problem, not a caller error.
                // The device won't be able to post yet, but we don't return an
                // AuthorBanned/InvalidSignature error.  Fall through to Database.
            }
            PostError::Database(msg)
        })?;
        Ok(())
    }

    async fn submit_post_inner(
        &self,
        req: &freesky_shared::types::PostRequest,
    ) -> std::result::Result<PostResult, PostError> {
        if !freesky_shared::crypto::ecdsa_verify(
            &req.author_pk,
            &req.ciphertext_comm,
            &req.author_sig,
        ) {
            return Err(PostError::InvalidSignature);
        }

        if self.check_banned(&req.author_pk).await {
            return Err(PostError::AuthorBanned);
        }

        self.ensure_device_registered(&req.author_pk).await?;

        let conn = self
            .db
            .connect()
            .map_err(|e| PostError::Database(e.to_string()))?;
        let mut rows = conn
            .query(
                "INSERT INTO posts (ciphertext_comm, author_pk, author_sig, timestamp, mls_epoch, parent_id) \
                 VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
                (
                    req.ciphertext_comm.clone(),
                    req.author_pk.clone(),
                    req.author_sig.clone(),
                    req.timestamp,
                    req.mls_epoch as i64,
                    req.parent_id,
                ),
            )
            .await
            .map_err(|e| PostError::Database(e.to_string()))?;

        let id = rows
            .next()
            .await
            .map_err(|e| PostError::Database(e.to_string()))?
            .ok_or_else(|| PostError::Database("no rowid returned".to_string()))?
            .get::<i64>(0)
            .map_err(|e| PostError::Database(e.to_string()))?;

        Ok(PostResult { id })
    }

    async fn fetch_feed_inner(
        &self,
        cursor: Option<i64>,
        limit: Option<u32>,
    ) -> Result<FeedResult> {
        let clamped = limit.unwrap_or(DEFAULT_FEED_LIMIT).clamp(1, MAX_FEED_LIMIT);

        let conn = self.db.connect()?;
        let mut rows = if let Some(c) = cursor {
            conn.query(
                "SELECT id, ciphertext_comm, author_pk, author_sig, timestamp, mls_epoch, parent_id \
                 FROM posts WHERE timestamp < ? ORDER BY timestamp DESC, id DESC LIMIT ?",
                (c, clamped as i64),
            )
            .await?
        } else {
            conn.query(
                "SELECT id, ciphertext_comm, author_pk, author_sig, timestamp, mls_epoch, parent_id \
                 FROM posts ORDER BY timestamp DESC, id DESC LIMIT ?",
                [clamped as i64],
            )
            .await?
        };

        let mut posts: Vec<freesky_shared::types::PostEntry> =
            Vec::with_capacity(clamped as usize);
        let mut last_ts: Option<i64> = None;
        while let Some(row) = rows.next().await? {
            let entry = freesky_shared::types::PostEntry {
                id: row.get::<i64>(0)?,
                ciphertext_comm: row.get::<Vec<u8>>(1)?,
                author_pk: row.get::<Vec<u8>>(2)?,
                author_sig: row.get::<Vec<u8>>(3)?,
                timestamp: row.get::<i64>(4)?,
                mls_epoch: row.get::<i64>(5)? as u64,
                parent_id: row.get::<Option<i64>>(6)?,
            };
            last_ts = Some(entry.timestamp);
            posts.push(entry);
        }

        let next_cursor = last_ts.filter(|_| posts.len() as u32 >= clamped);
        Ok(FeedResult { posts, next_cursor })
    }

    // ─── Public API ───

    pub async fn register_device(&self, pk_dev: &[u8]) -> Result<RegisterResult> {
        let now = Utc::now().timestamp();

        if self.check_banned(pk_dev).await {
            return Ok(RegisterResult {
                name: String::new(),
                color: 0,
                encrypted_sk_comm: Vec::new(),
                is_banned: true,
            });
        }

        let name = freesky_shared::crypto::derive_name(pk_dev);
        let color = freesky_shared::crypto::derive_color(pk_dev);

        let group_key = self.get_group_key().await?;
        let encrypted_sk_comm = freesky_shared::crypto::ecies_encrypt(pk_dev, &group_key)
            .map_err(|e| anyhow::anyhow!("ECIES encrypt failed: {e}"))?;

        let is_new = self
            .upsert_device(pk_dev, &name, color, &encrypted_sk_comm, now)
            .await?;

        if is_new {
            self.increment_member_count().await?;
        }

        Ok(RegisterResult {
            name,
            color,
            encrypted_sk_comm,
            is_banned: false,
        })
    }

    pub async fn rotate_group_key(&self) -> Result<usize> {
        let now = Utc::now().timestamp();
        self.rotate_group_key_inner(now).await
    }

    pub async fn submit_post(
        &self,
        req: &freesky_shared::types::PostRequest,
    ) -> std::result::Result<PostResult, PostError> {
        self.submit_post_inner(req).await
    }

    pub async fn fetch_feed(
        &self,
        cursor: Option<i64>,
        limit: Option<u32>,
    ) -> Result<FeedResult> {
        self.fetch_feed_inner(cursor, limit).await
    }

    pub async fn fetch_thread(
        &self,
        post_id: i64,
    ) -> std::result::Result<ThreadResult, PostError> {
        let conn = self
            .db
            .connect()
            .map_err(|e| PostError::Database(e.to_string()))?;

        // Recursive CTE: fetches parent post + all descendants in one query.
        let mut rows = conn
            .query(
                "WITH RECURSIVE thread AS (
                    SELECT id, ciphertext_comm, author_pk, author_sig, timestamp, mls_epoch, parent_id, 0 AS depth
                    FROM posts WHERE id = ?
                    UNION ALL
                    SELECT p.id, p.ciphertext_comm, p.author_pk, p.author_sig, p.timestamp, p.mls_epoch, p.parent_id, t.depth + 1
                    FROM posts p JOIN thread t ON p.parent_id = t.id
                 )
                 SELECT id, ciphertext_comm, author_pk, author_sig, timestamp, mls_epoch, parent_id, depth
                 FROM thread ORDER BY depth, timestamp ASC",
                [post_id],
            )
            .await
            .map_err(|e| PostError::Database(e.to_string()))?;

        let mut entries: Vec<(i64, freesky_shared::types::PostEntry)> = Vec::new();
        while let Some(row) = rows.next().await.map_err(|e| PostError::Database(e.to_string()))? {
            let entry = freesky_shared::types::PostEntry {
                id: row.get::<i64>(0).map_err(|e| PostError::Database(e.to_string()))?,
                ciphertext_comm: row.get::<Vec<u8>>(1).map_err(|e| PostError::Database(e.to_string()))?,
                author_pk: row.get::<Vec<u8>>(2).map_err(|e| PostError::Database(e.to_string()))?,
                author_sig: row.get::<Vec<u8>>(3).map_err(|e| PostError::Database(e.to_string()))?,
                timestamp: row.get::<i64>(4).map_err(|e| PostError::Database(e.to_string()))?,
                mls_epoch: row.get::<i64>(5).map_err(|e| PostError::Database(e.to_string()))? as u64,
                parent_id: row.get::<Option<i64>>(6).map_err(|e| PostError::Database(e.to_string()))?,
            };
            let depth: i64 = row.get(7).map_err(|e| PostError::Database(e.to_string()))?;
            entries.push((depth, entry));
        }

        if entries.is_empty() {
            return Err(PostError::NotFound);
        }

        let (_, post) = entries.remove(0);
        let replies: Vec<freesky_shared::types::PostEntry> = entries.into_iter().map(|(_, e)| e).collect();

        Ok(ThreadResult { post, replies })
    }

    pub async fn submit_report(
        &self,
        req: &freesky_shared::types::ReportRequest,
    ) -> std::result::Result<(), PostError> {
        if !self.parent_post_exists(req.post_id).await {
            return Err(PostError::NotFound);
        }
        self.ensure_device_registered(&req.reporter_pk).await?;

        let conn = self
            .db
            .connect()
            .map_err(|e| PostError::Database(e.to_string()))?;
        let now = Utc::now().timestamp();
        conn.execute(
            "INSERT INTO reports (post_id, reporter_pk, reason, reported_at) VALUES (?, ?, ?, ?)",
            (req.post_id, req.reporter_pk.clone(), req.reason.clone(), now),
        )
        .await
        .map_err(|e| PostError::Database(e.to_string()))?;
        Ok(())
    }

    pub async fn parent_post_exists(&self, post_id: i64) -> bool {
        let conn = match self.db.connect() {
            Ok(c) => c,
            Err(_) => return false,
        };
        let mut rows = match conn
            .query("SELECT 1 FROM posts WHERE id = ?", [post_id])
            .await
        {
            Ok(r) => r,
            Err(_) => return false,
        };
        matches!(rows.next().await.ok().flatten(), Some(_))
    }

    pub async fn create_comment_trigger(&self) -> std::result::Result<CreateCommentTriggerResult, PostError> {
        let conn = self
            .db
            .connect()
            .map_err(|e| PostError::Database(e.to_string()))?;

        // Drop trigger if it already exists (idempotent setup).
        let _ = conn
            .execute("DROP TRIGGER IF EXISTS validate_comment_parent", ())
            .await;

        conn.execute(
            "CREATE TRIGGER validate_comment_parent
             BEFORE INSERT ON posts
             WHEN NEW.parent_id IS NOT NULL
             BEGIN
                 SELECT CASE
                     WHEN NOT EXISTS (SELECT 1 FROM posts WHERE id = NEW.parent_id)
                     THEN RAISE(ABORT, 'parent post not found')
                 END;
             END",
            (),
        )
        .await
        .map_err(|e| PostError::Database(e.to_string()))?;

        Ok(CreateCommentTriggerResult(true))
    }

    pub async fn run_schema(&self) -> anyhow::Result<()> {
        let conn = self.db.connect()?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS devices (
                pk_dev             BLOB PRIMARY KEY,
                user_name          TEXT NOT NULL,
                user_color         INTEGER NOT NULL,
                encrypted_sk_comm  BLOB,
                registered_at      INTEGER NOT NULL,
                banned_at          INTEGER,
                last_seen_at       INTEGER
            )",
            (),
        )
        .await?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS community (
                id              INTEGER PRIMARY KEY DEFAULT 1,
                mls_group_state BLOB,
                created_at      INTEGER NOT NULL,
                member_count    INTEGER DEFAULT 1
            )",
            (),
        )
        .await?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS posts (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                ciphertext_comm BLOB NOT NULL,
                author_pk       BLOB NOT NULL REFERENCES devices(pk_dev),
                author_sig      BLOB NOT NULL,
                timestamp       INTEGER NOT NULL,
                mls_epoch       INTEGER NOT NULL,
                parent_id       INTEGER REFERENCES posts(id)
            )",
            (),
        )
        .await?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS reports (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id         INTEGER NOT NULL REFERENCES posts(id),
                reporter_pk     BLOB NOT NULL REFERENCES devices(pk_dev),
                reason          TEXT,
                reported_at     INTEGER NOT NULL,
                resolved_at     INTEGER,
                resolution      TEXT
            )",
            (),
        )
        .await?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_posts_timestamp ON posts(timestamp DESC)",
            (),
        )
        .await?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_posts_author ON posts(author_pk)",
            (),
        )
        .await?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS server_config (
                key   TEXT PRIMARY KEY,
                value BLOB NOT NULL
            )",
            (),
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "queries_test.rs"]
mod tests;
