use rusqlite::Connection;
use std::sync::Mutex;

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn open(path: &str) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.run_migrations()?;
        Ok(db)
    }

    fn run_migrations(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS devices (
                pk_dev          BLOB PRIMARY KEY,
                user_name       TEXT NOT NULL,
                user_color      INTEGER NOT NULL,
                encrypted_sk_comm BLOB,
                registered_at   INTEGER NOT NULL,
                banned_at       INTEGER,
                last_seen_at    INTEGER
            );

            CREATE TABLE IF NOT EXISTS community (
                id              INTEGER PRIMARY KEY DEFAULT 1,
                mls_group_state BLOB,
                created_at      INTEGER NOT NULL,
                member_count    INTEGER DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS posts (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                ciphertext_comm BLOB NOT NULL,
                author_pk       BLOB NOT NULL REFERENCES devices(pk_dev),
                author_sig      BLOB NOT NULL,
                timestamp       INTEGER NOT NULL,
                mls_epoch       INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS reports (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id         INTEGER NOT NULL REFERENCES posts(id),
                reporter_pk     BLOB NOT NULL REFERENCES devices(pk_dev),
                reason          TEXT,
                reported_at     INTEGER NOT NULL,
                resolved_at     INTEGER,
                resolution      TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_posts_timestamp ON posts(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_posts_author ON posts(author_pk);

            CREATE TABLE IF NOT EXISTS server_config (
                key   TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );
            ",
        )?;
        Ok(())
    }

    pub fn load_noise_key(&self) -> Option<Vec<u8>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT value FROM server_config WHERE key = 'noise_sk'",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .ok()
    }

    pub fn store_noise_key(&self, sk_bytes: &[u8]) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO server_config (key, value) VALUES ('noise_sk', ?1)",
            [sk_bytes],
        )?;
        Ok(())
    }

    pub fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap()
    }
}
