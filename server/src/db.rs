use std::sync::atomic::{AtomicU64, Ordering};

static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(crate) fn next_db_id() -> String {
    let n = DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("freesky-{n:x}")
}

pub struct Database {
    pub(crate) db: libsql::Database,
}

impl Database {
    pub async fn connect(url: &str, token: &str) -> anyhow::Result<Self> {
        let db = if url.starts_with("file://") || url.starts_with("file:") || !url.contains("://") {
            let path = url
                .strip_prefix("file://")
                .or_else(|| url.strip_prefix("file:"))
                .unwrap_or(url);
            libsql::Builder::new_local(path).build().await?
        } else {
            libsql::Builder::new_remote(url.to_string(), token.to_string())
                .build()
                .await?
        };
        Ok(Self { db })
    }

    pub async fn in_memory() -> anyhow::Result<Self> {
        let path = std::env::temp_dir().join(next_db_id());
        let _ = std::fs::remove_file(&path);
        let db = libsql::Builder::new_local(&path).build().await?;
        Ok(Self { db })
    }

    pub async fn load_noise_key(&self) -> Option<Vec<u8>> {
        let conn = self.db.connect().ok()?;
        let mut rows = conn
            .query("SELECT value FROM server_config WHERE key = 'noise_sk'", ())
            .await
            .ok()?;
        match rows.next().await.ok()? {
            Some(row) => row.get::<Vec<u8>>(0).ok(),
            None => None,
        }
    }

    pub async fn store_noise_key(&self, sk_bytes: &[u8]) -> anyhow::Result<()> {
        let conn = self.db.connect()?;
        conn.execute(
            "INSERT OR REPLACE INTO server_config (key, value) VALUES ('noise_sk', ?)",
            [sk_bytes.to_vec()],
        )
        .await?;
        Ok(())
    }
}
