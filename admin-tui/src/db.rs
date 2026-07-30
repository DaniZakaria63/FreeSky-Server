use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::Connection;

#[derive(Clone, Debug)]
pub(crate) struct Stats {
    pub total_users: i64,
    pub active_users: i64,
    pub banned_users: i64,
    pub total_posts: i64,
    pub today_posts: i64,
    pub total_reports: i64,
    pub unresolved_reports: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct ReportRow {
    pub id: i64,
    pub reason: Option<String>,
    pub reported_at: i64,
    pub user_name: String,
}

#[derive(Clone, Debug)]
pub(crate) struct CommunityInfo {
    pub member_count: i64,
    pub created_at: i64,
    pub has_group_key: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct DeviceInfo {
    pub pk_dev: Vec<u8>,
    pub user_name: String,
    pub user_color: u8,
    pub registered_at: i64,
    pub banned_at: Option<i64>,
    pub last_seen_at: Option<i64>,
    pub post_count: i64,
}

pub(crate) struct AdminDb {
    conn: Connection,
}

impl AdminDb {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path).context("failed to open database")?;
        conn.execute_batch("PRAGMA journal_mode=WAL").ok();
        Ok(Self { conn })
    }

    pub fn stats(&self) -> Result<Stats> {
        let total_users: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM devices", [], |r| r.get(0))?;
        let active_users: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM devices WHERE banned_at IS NULL",
            [],
            |r| r.get(0),
        )?;
        let banned_users: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM devices WHERE banned_at IS NOT NULL",
            [],
            |r| r.get(0),
        )?;
        let total_posts: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM posts", [], |r| r.get(0))?;
        let today_start = Utc::now().date_naive().and_hms_opt(0, 0, 0).unwrap();
        let today_ts = today_start.and_utc().timestamp();
        let today_posts: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM posts WHERE timestamp >= ?",
            [today_ts],
            |r| r.get(0),
        )?;
        let total_reports: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM reports", [], |r| r.get(0))?;
        let unresolved_reports: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM reports WHERE resolved_at IS NULL",
            [],
            |r| r.get(0),
        )?;
        Ok(Stats {
            total_users,
            active_users,
            banned_users,
            total_posts,
            today_posts,
            total_reports,
            unresolved_reports,
        })
    }

    pub fn reports(&self) -> Result<Vec<ReportRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT r.id, r.reason, r.reported_at,
                    d.user_name
             FROM reports r
             JOIN posts p ON p.id = r.post_id
             JOIN devices d ON d.pk_dev = p.author_pk
             WHERE r.resolved_at IS NULL
             ORDER BY r.reported_at DESC
             LIMIT 50",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ReportRow {
                id: row.get(0)?,
                reason: row.get(1)?,
                reported_at: row.get(2)?,
                user_name: row.get(3)?,
            })
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    pub fn community_info(&self) -> Result<CommunityInfo> {
        let info = self.conn.query_row(
            "SELECT member_count, created_at, mls_group_state IS NOT NULL
             FROM community WHERE id = 1",
            [],
            |r| {
                Ok(CommunityInfo {
                    member_count: r.get(0)?,
                    created_at: r.get(1)?,
                    has_group_key: r.get(2)?,
                })
            },
        );
        Ok(info.unwrap_or(CommunityInfo {
            member_count: 0,
            created_at: 0,
            has_group_key: false,
        }))
    }

    pub fn search_devices(&self, query: &str) -> Result<Vec<DeviceInfo>> {
        let pattern = format!("%{}%", query);
        let mut stmt = self.conn.prepare(
            "SELECT d.pk_dev, d.user_name, d.user_color, d.registered_at,
                    d.banned_at, d.last_seen_at,
                    (SELECT COUNT(*) FROM posts WHERE author_pk = d.pk_dev) AS post_count
             FROM devices d
             WHERE hex(d.pk_dev) LIKE ?1
                OR d.user_name LIKE ?1
             ORDER BY d.registered_at DESC
             LIMIT 20",
        )?;
        let rows = stmt.query_map([&pattern], |row| {
            Ok(DeviceInfo {
                pk_dev: row.get(0)?,
                user_name: row.get(1)?,
                user_color: row.get(2)?,
                registered_at: row.get(3)?,
                banned_at: row.get(4)?,
                last_seen_at: row.get(5)?,
                post_count: row.get(6)?,
            })
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    pub fn ban_user(&self, pk_dev: &[u8]) -> Result<()> {
        let now = Utc::now().timestamp();
        self.conn.execute(
            "UPDATE devices SET banned_at = ? WHERE pk_dev = ?",
            rusqlite::params![now, pk_dev],
        )?;
        Ok(())
    }

    pub fn unban_user(&self, pk_dev: &[u8]) -> Result<()> {
        self.conn.execute(
            "UPDATE devices SET banned_at = NULL WHERE pk_dev = ?",
            rusqlite::params![pk_dev],
        )?;
        Ok(())
    }

    pub fn resolve_report(&self, report_id: i64, resolution: &str) -> Result<()> {
        let now = Utc::now().timestamp();
        self.conn.execute(
            "UPDATE reports SET resolved_at = ?, resolution = ? WHERE id = ?",
            rusqlite::params![now, resolution, report_id],
        )?;
        Ok(())
    }
}
