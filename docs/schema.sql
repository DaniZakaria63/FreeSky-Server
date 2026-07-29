PRAGMA journal_mode=WAL;

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
    mls_epoch       INTEGER NOT NULL,
    parent_id       INTEGER REFERENCES posts(id)
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

CREATE TRIGGER IF NOT EXISTS validate_comment_parent
BEFORE INSERT ON posts
WHEN NEW.parent_id IS NOT NULL
BEGIN
    SELECT CASE
        WHEN NOT EXISTS (SELECT 1 FROM posts WHERE id = NEW.parent_id)
        THEN RAISE(ABORT, 'parent post not found')
    END;
END;
