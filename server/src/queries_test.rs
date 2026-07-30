use super::*;

async fn test_db() -> Database {
    let db = Database::in_memory().await.unwrap();
    let conn = db.db.connect().unwrap();
    let schema = [
        "CREATE TABLE IF NOT EXISTS devices (
            pk_dev          BLOB PRIMARY KEY,
            user_name       TEXT NOT NULL,
            user_color      INTEGER NOT NULL,
            encrypted_sk_comm BLOB,
            registered_at   INTEGER NOT NULL,
            banned_at       INTEGER,
            last_seen_at    INTEGER
        )",
        "CREATE TABLE IF NOT EXISTS community (
            id              INTEGER PRIMARY KEY DEFAULT 1,
            mls_group_state BLOB,
            created_at      INTEGER NOT NULL,
            member_count    INTEGER DEFAULT 1
        )",
        "CREATE TABLE IF NOT EXISTS posts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ciphertext_comm BLOB NOT NULL,
            author_pk       BLOB NOT NULL REFERENCES devices(pk_dev),
            author_sig      BLOB NOT NULL,
            timestamp       INTEGER NOT NULL,
            mls_epoch       INTEGER NOT NULL,
            parent_id       INTEGER REFERENCES posts(id)
        )",
        "CREATE INDEX IF NOT EXISTS idx_posts_timestamp ON posts(timestamp DESC)",
        "CREATE TABLE IF NOT EXISTS server_config (
            key   TEXT PRIMARY KEY,
            value BLOB NOT NULL
        )",
    ];
    for sql in &schema {
        conn.execute(sql, ()).await.unwrap();
    }
    conn.execute(
        "INSERT INTO community (id, mls_group_state, created_at, member_count) VALUES (1, ?, 0, 1)",
        [vec![0u8; 32]],
    )
    .await
    .unwrap();
    drop(conn);
    db
}

fn gen_keypair() -> (Vec<u8>, p256::SecretKey) {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let sk = p256::SecretKey::random(&mut OsRng);
    let pk = sk.public_key();
    let pk_bytes = pk.to_encoded_point(false).to_bytes();
    (pk_bytes.to_vec(), sk)
}

fn sign(sk: &p256::SecretKey, msg: &[u8]) -> Vec<u8> {
    use p256::ecdsa::signature::Signer;
    let signing_key = p256::ecdsa::SigningKey::from(sk);
    let sig: p256::ecdsa::Signature = signing_key.sign(msg);
    sig.to_der().as_bytes().to_vec()
}

async fn insert_post_raw(db: &Database, author_pk: &[u8], ts: i64, body: &[u8]) -> i64 {
    db.register_device(author_pk).await.unwrap();
    let conn = db.db.connect().unwrap();
    let mut rows = conn
        .query(
            "INSERT INTO posts (ciphertext_comm, author_pk, author_sig, timestamp, mls_epoch) \
             VALUES (?, ?, ?, ?, 1) RETURNING id",
            (body.to_vec(), author_pk.to_vec(), b"sig".to_vec(), ts),
        )
        .await
        .unwrap();
    let id: i64 = rows.next().await.unwrap().unwrap().get(0).unwrap();
    id
}

#[tokio::test]
async fn feed_empty_returns_empty_vec() {
    let db = test_db().await;
    let r = db.fetch_feed(None, None).await.unwrap();
    assert!(r.posts.is_empty());
    assert!(r.next_cursor.is_none());
}

#[tokio::test]
async fn feed_returns_newest_first() {
    let db = test_db().await;
    let (pk, _) = gen_keypair();
    insert_post_raw(&db, &pk, 1000, b"old").await;
    insert_post_raw(&db, &pk, 2000, b"new").await;

    let r = db.fetch_feed(None, None).await.unwrap();
    assert_eq!(r.posts.len(), 2);
    assert_eq!(r.posts[0].timestamp, 2000);
    assert_eq!(r.posts[1].timestamp, 1000);
}

#[tokio::test]
async fn feed_pagination_walks_all_posts() {
    let db = test_db().await;
    let (pk, _) = gen_keypair();
    for i in 0..5 {
        insert_post_raw(&db, &pk, 1000 + i, &[i as u8]).await;
    }

    let p1 = db.fetch_feed(None, Some(2)).await.unwrap();
    assert_eq!(p1.posts.len(), 2);
    assert_eq!(p1.posts[0].timestamp, 1004);
    assert_eq!(p1.posts[1].timestamp, 1003);
    let cursor1 = p1.next_cursor.expect("should have next cursor");
    assert_eq!(cursor1, 1003);

    let p2 = db.fetch_feed(Some(cursor1), Some(2)).await.unwrap();
    assert_eq!(p2.posts.len(), 2);
    assert_eq!(p2.posts[0].timestamp, 1002);
    assert_eq!(p2.posts[1].timestamp, 1001);
    let cursor2 = p2.next_cursor.expect("should have next cursor");

    let p3 = db.fetch_feed(Some(cursor2), Some(2)).await.unwrap();
    assert_eq!(p3.posts.len(), 1);
    assert_eq!(p3.posts[0].timestamp, 1000);
    assert!(p3.next_cursor.is_none());
}

#[tokio::test]
async fn feed_limit_clamped_to_max() {
    let db = test_db().await;
    let (pk, _) = gen_keypair();
    for i in 0..150 {
        insert_post_raw(&db, &pk, 1000 + i, &[i as u8]).await;
    }
    let r = db.fetch_feed(None, Some(999)).await.unwrap();
    assert_eq!(r.posts.len(), MAX_FEED_LIMIT as usize);
}

#[tokio::test]
async fn feed_limit_clamped_to_min_one() {
    let db = test_db().await;
    let (pk, _) = gen_keypair();
    for i in 0..5 {
        insert_post_raw(&db, &pk, 1000 + i, &[i as u8]).await;
    }
    let r = db.fetch_feed(None, Some(0)).await.unwrap();
    assert_eq!(r.posts.len(), 1);
}

#[tokio::test]
async fn feed_cursor_excludes_boundary_post() {
    let db = test_db().await;
    let (pk, _) = gen_keypair();
    insert_post_raw(&db, &pk, 1000, b"a").await;
    insert_post_raw(&db, &pk, 1000, b"b").await;
    insert_post_raw(&db, &pk, 999, b"c").await;

    let p1 = db.fetch_feed(None, Some(2)).await.unwrap();
    assert_eq!(p1.posts.len(), 2);
    assert_eq!(p1.posts[0].timestamp, 1000);
    assert_eq!(p1.posts[1].timestamp, 1000);
    let cursor = p1.next_cursor.unwrap();
    assert_eq!(cursor, 1000);

    let p2 = db.fetch_feed(Some(cursor), Some(2)).await.unwrap();
    assert_eq!(p2.posts.len(), 1);
    assert_eq!(p2.posts[0].timestamp, 999);
}

#[tokio::test]
async fn submit_post_rejects_bad_signature() {
    let db = test_db().await;
    let (pk, sk) = gen_keypair();
    db.register_device(&pk).await.unwrap();

    let good_sig = sign(&sk, b"hello");
    let req = freesky_shared::types::PostRequest {
        ciphertext_comm: b"hello".to_vec(),
        author_pk: pk.clone(),
        author_sig: good_sig,
        timestamp: 1234,
        mls_epoch: 1,
        parent_id: None,
    };
    assert!(db.submit_post(&req).await.is_ok());

    let mut bad_sig = sign(&sk, b"hello");
    bad_sig[0] ^= 0xff;
    let req_bad = freesky_shared::types::PostRequest {
        ciphertext_comm: b"hello".to_vec(),
        author_pk: pk,
        author_sig: bad_sig,
        timestamp: 1235,
        mls_epoch: 1,
        parent_id: None,
    };
    match db.submit_post(&req_bad).await {
        Err(PostError::InvalidSignature) => {}
        other => panic!("expected InvalidSignature, got {other:?}"),
    }
}

#[tokio::test]
async fn submit_post_with_parent_id() {
    let db = test_db().await;
    let (pk, sk) = gen_keypair();
    db.register_device(&pk).await.unwrap();

    // Create parent post
    let parent_req = freesky_shared::types::PostRequest {
        ciphertext_comm: b"parent".to_vec(),
        author_pk: pk.clone(),
        author_sig: sign(&sk, b"parent"),
        timestamp: 1000,
        mls_epoch: 1,
        parent_id: None,
    };
    let parent_result = db.submit_post(&parent_req).await.unwrap();

    // Create reply with parent_id
    let reply_sig = sign(&sk, b"reply to parent");
    let reply_req = freesky_shared::types::PostRequest {
        ciphertext_comm: b"reply to parent".to_vec(),
        author_pk: pk.clone(),
        author_sig: reply_sig,
        timestamp: 2000,
        mls_epoch: 1,
        parent_id: Some(parent_result.id),
    };
    assert!(db.submit_post(&reply_req).await.is_ok());
}

#[tokio::test]
async fn fetch_thread_returns_parent_and_replies() {
    let db = test_db().await;
    let (pk, sk) = gen_keypair();
    db.register_device(&pk).await.unwrap();

    // Create parent
    let parent_req = freesky_shared::types::PostRequest {
        ciphertext_comm: b"parent".to_vec(),
        author_pk: pk.clone(),
        author_sig: sign(&sk, b"parent"),
        timestamp: 1000,
        mls_epoch: 1,
        parent_id: None,
    };
    let parent_id = db.submit_post(&parent_req).await.unwrap().id;

    // Create 2 replies
    for (body, ts) in [(b"\x01" as &[u8], 2000), (b"\x02" as &[u8], 3000)] {
        let reply_req = freesky_shared::types::PostRequest {
            ciphertext_comm: body.to_vec(),
            author_pk: pk.clone(),
            author_sig: sign(&sk, body),
            timestamp: ts,
            mls_epoch: 1,
            parent_id: Some(parent_id),
        };
        db.submit_post(&reply_req).await.unwrap();
    }

    let thread = db.fetch_thread(parent_id).await.unwrap();
    assert_eq!(thread.post.id, parent_id);
    assert_eq!(thread.replies.len(), 2);
    assert_eq!(thread.replies[0].timestamp, 2000);
    assert_eq!(thread.replies[1].timestamp, 3000);
}

#[tokio::test]
async fn fetch_thread_not_found_returns_error() {
    let db = test_db().await;
    match db.fetch_thread(99999).await {
        Err(PostError::NotFound) => {}
        other => panic!("expected NotFound, got {other:?}"),
    }
}
