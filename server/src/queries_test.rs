use super::*;

fn test_db() -> Database {
    let db = Database::open(":memory:").unwrap();
    // Seed a group key so registration works.
    let conn = db.conn();
    OsRng.fill_bytes(&mut [0u8; 32]); // sanity
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    conn.execute(
        "INSERT INTO community (id, mls_group_state, created_at, member_count)
         VALUES (1, ?, 0, 1)",
        params![key.as_slice()],
    )
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

fn insert_post_raw(db: &Database, author_pk: &[u8], ts: i64, body: &[u8]) {
    db.register_device(author_pk).unwrap();
    let conn = db.conn();
    conn.execute(
        "INSERT INTO posts (ciphertext_comm, author_pk, author_sig, timestamp, mls_epoch)
         VALUES (?, ?, ?, ?, ?)",
        params![body, author_pk, b"sig", ts, 1u64],
    )
    .unwrap();
}

#[test]
fn feed_empty_returns_empty_vec() {
    let db = test_db();
    let r = db.fetch_feed(None, None).unwrap();
    assert!(r.posts.is_empty());
    assert!(r.next_cursor.is_none());
}

#[test]
fn feed_returns_newest_first() {
    let db = test_db();
    let (pk, _) = gen_keypair();
    insert_post_raw(&db, &pk, 1000, b"old");
    insert_post_raw(&db, &pk, 2000, b"new");

    let r = db.fetch_feed(None, None).unwrap();
    assert_eq!(r.posts.len(), 2);
    assert_eq!(r.posts[0].timestamp, 2000);
    assert_eq!(r.posts[1].timestamp, 1000);
}

#[test]
fn feed_pagination_walks_all_posts() {
    let db = test_db();
    let (pk, _) = gen_keypair();
    for i in 0..5 {
        insert_post_raw(&db, &pk, 1000 + i, &[i as u8]);
    }

    let p1 = db.fetch_feed(None, Some(2)).unwrap();
    assert_eq!(p1.posts.len(), 2);
    assert_eq!(p1.posts[0].timestamp, 1004);
    assert_eq!(p1.posts[1].timestamp, 1003);
    let cursor1 = p1.next_cursor.expect("should have next cursor");
    assert_eq!(cursor1, 1003);

    let p2 = db.fetch_feed(Some(cursor1), Some(2)).unwrap();
    assert_eq!(p2.posts.len(), 2);
    assert_eq!(p2.posts[0].timestamp, 1002);
    assert_eq!(p2.posts[1].timestamp, 1001);
    let cursor2 = p2.next_cursor.expect("should have next cursor");

    let p3 = db.fetch_feed(Some(cursor2), Some(2)).unwrap();
    assert_eq!(p3.posts.len(), 1);
    assert_eq!(p3.posts[0].timestamp, 1000);
    assert!(p3.next_cursor.is_none());
}

#[test]
fn feed_limit_clamped_to_max() {
    let db = test_db();
    let (pk, _) = gen_keypair();
    for i in 0..150 {
        insert_post_raw(&db, &pk, 1000 + i, &[i as u8]);
    }
    let r = db.fetch_feed(None, Some(999)).unwrap();
    assert_eq!(r.posts.len(), MAX_FEED_LIMIT as usize);
}

#[test]
fn feed_limit_clamped_to_min_one() {
    let db = test_db();
    let (pk, _) = gen_keypair();
    for i in 0..5 {
        insert_post_raw(&db, &pk, 1000 + i, &[i as u8]);
    }
    let r = db.fetch_feed(None, Some(0)).unwrap();
    assert_eq!(r.posts.len(), 1);
}

#[test]
fn feed_cursor_excludes_boundary_post() {
    let db = test_db();
    let (pk, _) = gen_keypair();
    insert_post_raw(&db, &pk, 1000, b"a");
    insert_post_raw(&db, &pk, 1000, b"b");
    insert_post_raw(&db, &pk, 999, b"c");

    let p1 = db.fetch_feed(None, Some(2)).unwrap();
    assert_eq!(p1.posts.len(), 2);
    assert_eq!(p1.posts[0].timestamp, 1000);
    assert_eq!(p1.posts[1].timestamp, 1000);
    let cursor = p1.next_cursor.unwrap();
    assert_eq!(cursor, 1000);

    let p2 = db.fetch_feed(Some(cursor), Some(2)).unwrap();
    assert_eq!(p2.posts.len(), 1);
    assert_eq!(p2.posts[0].timestamp, 999);
}

#[test]
fn submit_post_rejects_bad_signature() {
    let db = test_db();
    let (pk, sk) = gen_keypair();
    db.register_device(&pk).unwrap();

    let good_sig = sign(&sk, b"hello");
    let req = freesky_shared::types::PostRequest {
        ciphertext_comm: b"hello".to_vec(),
        author_pk: pk.clone(),
        author_sig: good_sig,
        timestamp: 1234,
        mls_epoch: 1,
    };
    assert!(db.submit_post(&req).is_ok());

    let mut bad_sig = sign(&sk, b"hello");
    bad_sig[0] ^= 0xff;
    let req_bad = freesky_shared::types::PostRequest {
        ciphertext_comm: b"hello".to_vec(),
        author_pk: pk,
        author_sig: bad_sig,
        timestamp: 1235,
        mls_epoch: 1,
    };
    match db.submit_post(&req_bad) {
        Err(PostError::InvalidSignature) => {}
        other => panic!("expected InvalidSignature, got {other:?}"),
    }
}
