# Community App — MLS-Based Private Group Communication

> **Concept**: A Twitter-like community app where users post into a shared space. The server stores encrypted content and cannot read it. Only community members (device holders) can read and write. No real identity — every user is a random name + color derived from their device key. Content is public/dumb — moderation just needs identity reveal.

---

## 1. System Overview

```
User A (device keypair sk_A, pk_A)
  │
  ├── Registers with server
  │     → Server assigns random name + color
  │     → Server delivers encrypted community group key (ECIES with pk_A)
  │
  ├── Posts "hello"
  │     → Encrypts with MLS group key
  │     → Signs with sk_A
  │     → Server stores encrypted blob
  │
User B (sk_B, pk_B)
  │
  ├── Fetches post
  │     → Cannot decrypt (server can't either)
  │     → User B has MLS group key (received on registration)
  │     → Decrypts with group key
  │     → Verifies signature with pk_A
  │
Server
  ├── Stores encrypted blobs
  ├── Cannot decrypt (no group key)
  ├── On report: reporter submits plaintext → server looks up author identity
  └── Manages membership (MLS key rotation on join/leave)
```

---

## 2. Identity Model

### 2.1 No Real Identity

| Element | Derivation |
|---|---|
| **Device keypair** | X25519, generated on first launch, stored in AndroidKeyStore |
| **User name** | `HMAC-SHA256(device_pk, "community-name")` truncated to 12 chars, mapped to a color palette |
| **User color** | `HMAC-SHA256(device_pk, "community-color") mod num_colors` |
| **Avatar** | Generated deterministically from device_pk (geometric pattern) |

Since every user gets a fixed name+color from their key, they keep the same identity across reinstalls on the same device. Different devices get different names. No email, no phone, no password.

### 2.2 Registration Flow

```
1. App: generate device keypair (sk_dev, pk_dev)
2. App → Server: POST /register { pk_dev }

3. Server:
   a. Derive name + color from pk_dev
   b. If community group key (sk_comm) exists:
      → ECIES-encrypt sk_comm with pk_dev → encrypted_sk_comm
   c. If first user ever:
      → Generate MLS group key material
      → encrypted_sk_comm = ECIES(pk_dev, sk_comm)
   d. Store { name, color, pk_dev, encrypted_sk_comm, registered_at }
   e. Return { name, color, encrypted_sk_comm, pk_comm }

4. App:
   a. Decrypt encrypted_sk_comm with sk_dev → sk_comm
   b. Initialize MLS group with sk_comm
   c. Store MLS group + name + color locally
   d. User sees: "You are GreenFox42"
```

---

## 3. MLS-Based Group Key Management

### 3.1 Why MLS

MLS (Messaging Layer Security, RFC 9420) provides:

| Property | What it means |
|---|---|
| **Server-blind key agreement** | All members agree on a shared secret without server knowing it |
| **Forward secrecy** | Past keys useless if current key leaks — old posts safe |
| **Post-compromise security** | After a join/leave, new keys heal the group |
| **Efficient membership changes** | O(log n) operations per join/kick |

### 3.2 Architecture

```
                   ┌──────────────────────┐
                   │   Community Group     │
                   │  (MLS group state)    │
                   │                      │
                   │  sk_comm (ratcheting) │
                   └──────┬───────────────┘
                          │
          ┌───────────────┼───────────────┐
          │               │               │
     User A           User B          User C
     (member)        (member)        (member)
          │               │               │
          └─────── MLS messages ──────────┘
                  (via server relay)
```

### 3.3 MLS Protocol Flow

```
Group creation (first user):
  User A creates MLS group with self as member
  Server stores group state (encrypted)

User B joins:
  User A → Server: MLS Commit(Add(B))
  Server → User B: encrypted Welcome message
  User B: now has sk_comm → can read all posts

User A posts:
  User A: MLS.encrypt(sk_comm, "hello")
  Server stores ciphertext (cannot decrypt)

User C joins:
  User A or B: MLS Commit(Add(C))
  Server relays → all members ratchet to new epoch key
  Server still cannot read (new key never passes through server in plaintext)

User B leaves/kicked:
  User A: MLS Commit(Remove(B))
  All remaining members ratchet to new epoch
  User B cannot decrypt new posts (doesn't have new epoch key)
```

### 3.4 MLS Library: kotlin-mls

| Property | Value |
|---|---|
| **Android library** | `space.zeroxv6:kotlin-mls:1.1.0` (Maven Central) |
| **License** | MIT |
| **Approach** | Rust OpenMLS + UniFFI Kotlin bindings → native `.so` in AAR |
| **Android API** | 26+ |
| **Server** | OpenMLS (Rust binary called from Node.js) or mls-rs WASM |

```kotlin
// Android: create MLS group
val group = MlsGroup::new(
    version = MlsProtocolVersion::Mls10,
    cipherSuite = CipherSuite::MLS_128_X25519_AES128GCM_SHA256_Ed25519,
    identity = keyPackage(credential_bundle),
)

// Add member
group.addMembers(listOf(recipientKeyPackage))

// Encrypt a post
val ciphertext = group.encrypt("hello world".encodeToByteArray())

// Decrypt a post
val plaintext = group.decrypt(ciphertext)
```

---

## 4. Post Encryption (Single Layer)

Every post is encrypted once — with the MLS group key. No moderation keypair needed (content is public anyway).

```
Post plaintext: "hello world"

Encrypted post stored on server:
{
  ciphertext_comm,     ← MLS-encrypted, decryptable by members
  author_pk,           ← Ed25519 public key of poster
  author_sig,          ← Ed25519 signature over ciphertext
  timestamp,
  mls_epoch            ← which MLS epoch this post belongs to
}
```

### 4.1 Writing

```kotlin
fun createPost(content: ByteArray, mlsGroup: MlsGroup, skDev: PrivateKey): Post {
    val ciphertext = mlsGroup.encrypt(content)
    val signature = sign(skDev, sha256(ciphertext))
    return Post(
        ciphertextComm = ciphertext,
        authorPk = pkDev,
        signature = signature,
        timestamp = now(),
        epoch = mlsGroup.epoch()
    )
}
```

### 4.2 Reading

```kotlin
fun readPost(post: Post, mlsGroup: MlsGroup): String? {
    if (!verify(post.authorPk, post.signature, sha256(post.ciphertextComm))) {
        return null  // tampered or forged
    }
    return mlsGroup.decrypt(post.ciphertextComm).decodeToString()
}
```

---

## 5. Report & Moderation Flow

Content is dumb/public, so there's no "secret decryption" needed. When someone reports a post:

```
1. User B reports User A's post:

   Option A (user submits plaintext):
     User B: POST /report { post_id, plaintext: "hello world" }
     Server: verify sha256(plaintext) matches? No — server can't decrypt ciphertext
     Server: just trusts the reporter (content is public anyway)

   Option B (server reveals identity only):
     User B: POST /report { post_id }
     Server: marks post as reported
     Server: looks up author_pk → finds name_A, color_A, pk_dev_A
     Server admin sees:
       "GreenFox42 (pk_dev: abc...) posted this at 2026-07-23"
       "Reported by PurpleLion99"

2. Admin action:
   - Warn: marks user record
   - Ban: sets devices.banned_at = now()
   - Banned user can't post. Their device key rejected on handshake.
```

**Server never needs to read the content.** The report is about the user's behavior, not the content text. The content is already public to all members anyway — the point of encryption is to keep the server blind, not to keep content secret from other users.

### 5.1 Report Schema

```sql
CREATE TABLE reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id         INTEGER NOT NULL REFERENCES posts(id),
    reporter_pk     BLOB NOT NULL REFERENCES devices(pk_dev),
    reported_at     INTEGER NOT NULL,
    resolved_at     INTEGER,
    resolution      TEXT  -- "warning", "ban", "dismissed"
);
```

---

## 6. Free Tech Stack

### 6.1 Android Client

| Component | Library | License | Cost |
|---|---|---|---|
| **Transport auth** | `nl.sanderdijkhuis:noise-kotlin` | MIT | Free |
| **Group encryption** | `space.zeroxv6:kotlin-mls:1.1.0` | MIT | Free |
| **Crypto primitives** | Android `javax.crypto` + `java.security` | Android built-in | Free |
| **Key storage** | Android `KeyStore` | Android built-in | Free |

### 6.2 Server + Admin — Rust Workspace (single `cargo build`)

| Component | Crate | License | Cost |
|---|---|---|---|
| **HTTP framework** | `axum` | MIT | Free |
| **Database** | `rusqlite` with bundled SQLite | MIT | Free |
| **MLS** | `openmls` | MIT | Free |
| **Crypto (X25519, Ed25519)** | `x25519-dalek` + `ed25519-dalek` | Apache-2.0 / BSD-3 | Free |
| **JSON** | `serde` + `serde_json` | Apache-2.0 | Free |
| **Async runtime** | `tokio` | MIT | Free |
| **Admin API** | `axum` router bound to `127.0.0.1` | MIT | Free |
| **Hosting** | Oracle Cloud free tier (4 ARM, 24GB RAM) | — | Free |
| **Or: Hosting** | Railway $5/mo (Docker) | — | $5 |
| **Or: Hosting** | Render free tier (750 instance-hours/mo) | — | Free |

### 6.3 Admin TUI (same Rust workspace, separate binary)

| Component | Crate | License | Cost |
|---|---|---|---|
| **TUI framework** | `ratatui` | MIT | Free |
| **SQLite** | `rusqlite` (shared with server) | MIT | Free |
| **HTTP client** | `reqwest` | MIT | Free |
| **MLS operations** | `openmls` | MIT | Free |
| **X25519 ECIES** | `x25519-dalek` + `chacha20poly1305` | Apache-2.0/MIT | Free |
| **Ed25519 verify** | `ed25519-dalek` | BSD-3 | Free |
| **Terminal input** | `crossterm` | MIT | Free |

### 6.5 Total Cost: $0–$5/month

### 6.6 Server Skeleton (Rust, axum + rusqlite + openmls)

```rust
// Cargo.toml (workspace root)
// workspace = { members = ["server", "admin-tui"] }
//
// server/Cargo.toml
// [dependencies]
// axum = "0.8"
// tokio = { version = "1", features = ["full"] }
// rusqlite = { version = "0.32", features = ["bundled"] }
// serde = { version = "1", features = ["derive"] }
// serde_json = "1"
// openmls = "0.7"
// x25519-dalek = "2"
// ed25519-dalek = "2"
// sha2 = "0.10"
// hex = "0.4"

use axum::{Router, routing::post, extract::Json};
use rusqlite::Connection;
use openmls::prelude::*;
use std::sync::Arc;

// ── App state ──
struct AppState {
    db: Mutex<Connection>,
    mls_group: Mutex<Option<MlsGroup>>,  // in-memory MLS group
}

// ── POST /register ──
#[derive(Deserialize)]
struct RegisterReq { pk_dev: String }
#[derive(Serialize)]
struct RegisterRes { name: String, color: u8, encrypted_sk_comm: String }

async fn register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterReq>,
) -> Json<RegisterRes> {
    let pk_bytes = hex::decode(&req.pk_dev).unwrap();
    let name = derive_name(&pk_bytes);
    let color = derive_color(&pk_bytes);

    let mut db = state.db.lock().unwrap();
    let encrypted_sk_comm = if let Some(ref group) = *state.mls_group.lock().unwrap() {
        let sk_comm = group.export_secret();
        encrypt_ecies(&pk_bytes, &sk_comm)
    } else {
        // First user — create MLS group
        let mut group = MlsGroup::new(...);
        let sk_comm = group.export_secret();
        *state.mls_group.lock().unwrap() = Some(group);
        encrypt_ecies(&pk_bytes, &sk_comm)
    };

    db.execute(
        "INSERT INTO devices (pk_dev, user_name, user_color, encrypted_sk_comm, registered_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![pk_bytes, name, color, &encrypted_sk_comm, now()],
    ).unwrap();

    Json(RegisterRes { name, color, encrypted_sk_comm: hex::encode(encrypted_sk_comm) })
}

// ── POST /post ──
#[derive(Deserialize)]
struct PostReq { ciphertext_comm: String, author_pk: String, author_sig: String }

async fn submit_post(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PostReq>,
) -> StatusCode {
    let ct = hex::decode(&req.ciphertext_comm).unwrap();
    let pk = hex::decode(&req.author_pk).unwrap();
    let sig = hex::decode(&req.author_sig).unwrap();

    // Verify Ed25519 signature
    let hash = sha2::Sha256::digest(&ct);
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk).unwrap();
    verifying_key.verify_strict(&hash, &sig).unwrap();

    state.db.lock().unwrap().execute(
        "INSERT INTO posts (ciphertext_comm, author_pk, author_sig, timestamp, mls_epoch)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![ct, pk, sig, now(), current_epoch],
    ).unwrap();
    StatusCode::OK
}

// ── Router ──
#[tokio::main]
async fn main() {
    let db = Connection::open("community.db").unwrap();
    db.execute_batch(SCHEMA).unwrap();

    // Main API — public
    let app = Router::new()
        .route("/register", post(register))
        .route("/post", post(submit_post))
        .with_state(app_state);

    // Admin API — localhost only
    let admin_app = Router::new()
        .route("/admin/health", get(health))
        .route("/admin/kick/:b64_pk", post(kick_member));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

---

## 7. Complete Protocol Flow

### 7.1 First User Ever

```
User A:
  sk_dev_A, pk_dev_A = X25519.generate()

Server:
  sk_comm, pk_comm = X25519.generate()     ← MLS group key material
  encrypted_sk_comm = ECIES.encrypt(pk_dev_A, sk_comm)
  name_A = deriveName(pk_dev_A)
  color_A = deriveColor(pk_dev_A)
  store(pk_dev_A, name_A, color_A, encrypted_sk_comm)
  return { name_A, color_A, encrypted_sk_comm, pk_comm }

User A:
  sk_comm = ECIES.decrypt(sk_dev_A, encrypted_sk_comm)
  mlsGroup = MlsGroup.create(sk_comm)
  store(name_A, color_A, mlsGroup)
```

### 7.2 Second User Joins

```
User B:
  sk_dev_B, pk_dev_B = X25519.generate()

Server:
  encrypted_sk_comm = ECIES.encrypt(pk_dev_B, sk_comm)
  name_B = deriveName(pk_dev_B)
  color_B = deriveColor(pk_dev_B)
  store(pk_dev_B, name_B, color_B, encrypted_sk_comm)
  return { name_B, color_B, encrypted_sk_comm, pk_comm }

User B:
  sk_comm = ECIES.decrypt(sk_dev_B, encrypted_sk_comm)

User A (MLS Add):
  keyPackage_B = createKeyPackage(sk_comm, pk_dev_B)
  mlsGroup.addMembers([keyPackage_B])
  → MLS Commit(Add) → server relays to User B

User B:
  processes Welcome message → joins MLS group
  Now has same MLS epoch key as User A
  Can decrypt all existing and future posts
```

### 7.3 User A Posts

```
User A:
  content = "hello world"
  ciphertext_comm = mlsGroup.encrypt(content)
  sig = Ed25519.sign(sk_dev_A, sha256(ciphertext_comm))
  → POST /post { ciphertext_comm, author_pk: pk_dev_A, sig }

Server:
  verify(Ed25519, pk_dev_A, sig, sha256(ciphertext_comm)) → OK
  store(post)

User B:
  GET /feed → receives encrypted posts
  for each post:
    verify(pk_dev_A, post.sig, sha256(post.ciphertext_comm)) → OK, User A wrote this
    content = mlsGroup.decrypt(post.ciphertext_comm)
    → "hello world"

Server:
  stores ciphertext_comm, sees author_pk, cannot decrypt content
```

### 7.4 User Gets Kicked

```
Server: initiates MLS Remove(A)
  → MLS Commit(Remove(A_keyPackage))
  → relays to all remaining members

Remaining members:
  mlsGroup.remove(A_keyPackage)
  → ratchet to new epoch key
  → future posts encrypted with NEW key

User A:
  No longer in MLS group
  Cannot decrypt new posts (doesn't have new epoch key)
  Old posts encrypted with old epoch key (User A still has this — can't revoke history)
```

### 7.5 Report Flow

```
User B sees a post by GreenFox42 that violates rules.

User B: POST /report { post_id, reason: "spam" }
  (no need to submit plaintext — content is dumb, the issue is behavior)

Server:
  marks post as reported
  looks up author_pk → GreenFox42 (pk_dev_A)
  Admin dashboard shows:
    "GreenFox42 — 3 reports in 24h — device: pk_dev_A"
    "BAN / WARN / DISMISS"

Admin clicks BAN:
  Server sets devices.banned_at for pk_dev_A
  Next time User A's device tries to connect: Noise handshake rejected
```

---

## 8. What the Server Knows

| Data | Server sees |
|---|---|
| Who registered (pk_dev) | ✓ (needed for ban) |
| User name + color | ✓ (public anyway) |
| Post ciphertext | ✓ (cannot decrypt — no MLS key) |
| Post metadata (timestamp, author_pk) | ✓ |
| Post plaintext | ✗ |
| MLS group keys | ✗ (stored encrypted per-device) |
| Who reads what | ✓ (can log fetch requests) |
| Admin actions (audit log) | ✓ (logged by TUI) |

---

## 9. Superadmin TUI (Rust)

### 9.1 Architecture

```
┌──────────────────────────────────────────────────────────┐
│  Admin SSHes in                                          │
│  ssh pixheal@server ──► sshd (public key auth)           │
│       │                                                  │
│       ▼                                                  │
│  Shell = admin-tui (Rust binary, compiled for linux/amd64)│
│       │                                                  │
│       ├── Direct SQLite reads (read-only)                │
│       │   └── stats, reports, user lookup                │
│       │                                                  │
│       ├── Direct SQLite writes (write ops)               │
│       │   └── ban/unban, resolve report,                 │
│       │       warn user                                  │
│       │                                                  │
│       └── HTTP to server localhost API (write ops)       │
│           └── community key rotate, MLS kick,            │
│               MLS group export                           │
│                                                          │
│  No auth middleware needed — TUI writes                   │
│  SQLite directly, server localhost API only for ops that   │
│  operations that touch in-memory MLS state.               │
└──────────────────────────────────────────────────────────┘
```

### 9.2 What TUI Reads Directly (SQLite, read-only)

```rust
// rusqlite read queries — TUI opens DB in read-only mode
fn stats(db: &Connection) -> Stats {
    let total_users = db.query_row("SELECT COUNT(*) FROM devices", [], |r| r.get(0)).unwrap();
    let active_users = db.query_row("SELECT COUNT(*) FROM devices WHERE banned_at IS NULL", [], |r| r.get(0)).unwrap();
    let total_posts = db.query_row("SELECT COUNT(*) FROM posts", [], |r| r.get(0)).unwrap();
    let today_posts = db.query_row(
        "SELECT COUNT(*) FROM posts WHERE timestamp > ?",
        [&start_of_day()], |r| r.get(0)
    ).unwrap();
    let unresolved_reports = db.query_row(
        "SELECT COUNT(*) FROM reports WHERE resolved_at IS NULL", [], |r| r.get(0)
    ).unwrap();
    Stats { total_users, active_users, total_posts, today_posts, unresolved_reports }
}

fn recent_reports(db: &Connection) -> Vec<Report> {
    db.prepare("
        SELECT r.id, r.reason, r.reported_at, r.post_id,
               d.user_name, d.user_color, d.pk_dev
        FROM reports r
        JOIN posts p ON p.id = r.post_id
        JOIN devices d ON d.pk_dev = p.author_pk
        WHERE r.resolved_at IS NULL
        ORDER BY r.reported_at DESC
        LIMIT 50
    ").unwrap().query_map([], |row| { /* map to Report struct */ })
}

fn community_info(db: &Connection) -> CommunityInfo {
    db.query_row("SELECT member_count, created_at FROM community WHERE id = 1", [], |r| {
        Ok(CommunityInfo { members: r.get(0)?, created_at: r.get(1)? })
    }).unwrap()
}
```

### 9.3 What TUI Writes Directly (SQLite)

```rust
// Direct writes — no server round-trip needed
fn ban_user(db: &Connection, pk_dev: &[u8]) {
    db.execute("UPDATE devices SET banned_at = ? WHERE pk_dev = ?",
        params![Utc::now().timestamp(), pk_dev]).unwrap();
}

fn unban_user(db: &Connection, pk_dev: &[u8]) {
    db.execute("UPDATE devices SET banned_at = NULL WHERE pk_dev = ?",
        params![pk_dev]).unwrap();
}

fn resolve_report(db: &Connection, report_id: i64, resolution: &str) {
    db.execute("UPDATE reports SET resolved_at = ?, resolution = ? WHERE id = ?",
        params![Utc::now().timestamp(), resolution, report_id]).unwrap();
}
```

### 9.4 What TUI Sends via HTTP (localhost admin API)

Only operations that require the server's in-memory MLS group state:

```
POST /admin/key-rotate   → generate new MLS group key
                             re-encrypt new sk_comm for every device
                             update community.mls_group_state
                             → returns: count of re-encrypted devices

POST /admin/kick/:b64pk  → MLS Remove(pk) from group
                             set devices.banned_at
                             relay MLS Commit to remaining members
                             → returns: ok

GET  /admin/health        → returns: { ok: true, epoch, members }

POST /admin/export        → returns: encrypted bundle of MLS state
```

TUI sends `Authorization: Bearer <file-system-local-token>` or just relies on localhost source IP check.

### 9.5 TUI Layout (ratatui)

```
┌─────────────────────────────────────────────────────────────────┐
│  PixHeal Admin ● connected              Q:quit R:refresh 1:user │
├─────────────────────────────────────────────────────────────────┤
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────┐     │
│  │ Users:   1,247  │ │ Posts:  12,891 │ │ Reports:       38 │    │
│  │ Active:  1,203  │ │ Today:     142 │ │ Unresolved:    12 │    │
│  │ Banned:    44   │ │                │ │                  │     │
│  └────────────────┘ └────────────────┘ └──────────────────┘     │
│                                                                  │
│  Unresolved Reports                     Community Key           │
│  ┌────────────────────────────────────┐ ┌──────────────────────┐│
│  │ ● GreenFox42  spam      2m ago     │ │ Epoch: 12            ││
│  │ ● PurpleLion99 abuse    5m ago     │ │ Members: 1,247       ││
│  │ ● RedBear33   spam      1h ago     │ │ Created: 2026-07-01  ││
│  │ ● BlueOwl7    nsfw      3h ago     │ │ OK                    ││
│  │ ● YellowFox   spam      6h ago     │ │                      ││
│  └────────────────────────────────────┘ └──────────────────────┘│
│                                                                  │
│  [1] View user     [2] Ban/Unban     [3] Key rotate             │
│  [4] Kick member   [5] Resolve report [6] Export backup         │
│                                                                  │
│  Log: ✓ 12:34:56 Banned GreenFox42 (pk_dev: a1b2...c3d4)       │
│       ✓ 12:35:10 Resolved report #42 as "warning"               │
└─────────────────────────────────────────────────────────────────┘
```

### 9.6 Key Rotation Flow (Rust)

Most expensive admin operation — needs to re-encrypt group key for every device.

```rust
fn rotate_key(tui: &mut Tui) -> Result<()> {
    // 1. Confirm with user (destructive — old posts unreadable)
    tui.confirm("Rotate key? All existing posts become unreadable.")?;

    // 2. Generate new MLS group
    let new_group = MlsGroup::new(
        CipherSuite::MLS_128_X25519_AES128GCM_SHA256_Ed25519,
    );
    let new_sk_comm = new_group.export_secret();

    // 3. Re-encrypt for every device (parallel, fast in Rust)
    let devices = tui.db.query("SELECT pk_dev FROM devices WHERE banned_at IS NULL", [])?;

    let progress = tui.progress_bar("Re-encrypting keys...", devices.len());
    let new_encrypted: Vec<(Vec<u8>, Vec<u8>)> = devices.par_iter().map(|row| {
        let pk = X25519PublicKey::from(row.pk_dev);
        let encrypted = Ecies::encrypt(&pk, &new_sk_comm);
        progress.inc(1);
        (row.pk_dev, encrypted)
    }).collect();

    // 4. Batch-write to SQLite
    let tx = tui.db.transaction()?;
    for (pk_dev, encrypted) in &new_encrypted {
        tx.execute("UPDATE devices SET encrypted_sk_comm = ? WHERE pk_dev = ?",
            params![encrypted, pk_dev])?;
    }
    tx.execute("UPDATE community SET mls_group_state = ?, member_count = 1 WHERE id = 1",
        params![new_group.to_bytes(), 1])?;
    tx.commit()?;

    // 5. Notify server via localhost API
    tui.http.post("http://127.0.0.1:PORT/admin/key-rotated", &json!({
        "new_group_state": new_group.to_bytes()
    }))?;

    tui.notify("Key rotated. Only future registrations will get new key.");
    Ok(())
}
```

### 9.7 Build & Deploy

```bash
# Build everything (server + TUI) in one command
cd pixheal-server/
cargo build --release

# scp both binaries to server
scp target/release/pixheal-server server:/usr/local/bin/
scp target/release/admin-tui server:/usr/local/bin/

# Set admin shell
ssh server "sudo usermod -s /usr/local/bin/admin-tui pixheal-admin"

# Run server (systemd service or supervised)
ssh server "sudo systemctl enable --now pixheal-server"
```

### 9.8 Cargo Workspace Structure

```
pixheal-server/
├── Cargo.toml                 # [workspace]
│   └── members = ["server", "admin-tui"]
├── server/
│   ├── Cargo.toml
│   └── src/main.rs            # axum app, public + admin API
├── admin-tui/
│   ├── Cargo.toml
│   └── src/main.rs            # ratatui app
└── shared/                    # (optional) shared DB types, crypto helpers
    ├── Cargo.toml
    └── src/lib.rs
```

---



## 10. Implementation Priority

### Phase 3: Post Feed (Week 3-4)

- [ ] Android: POST /post with MLS encryption + Ed25519 signature
- [ ] Android: GET /feed with MLS decryption + signature verification
- [ ] Server: Feed pagination + author_pk lookup
- [ ] Test: 3 devices, cross-read, verify authorship

### Phase 0: Admin TUI (Week 0-1, parallelizable)

- [ ] Rust project scaffold (`cargo init admin-tui`, add ratatui + rusqlite + reqwest)
- [ ] TUI layout: dashboard stats, reports list, community info panel
- [ ] SQLite read queries: count users/posts/reports
- [ ] SQLite write ops: ban/unban user, resolve report
- [ ] SSH shell setup (`sudo usermod -s /path/admin-tui pixheal-admin`)
- [ ] Cross-compile and deploy

### Phase 1: Auth + Identity (Week 1)

- [ ] Noise IK handshake (transport auth + forward secrecy)
- [ ] Device keypair generation + AndroidKeyStore
- [ ] Server: Rust project scaffold (axum + rusqlite + openmls)
- [ ] Server: POST /register endpoint
- [ ] Android: Registration flow (receive name + color)
- [ ] Test: register device, get name back

### Phase 2: MLS Group Encryption (Week 2-3)

- [ ] Android: Add `kotlin-mls` dependency
- [ ] Server: MLS group creation on first user (openmls)
- [ ] Android: MLS Add member on join
- [ ] Android: MLS Remove member on kick
- [ ] Server: Relay MLS messages between members
- [ ] Test: 2 devices → both decrypt same post

### Phase 3: Post Feed (Week 3-4)

- [ ] Android: POST /post with MLS encryption + Ed25519 signature
- [ ] Android: GET /feed with MLS decryption + signature verification
- [ ] Server: Feed pagination + author_pk lookup
- [ ] Test: 3 devices, cross-read, verify authorship

### Phase 4: Moderation + Admin API (Week 4)

- [ ] Server: POST /report endpoint
- [ ] Server: localhost admin API (health, kick, key-rotate)
- [ ] TUI: localhost HTTP calls for key rotate / kick
- [ ] TUI: audit log write for all admin actions
- [ ] Server: Noise handshake rejects banned pk_dev
- [ ] Test: TUI ban → device rejected on reconnect

### Phase 5: Ship (Week 5)

- [ ] Rate limiting per pk_dev
- [ ] MLS key rotation on join/leave
- [ ] TUI: key rotation with progress bar + re-encrypt all devices
- [ ] Deploy to free tier (Fly.io or Railway)

---

## 11. Database Schema (SQLite)

```sql
CREATE TABLE devices (
    pk_dev          BLOB PRIMARY KEY,
    user_name       TEXT NOT NULL,
    user_color      INTEGER NOT NULL,
    encrypted_sk_comm BLOB,
    registered_at   INTEGER NOT NULL,
    banned_at       INTEGER,
    last_seen_at    INTEGER
);

CREATE TABLE community (
    id              INTEGER PRIMARY KEY DEFAULT 1,
    mls_group_state BLOB,
    created_at      INTEGER NOT NULL,
    member_count    INTEGER DEFAULT 1
);

CREATE TABLE posts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ciphertext_comm BLOB NOT NULL,
    author_pk       BLOB NOT NULL REFERENCES devices(pk_dev),
    author_sig      BLOB NOT NULL,
    timestamp       INTEGER NOT NULL,
    mls_epoch       INTEGER NOT NULL
);

CREATE TABLE reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id         INTEGER NOT NULL REFERENCES posts(id),
    reporter_pk     BLOB NOT NULL REFERENCES devices(pk_dev),
    reason          TEXT,
    reported_at     INTEGER NOT NULL,
    resolved_at     INTEGER,
    resolution      TEXT
);

CREATE INDEX idx_posts_timestamp ON posts(timestamp DESC);
CREATE INDEX idx_posts_author ON posts(author_pk);
```

---

## 12. Key References

| Resource | URL |
|---|---|
| MLS RFC 9420 | https://datatracker.ietf.org/doc/html/rfc9420 |
| kotlin-mls (Android) | https://github.com/openmls/kotlin-mls |
| OpenMLS (Rust) | https://github.com/openmls/openmls |
| mls-rs (AWS, Rust+WASM) | https://github.com/aws/mls-rs |
| Noise Protocol Framework | https://noiseprotocol.org/noise.html |
| noise-kotlin (Android auth) | https://github.com/sander/noise-kotlin |
| ratatui (Rust TUI) | https://github.com/ratatui-org/ratatui |
| axum (Rust HTTP) | https://github.com/tokio-rs/axum |
| rusqlite | https://github.com/rusqlite/rusqlite |
| reqwest (Rust HTTP client) | https://github.com/seanmonstar/reqwest |
| x25519-dalek | https://github.com/dalek-cryptography/x25519-dalek |
| X25519 RFC 7748 | https://datatracker.ietf.org/doc/html/rfc7748 |
| Ed25519 RFC 8032 | https://datatracker.ietf.org/doc/html/rfc8032 |
| Fly.io free tier | https://fly.io/docs/about/pricing/#free-allowances |
| Railway free tier | https://railway.app/pricing |
| Oracle Cloud free tier | https://www.oracle.com/cloud/free/ |

---

## 13. Summary

```
User experience:
  ┌──────────────────────────────────────┐
  │  Community Feed                      │
  │                                      │
  │  GreenFox42 · 2m ago                 │
  │  hello world                         │
  │                                      │
  │  PurpleLion99 · 5m ago               │
  │  what's everyone up to?              │
  │                                      │
  │  ┌────────────────────────────────┐  │
  │  │ Write something...             │  │
  │  └────────────────────────────────┘  │
  └──────────────────────────────────────┘

Behind the scenes:
  ✓ Every user = device key → fixed random name + color
  ✓ All posts MLS-encrypted → server blind to content
  ✓ Anyone in community can read any post (shared group key)
  ✓ Ed25519 signatures → authorship verified, no impersonation
  ✓ MLS membership management → forward secrecy on kick
  ✓ Report flow → admin sees name + device key, no content needed
  ✓ Ban → device key rejected at handshake
  ✓ No moderation keypair, no double encryption, no blockchain
  ✓ Admin TUI in Rust (ratatui + rusqlite) — SSH login → dashboard
  ✓ Key rotation in Rust — parallel re-encrypt across all devices
  ✓ Total cost: $0/month
```

---

*Document version 3.0 — 2026-07-23*
*References: MLS RFC 9420, Noise Protocol Framework Rev 34, kotlin-mls, OpenMLS, ratatui, rusqlite*
