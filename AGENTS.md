# Freesky Server — AGENTS.md

## Project

Rust workspace: encrypted community app server. Server stores MLS-encrypted posts, cannot read content. Users authenticated via Noise IK handshake + X25519 device keys. Admin via ratatui TUI over SSH.

## Priorities

- **Memory efficiency** — minimize allocations in hot paths (Noise handshake, MLS encrypt/decrypt, feed pagination). Prefer `Vec` reuse, buffer pooling, zero-copy deser where practical.
- **Fast encrypt processing** — Noise transport encrypts every request/response. MLS encrypts every post write. Both paths must minimize syscalls and copying. Benchmark regressions in crypto paths are blockers.

## Workspace structure

```
freesky-server/
├── Cargo.toml              # workspace root
├── server/                 # axum + noise listener + rusqlite + openmls
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs         # tokio main, dual listener (3000 HTTP, 9443 Noise)
│       ├── noise.rs        # Noise IK handshake (snow crate)
│       ├── routes.rs       # register, post, feed
│       ├── admin.rs        # localhost admin API
│       └── db.rs           # SQLite queries + schema
├── admin-tui/              # ratatui dashboard (SSH login shell)
│   ├── Cargo.toml
│   └── src/main.rs
└── shared/                 # shared types, crypto helpers (optional)
    ├── Cargo.toml
    └── src/lib.rs
```

## Key commands

```bash
cargo build --release          # build all (server + admin-tui)
cargo build -p server          # just server binary
cargo build -p admin-tui       # just admin-tui binary
cargo test                     # all tests
cargo test -p server           # server tests only
scp target/release/server <host>:/usr/local/bin/freesky-server
scp target/release/admin-tui <host>:/usr/local/bin/
```

## Architecture

### Transport (Noise IK, port 9443)

- `snow` crate, pattern `Noise_IK_25519_ChaChaPoly_BLAKE2s`
- Prologue = SHA-256 of APK signing cert (app key)
- Every connection: mutual auth, forward secrecy, session key derivation
- After handshake, all API payloads encrypted with ChaChaPoly session keys
- Only TCP raw socket (no HTTP framing on Noise port)

### REST API (axum, port 3000)

- `POST /register` — device registers secp256r1 pk_dev (65-byte SEC1), receives name+color+encrypted group key (ECIES)
- `POST /post` — receives MLS ciphertext + ECDSA secp256r1 sig, verifies author, stores blob
- `GET /feed` — paginated posts, ciphertext returned (client decrypts)
- `POST /report` — report a post (reporter_pk + reason)

### Database (SQLite, rusqlite bundled)

Schema in `docs/community-app-crypto-plan.md` §11: `devices`, `community`, `posts`, `reports`. Key constraint: `pk_dev BLOB PRIMARY KEY` in devices.

### MLS (openmls)

- Single community group (1 group per server instance)
- **Admin creates group key** via `POST /admin/key-rotate` (not on first registration)
- Users register → get ECIES-encrypted group key (must exist, else 503)
- ECIES = secp256r1 ECDH + AES-256-GCM (`p256` + `aes-gcm` crate) — 65-byte SEC1 epk + 12-byte nonce
- Posts signed with ECDSA secp256r1 (`p256` ECDSA) — author_pk + author_sig on every post
- MLS epoch tracked per post for forward secrecy verification

### Admin TUI (ratatui + rusqlite + reqwest)

- Runs as SSH login shell (`sudo usermod -s /usr/local/bin/admin-tui admin`)
- Reads SQLite directly (read-only queries)
- Writes bans/reports directly to SQLite
- Calls localhost API for MLS ops (key rotate, kick — need in-memory group state)
- No auth middleware needed (SSH + localhost source IP)

## Conventions

- `snake_case` for Rust identifiers
- Use `thiserror` for error types, `anyhow` for top-level error handling
- SQL queries inline in Rust (no ORM)
- Crypto operations use `p256` + `aes-gcm` crate (for secp256r1 compat with Android), not dalek crates
- Buffer reuse pattern: allocate request/response buffers once, reuse across Noise transport loop
- No `unsafe` without benchmark justification + safety comment
- All public API inputs validated at boundary, then pass validated types internally
- `pk_dev` = raw 65-byte SEC1 uncompressed (0x04 || x || y), stored as BLOB in DB
- **App authentication**: registration requires `apk_cert_sha1` matching `TRUSTED_APK_KEY` env var (single key per environment — dev uses debug key, prod uses release key)

## Rust code style

- **Error handling**: propagate with `?` at boundaries. Use `thiserror` for domain errors, `anyhow` for top-level. Avoid `.unwrap()` / `.expect()` in non-test code.
- **Zero-cost abstractions**: prefer newtypes (`struct PkDev([u8; 65])`) over raw `Vec<u8>` for domain concepts. Use `Cow<'a, T>` when returning borrowed-or-owned.
- **Borrow, don't clone**: functions take `&[u8]` not `Vec<u8>` unless they need ownership. Use `Arc<T>` for cross-thread shared state.
- **Iterator chains**: prefer `.into_iter().filter().map().collect()` over manual loops with `Vec::push`.
- **Memory efficiency**: use `Vec::with_capacity` when size is known. Reuse buffers in hot paths (Noise transport, feed pagination).
- **Documentation**: `///` doc comments on all public items with `# Examples` and `# Errors` sections.
- **Formatting**: `cargo fmt` must pass. `cargo clippy` must pass with zero warnings.
- **Async**: use `async fn` for readability. Use `tokio::spawn_blocking` for CPU-bound work (crypto, DB). Never mix blocking and async code.

## Test expectations

- SQLite in-memory (`:memory:`) for unit tests
- Need `openmls` group setup for integration tests (2+ simulated devices)
- Key rotation test: verify old ciphertext unreadable after rotate, new device can still register
- Ban test: verify Noise handshake rejects after `banned_at` set
- Benchmarks for: Noise handshake throughput, MLS encrypt/decrypt, ECIES re-encrypt all devices

## Deploy

```bash
cargo build --release --target x86_64-unknown-linux-gnu
# binaries: target/release/server, target/release/admin-tui
# systemd service for server, admin shell for admin-tui
```

Single SQLite file (`community.db`) at server working directory.

## Source of truth

**Canonical protocol sync** at `/home/dani/opt/docs/freesky/` — single source of truth for all Android↔Server wire formats, curve choices, API shapes. Read `PROTOCOL_SYNC.md` first. Overrides docs/ if conflict.

Key points from sync doc:
- **Android uses secp256r1** (NIST P-256), NOT X25519. AndroidKeyStore constraint.
- **All ECIES must use** secp256r1 ECDH + AES-256-GCM + 65-byte SEC1 keys + 12-byte nonce.
- **All signatures must use** ECDSA secp256r1 (SHA256withECDSA), NOT Ed25519.
- `pk_dev` = 65-byte SEC1 uncompressed (0x04 || x || y), NOT 32-byte X25519.
- Current code uses X25519 + ChaChaPoly + Ed25519 — **must be rewritten** to match Android.

Both plan docs in `docs/` are stale. Fix them after verifying against PROTOCOL_SYNC.md.
