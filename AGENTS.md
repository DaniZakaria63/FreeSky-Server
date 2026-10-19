# Freesky Server — AGENTS.md

## Project

Rust workspace: encrypted community app server. Server stores MLS-encrypted posts, cannot read content. Users authenticated via Noise NK handshake + secp256r1 device keys. Admin via a ratatui TUI that runs on the server itself and is reached over SSH — the admin API is never published.

## Priorities

- **Memory efficiency** — minimize allocations in hot paths (Noise handshake, MLS encrypt/decrypt, feed pagination). Prefer `Vec` reuse, buffer pooling, zero-copy deser where practical.
- **Fast encrypt processing** — Noise transport encrypts every request/response. MLS encrypts every post write. Both paths must minimize syscalls and copying. Benchmark regressions in crypto paths are blockers.

## Workspace structure

```
freesky-server/
├── Cargo.toml              # workspace root
├── server/                 # axum + noise listener + libsql + openmls
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs         # tokio main, dual listener (3000 HTTP, 9443 Noise)
│       ├── noise.rs        # Noise NK handshake (snow crate)
│       ├── routes.rs       # register, post, feed
│       ├── admin.rs        # admin API (127.0.0.1:3001, SSH-only)
│       └── db.rs           # libsql connection (local file or remote Turso)
├── admin-tui/              # ratatui dashboard (runs on the server, over SSH)
│   ├── Cargo.toml
│   └── src/main.rs
└── shared/                 # shared types, crypto helpers (optional)
    ├── Cargo.toml
    └── src/lib.rs
```

## Key commands

```bash
cargo build --release              # build all (server + admin-tui)
cargo build -p freesky-server      # just server binary
cargo build -p freesky-admin-tui   # just TUI binary (target/release/admin-tui)
cargo test                         # all tests
cargo test -p freesky-server       # server tests only
cargo install --path admin-tui     # install the TUI locally (deploy ships it to the VPS)
scp target/release/freesky-server <host>:/usr/local/bin/freesky-server
```

## Architecture

### Transport (Noise NK, port 9443)

- `snow` crate, pattern `Noise_NK_P256_ChaChaPoly_BLAKE2s`
- Prologue = SHA-256 of APK signing cert (app key)
- Every connection: mutual auth, forward secrecy, session key derivation
- After handshake, all API payloads encrypted with ChaChaPoly session keys
- Only TCP raw socket (no HTTP framing on Noise port)

### REST API (axum, port 3000)

- `POST /register` — device registers secp256r1 pk_dev (65-byte SEC1), receives name+color+encrypted group key (ECIES)
- **Post, feed, report are NOT on HTTP** — they are only available over Noise (port 9443)

### Noise Transport (port 9443)

- `Noise_NK_P256_ChaChaPoly_BLAKE2s` pattern via `snow` crate
- Prologue = SHA-256 of APK signing cert (app key)
- All API operations (post, feed, report) go through encrypted Noise transport
- Length-prefixed encrypted JSON messages after handshake

### Database (libsql — local SQLite file or remote Turso)

Schema created by `queries.rs::run_schema` (mirrors `docs/community-app-crypto-plan.md` §11): `devices`, `community`, `posts`, `reports`, `server_config`. Key constraint: `pk_dev BLOB PRIMARY KEY` in devices. `TURSO_URL` selects local (`file://...`) or remote (`libsql://...`) mode.

### MLS (openmls)

- Single community group (1 group per server instance)
- **Admin creates group key** via `POST /admin/key-rotate` (not on first registration)
- Users register → get ECIES-encrypted group key (must exist, else 503)
- ECIES = secp256r1 ECDH + AES-256-GCM (`p256` + `aes-gcm` crate) — 65-byte SEC1 epk + 12-byte nonce
- Posts signed with ECDSA secp256r1 (`p256` ECDSA) — author_pk + author_sig on every post
- MLS epoch tracked per post for forward secrecy verification

### Admin TUI (ratatui + reqwest)

- **Access is SSH only.** The TUI runs on the server and talks to
  `127.0.0.1:3001`; `/usr/local/bin/freesky-admin` supplies `X-App-Key` from
  `/etc/freesky.env` so the operator types no credentials.
  Guide: `docs/admin-tui-ssh.md`
- The admin API is deliberately **not** published through the Cloudflare Tunnel.
  It was, with no Access application in front, which left it on the public
  internet guarded only by `X-App-Key` — a value that ships inside the APK.
  Do not re-publish it: beyond that header the origin has no way to tell who is
  calling, so remote access means administration on the open internet
- Install globally: `cargo install --path admin-tui` (binary: `admin-tui`)
- Deploy: `.github/workflows/deploy.yml` ships `freesky-server` **and**
  `admin-tui` + the wrapper scripts; `scripts/freesky-deploy.sh` is the root
  helper that installs them on the VPS
- Admin API endpoints: `/admin/health`, `/admin/stats`, `/admin/reports`,
  `/admin/reports/{id}/resolve`, `/admin/community`, `/admin/devices?q=`,
  `/admin/ban/{pk}`, `/admin/unban/{pk}`, `/admin/kick/{pk}`, `/admin/key-rotate`
- API refuses to serve when `TRUSTED_APK_KEY` is unset (503) — no "auth disabled" mode
- Setup guide: `docs/admin-tui-ssh.md`

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
# binaries: target/release/freesky-server, target/release/admin-tui
# server: systemd service (deploy.sh / GitHub Actions push to master)
# admin-tui: shipped by the deploy workflow, runs on the server via `freesky-admin`
```

Server data: single SQLite file (`community.db`, `TURSO_URL=file://...`) or remote Turso.

## Source of truth

**Canonical protocol sync** (`PROTOCOL_SYNC.md`, kept separately from this repo) — single source of truth for all Android↔Server wire formats, curve choices, API shapes. Overrides `docs/` if conflict.

Key points from sync doc:
- **Android uses secp256r1** (NIST P-256), NOT X25519. AndroidKeyStore constraint.
- **All ECIES must use** secp256r1 ECDH + AES-256-GCM + 65-byte SEC1 keys + 12-byte nonce.
- **All signatures must use** ECDSA secp256r1 (SHA256withECDSA), NOT Ed25519.
- `pk_dev` = 65-byte SEC1 uncompressed (0x04 || x || y), NOT 32-byte X25519.
- Current code uses X25519 + ChaChaPoly + Ed25519 — **must be rewritten** to match Android.

Both plan docs in `docs/` are stale. Fix them after verifying against PROTOCOL_SYNC.md.
