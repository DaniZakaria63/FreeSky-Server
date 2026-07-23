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

- `POST /register` — device registers X25519 pk_dev, receives name+color+encrypted group key (ECIES)
- `POST /post` — receives MLS ciphertext + Ed25519 sig, verifies author, stores blob
- `GET /feed` — paginated posts, ciphertext returned (client decrypts)
- `POST /report` — report a post (reporter_pk + reason)

### Database (SQLite, rusqlite bundled)

Schema in `docs/community-app-crypto-plan.md` §11: `devices`, `community`, `posts`, `reports`. Key constraint: `pk_dev BLOB PRIMARY KEY` in devices.

### MLS (openmls)

- Single community group (1 group per server instance)
- First user: group created on register; subsequent users: get ECIES-encrypted group key
- ECIES = X25519 + ChaCha20Poly1305 (`x25519-dalek` + `chacha20poly1305`)
- Posts signed with Ed25519 (`ed25519-dalek`) — author_pk + author_sig on every post
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
- Crypto operations use dalek crates (`x25519-dalek`, `ed25519-dalek`), not `ring`
- Buffer reuse pattern: allocate request/response buffers once, reuse across Noise transport loop
- No `unsafe` without benchmark justification + safety comment
- All public API inputs validated at boundary, then pass validated types internally
- `pk_dev` = raw 32-byte X25519 public key bytes, no hex encoding in DB (BLOB)

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

Both plan docs in `docs/` define the spec. If ambiguity, prefer the Rust crate examples (openmls, snow) over prose. Talk to user before diverging from plan.
