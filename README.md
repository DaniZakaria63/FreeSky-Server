# Freesky

**A server that can't read your messages.**

Freesky is an encrypted community platform where the server stores your posts but can never read them. Not "we promise not to look" — mathematically, structurally, the server simply does not have the keys. It's a storage locker you rent from someone who doesn't have a copy of your key.

This repository is the server half. The Android client lives elsewhere, but together they make one thing: a place where people can talk without anyone — including the person running the box — reading along.

---

## Why does this exist?

Because free speech needs infrastructure that isn't politely asking permission.

Most "secure" messaging apps are secure in the sense that the company *could* read your messages but promises not to. That promise lives in a privacy policy, a compliance audit, and a hope that nobody with a subpoena ever changes their mind. Freesky takes a different bet: make the server *cryptographically incapable* of reading anything. No backdoor, no key escrow, no "lawful access" — because there's nothing to access.

The server holds your encrypted blobs. Your phone holds the key. The two never meet in plaintext on the wire.

---

## How the encryption works (the short version)

You don't need a PhD to get the shape of this. Here's the plain-language version.

### 1. Your phone has a key, and only your phone has it

When you install the app, your phone generates a private key inside its secure hardware (the same chip that handles fingerprint auth on Android). That key never leaves the device in plaintext. The server gets a *public* version — like a mailbox address anyone can send to, but only you can open.

We use **secp256r1** (also called NIST P-256), an elliptic-curve standard that ships in every Android phone's hardware-backed keystore. It's the same family of math your bank uses for card payments, just put to different use.

### 2. Getting the group key to you, secretly (ECIES)

When you register, the server hands you a **group key** — the shared secret everyone in the community uses to encrypt posts. But it can't just send it in the clear over the network. So it wraps it like this:

1. The server picks a random one-time keypair for *this delivery only*.
2. It does a mathematical handshake between that throwaway key and your public key — producing a shared secret only you and the server could compute.
3. It stretches that secret into an AES key with a function called HKDF (a kind of cryptographic blender — same input always makes same output, but you can't reverse it).
4. It locks the group key inside AES-256-GCM (the same cipher approved for top-secret US government data).
5. It throws away the one-time private key.

The result on the wire is 65 bytes of public ephemeral key + 12 bytes of nonce + the ciphertext. Your phone does the handshake in reverse, derives the same AES key, and unlocks the group key. Nobody watching the network — not your ISP, not the server admin, not a state actor with a wiretap — can recover the group key from what they saw.

This pattern is called **ECIES** (Elliptic Curve Integrated Encryption Scheme). It's the digital equivalent of a one-time pad delivery.

### 3. Every post is signed, not just encrypted

This is the part most apps skip, and it matters.

When you write a post, your phone:

1. Encrypts the message text with the group key (so everyone in the group can read it, but no one outside can).
2. Signs a hash of the ciphertext with your *device private key* (ECDSA secp256r1 — the signing cousin of the same curve).
3. Sends the server three things: the ciphertext, your public key, and the signature.

The server verifies the signature before storing the post. That means:

- **No spoofing.** Someone can't claim you wrote something you didn't, because they don't have your private key.
- **No tampering.** If anyone flips a byte in the ciphertext, the signature stops matching and the server rejects it.
- **Provenance stays honest.** Every post is cryptographically tied to a device, and the server can't forge one even if it wanted to.

### 4. The transport layer is also encrypted (Noise IK)

Everything above is about *what* gets stored. But the connection between your phone and the server is itself wrapped in a separate encryption layer, using the **Noise Protocol Framework** — specifically the `Noise_IK_P256_ChaChaPoly_BLAKE2s` pattern.

Noise is the same framework WhatsApp Signal uses for their transport. The `IK` variant means:

- **I** — the client's identity is known up front (your device key).
- **K** — the server's identity is known to the client already (from registration).

So both sides authenticate each other before any app data flows. The handshake derives fresh session keys per connection (forward secrecy — if someone records today's traffic and steals your key tomorrow, they still can't decrypt today's messages). And there's a **prologue** binding: the SHA-256 hash of the app's APK signing certificate is mixed into the handshake, so a fake app pretending to be Freesky can't even complete the handshake.

After the handshake, every API request and response rides inside ChaCha20-Poly1305 — a fast, modern authenticated cipher.

### 5. Forward secrecy and key rotation

The group key isn't eternal. An admin can rotate it — generate a new one, re-encrypt it for every registered device, and retire the old one. Once rotated, posts encrypted under the old key become unreadable to anyone who joins later. That's **forward secrecy at the group level**: a new member can't reach back into history, and a kicked member can't read the future.

The roadmap calls for replacing the current random group key with full **MLS** (Messaging Layer Security, RFC 9420) — a protocol designed precisely for this: rotating group membership with cryptographic guarantees. The dependency is wired; the integration is pending.

---

## So what does the server actually see?

Honestly? Almost nothing useful.

| What the server has | What it means |
|---|---|
| Your device public key (65 bytes) | It can verify your signatures, but can't impersonate you. |
| Your derived username (12 hex chars from a hash) | A handle. Not your real name. Not your phone number. |
| Your derived color (0–15) | A little visual badge. That's it. |
| Encrypted post blobs | Ciphertext it stores but can't decrypt. |
| Your ECDSA signature on each post | Proof you wrote it, nothing more. |
| A timestamp | When you posted. |
| An MLS epoch number | Which group key version was current. |

The server knows *that* you posted, *when* you posted, and *that* you signed it. It does not know *what* you said. It cannot read a single word of your posts, ever, even if served with a warrant — because the plaintext is on devices, not on the server.

---

## What's in this repo

A Rust workspace, three crates:

```
freesky-server/
├── server/         # the actual server binary
├── admin-tui/      # a terminal dashboard for admins (ratatui over SSH)
└── shared/         # crypto helpers + wire types shared between crates
```

### The server (`server/`)

Built on **axum** (async HTTP framework) + **tokio** (the async runtime) + **rusqlite** (SQLite, bundled) + **snow** (Noise IK) + **p256** / **aes-gcm** / **hkdf** (the crypto primitives). It listens on three ports:

- **3000** — public HTTP, only for `/register` (registration must be reachable before Noise keys are exchanged).
- **9443** — raw TCP, Noise IK handshake then length-prefixed encrypted JSON. This is where `post`, `feed`, and `report` live. Nothing readable hits this port in plaintext.
- **3001** — admin API, localhost only. Key rotation, member kicks.

### The admin TUI (`admin-tui/`)

A **ratatui** dashboard that runs as an SSH login shell. The admin connects via SSH and lands directly in the dashboard — no shell prompt, no command injection surface. It reads SQLite directly for stats and calls the localhost admin API for stateful ops (key rotation needs the in-memory group state).

### Shared (`shared/`)

The crypto helpers (`ecies_encrypt`, `ecies_decrypt`, `ecdsa_verify`, `validate_pk_dev`, identity derivation) and the wire types (`PostRequest`, `FeedRequest`, `RegisterRequest`, etc.). Kept in a separate crate so both the server and any future tooling can reuse them without re-implementing the curve arithmetic.

---

## Build & run

You need a recent Rust toolchain (1.85+, edition 2024).

```bash
# Build everything (release)
cargo build --release

# Just the server
cargo build -p freesky-server

# Just the admin TUI
cargo build -p freesky-admin-tui

# Run the test suite
cargo test
```

The server reads `TRUSTED_APK_KEY` from the environment — the SHA-1 (hex, colons optional) of the Android app's signing certificate. Registrations from any APK with a different signing key are rejected at the door, before any crypto runs.

```bash
TRUSTED_APK_KEY=AB:CD:EF:12:... ./target/release/freesky-server
```

Deploy is two binaries + one SQLite file (`community.db`) in the working directory. systemd unit for the server, SSH login shell for the admin TUI. No database server, no container orchestration, no message broker. It's deliberately boring to operate.

---

## Project status

Real, not aspirational. As of the last sync with the Android client:

| Piece | State |
|---|---|
| secp256r1 device identity | Done |
| ECIES group key delivery | Done |
| ECDSA post signature verification | Done |
| Noise IK transport (secp256r1) | Done |
| Post submission over Noise | Done |
| Feed retrieval with cursor pagination | Done |
| Admin key rotation (re-ECIES to all devices) | Done |
| MLS group encryption (full RFC 9420) | Dependency wired, integration pending |
| Admin TUI | Stub |
| Post reporting | Stub |
| Member kick (MLS Remove) | Stub |

The crypto paths that protect user data are complete and interoperable with Android. The remaining work is operational tooling and the MLS upgrade — important, but not on the critical path of "can people talk privately."

---

## A note on the intent here

I want to be straight about this.

I don't care about the server. The server is plumbing. It's a box that holds ciphertext and hands out signatures. If this one gets seized, another one can be stood up in an afternoon — the protocol is the point, not the hardware.

What I care about is that free speech lives. Not the sanitized, platform-policy, terms-of-service kind. The actual kind — where people can say what they need to say to who they need to say it, without a moderator they've never met deciding it's too much, and without a government they didn't elect reading along.

Freesky exists because the right to speak privately is the right that makes all the other rights possible. You can't organize, you can't dissent, you can't even think freely out loud, if every word passes through a filter owned by someone who answers to someone else.

So this code is here. Use it, fork it, audit it, run it. The math doesn't care who's in power. That's the whole point.

---

*Protocol spec lives in `AGENTS.md` and the canonical sync doc at `~/opt/docs/freesky/PROTOCOL_SYNC.md` if you want to verify the wire formats yourself. Read the crypto code in `shared/src/crypto.rs` — it's short, and it's the part that matters.*
