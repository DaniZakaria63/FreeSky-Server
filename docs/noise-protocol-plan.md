# Noise Protocol — Android ↔ Server Transport Authentication

> **Goal**: Authenticate every Android device to the community server with mutual proof of identity, forward secrecy, and no passwords. The server stores no session state — every connection proves device ownership via 3-layer keys.

---

## 1. Three-Layer Key Model

```
Layer 3: Session Key (ephemeral, per-connection)
          ├── Generated fresh every Noise IK handshake
          ├── Forward secrecy — leak today, past sessions safe
          └── Used to encrypt all API payloads

Layer 2: Device Key (long-lived, per-install)
          ├── X25519 keypair (sk_dev, pk_dev)
          ├── Generated on first launch, stored in AndroidKeyStore
          ├── Cannot be extracted from AndroidKeyStore
          └── Registered with server on first connect

Layer 1: App Key (immutable, per-build)
          ├── SHA-256 of APK signing certificate
          ├── Every PixHeal APK has a fixed signing cert
          ├── Hardcoded into app binary at compile time
          └── Server rejects connections from tampered/mods
```

### 1.1 Why Three Layers?

| Layer | Leak scenario | Mitigation |
|---|---|---|
| Session key leak (network capture) | Past sessions still secure | Forward secrecy via Noise ephemeral key exchange |
| Device key leak (phone rooted, KeyStore bypassed) | Only that device compromised | Server bans sk_dev. Other devices unaffected. |
| App key leak (APK decompiled, cert extracted) | Attacker must also have device key | Hardcoding cert hash in app — tampering changes signing cert, server rejects |
| App key + Device key both leaked | Attaker impersonates a legitimate user | Report + ban flow. Also: app key same for all builds, so mass-impersonation risk. Mitigate by per-build rotation. |

---

## 2. Noise Protocol — IK Handshake

### 2.1 Why IK Pattern?

Noise IK (Identity + Key) provides:
- **Mutual authentication**: Both sides prove possession of static keys
- **Zero round-trip overhead**: Complete in 2 messages (1 round trip)
- **Forward secrecy**: Ephemeral keys exchanged during handshake
- **Identity hiding**: Server learns client's static key; client's identity is known to server (acceptable — server needs pk_dev for bans)

### 2.2 Handshake Flow

```
Noise_IK_25519_ChaChaPoly_BLAKE2s

Pre-requisites:
  Client knows:   pk_app (APK signing cert hash), sk_dev, pk_dev, pk_server
  Server knows:   sk_server, pk_server, {pk_dev, pk_app} for each registered device

Message 1 — Client → Server:
  client_ephemeral_pk || encrypted_client_static || tag
  ├── client_ephemeral_pk: X25519 public key (fresh random)
  ├── encrypted_client_static: EncryptAndAuth(pk_dev, mix_key)  ← authenticated with ephemeral
  └── tag: AEAD authentication tag

  Server decrypts pk_dev from the payload.
  Server looks up {pk_dev, pk_app} in database.
  Server computes shared secret = DH(sk_server, client_ephemeral_pk) + DH(sk_server, pk_dev)
  Server derives session keys from shared secret.

Message 2 — Server → Client:
  server_ephemeral_pk || encrypted_empty || tag
  ├── server_ephemeral_pk: X25519 public key (fresh random)
  ├── encrypted_empty: empty payload (padded)  ← proves server knows sk_server
  └── tag: AEAD authentication tag

  Client computes shared secret = DH(sk_dev, server_ephemeral_pk) + DH(sk_dev, pk_server)
  Client derives session keys === server's session keys (confirmed by decrypting Message 2)
  Mutual authentication complete.

From this point: all application data encrypted with session keys (ChaChaPoly).
```

### 2.3 Key Derivation

```
IK handshake produces two session keys:
  ┌──────────────────────────────┬──────────────────────────────┐
  │  send_key (client → server)  │  recv_key (server → client)  │
  ├──────────────────────────────┼──────────────────────────────┤
  │  Used to encrypt API         │  Used to decrypt server      │
  │  request payloads            │  response payloads           │
  └──────────────────────────────┴──────────────────────────────┘

Derivation:
  h = Hash("Noise_IK_25519_ChaChaPoly_BLAKE2s")  ← protocol name
  ck = h                                           ← chaining key
  h = Hash(h || client_ephemeral_pk)               ← mix client's ephemeral
  ck, k = HKDF(ck, DH(sk_dev, pk_server))          ← mix static-static DH
  h = Hash(h || pk_dev)                             ← mix client's static
  ck, k = HKDF(ck, DH(sk_dev, server_ephemeral_pk))← mix static-ephemeral DH
  h = Hash(h || decrypted_empty)                   ← mix server proof
  send_key, recv_key = HKDF(ck, empty)             ← split into two session keys
```

---

## 3. Android Implementation (noise-kotlin)

```kotlin
// build.gradle.kts (app module)
dependencies {
    implementation("nl.sanderdijkhuis:noise-kotlin:2.0.0")
}

// ── Key generation on first launch ──
class DeviceKeyManager(context: Context) {
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun generateDeviceKey(): KeyPair {
        val generator = KeyPairGenerator.getInstance("X25519", "AndroidKeyStore")
        generator.initialize(
            KeyGenParameterSpec.Builder("pixheal-device-key")
                .setKeySize(256)
                .setKeyPurpose(KeyPurpose.SIGN, KeyPurpose.ENCRYPT)
                .setAlgorithmParameterSpec(ECGenParameterSpec("X25519"))
                .build()
        )
        return generator.generateKeyPair()
    }

    fun getDeviceKey(): KeyPair {
        val privateKey = keyStore.getEntry("pixheal-device-key", null) as? PrivateKey
            ?: return generateDeviceKey()
        return KeyPair(getPublic(privateKey), privateKey)
    }
}

// ── App Key (from APK signing certificate) ──
object AppKey {
    fun getHash(context: Context): ByteArray {
        val packageInfo = context.packageManager.getPackageInfo(
            context.packageName,
            PackageManager.GET_SIGNATURES
        )
        val cert = packageInfo.signatures[0].toByteArray()
        return MessageDigest.getInstance("SHA-256").digest(cert)
    }
}

// ── Noise IK Handshake ──
class NoiseHandshake(
    private val appKey: ByteArray,       // SHA-256 of APK signing cert
    private val deviceKey: KeyPair,      // from AndroidKeyStore
    private val serverKey: X25519PublicKey  // server's static public key (hardcoded or fetched)
) {
    suspend fun handshake(socket: RawSocket): NoiseSession {
        val prologue = appKey  // bind connection to app identity

        val handshake = NoiseHandshakeBuilder(
            pattern = NoisePattern.IK,
            dh = X25519DH(),
            cipher = ChaChaPolyCipher(),
            hash = Blake2sHash(),
            prologue = prologue
        ).build(
            s = deviceKey.private.toX25519(),    // local static
            rs = serverKey                        // remote static (known a priori)
        )

        // Message 1: client → server
        val msg1 = handshake.writeMessage()      // includes client ephemeral + encrypted static
        socket.send(msg1)

        // Message 2: server → client
        val msg2 = socket.receive()
        handshake.readMessage(msg2)

        // Session keys established
        return NoiseSession(
            sendKey = handshake.sendKey,
            recvKey = handshake.recvKey,
        )
    }
}

// ── Encrypted API request ──
class NoiseTransport(private val session: NoiseSession, private val socket: RawSocket) {
    suspend fun request(payload: ByteArray): ByteArray {
        val encrypted = session.sendKey.encrypt(payload)
        socket.send(encrypted)
        val response = socket.receive()
        return session.recvKey.decrypt(response)
    }
}
```

---

## 4. Server Implementation (Rust, snow crate)

```rust
// server/Cargo.toml
// [dependencies]
// snow = "0.10"
// x25519-dalek = "2"
// tokio = { version = "1", features = ["full"] }

use snow::{Builder, TransportState};
use x25519_dalek::{StaticSecret, PublicKey};
use std::sync::Arc;

// ── State ──
struct NoiseState {
    sk_server: StaticSecret,
    pk_server: PublicKey,
    db: Arc<Mutex<Connection>>,
}

// ── Handshake handler ──
fn handle_noise_handshake(
    state: &NoiseState,
    stream: &mut TcpStream,
    prologue: &[u8],  // app_key from client
) -> Result<TransportState> {
    // Server's static keypair
    let builder = Builder::new(
        "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap(),
    )
    .prologue(prologue)
    .local_private_key(&state.sk_server.to_bytes());

    let mut handshake = builder.build_responder()?;

    // Receive Message 1
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf)?;
    handshake.read_message(&buf[..n], &mut [] )?;

    // Extract client's static key from handshake state
    let pk_dev = handshake.get_remote_static().unwrap();
    let pk_app = prologue;  // prologue = app key hash

    // Verify device is registered and not banned
    let db = state.db.lock().unwrap();
    let is_valid: bool = db.query_row(
        "SELECT banned_at FROM devices WHERE pk_dev = ?",
        params![pk_dev], |row| {
            let banned: Option<i64> = row.get(0)?;
            Ok(banned.is_none())
        }
    ).unwrap_or(false);
    drop(db);

    if !is_valid {
        return Err(anyhow!("device not found or banned"));
    }

    // Send Message 2
    let mut msg2 = [0u8; 1024];
    let len = handshake.write_message(&[], &mut msg2)?;
    stream.write_all(&msg2[..len])?;

    // Transition to transport mode
    let transport = handshake.into_transport_mode()?;
    Ok(transport)
}

// ── Application data handler ──
async fn handle_encrypted_connection(
    mut transport: TransportState,
    mut stream: TcpStream,
    app: Arc<App>,
) {
    loop {
        let mut buf = [0u8; 65536];
        let n = stream.read(&mut buf).await.unwrap();

        // Decrypt request (Noise transport mode)
        let mut plaintext = vec![0u8; n - 16];  // AEAD overhead
        transport.read_message(&buf[..n], &mut plaintext).unwrap();

        // Parse and route
        let req: Request = serde_json::from_slice(&plaintext).unwrap();
        let res = app.handle(req).await;

        // Encrypt and send response
        let mut encrypted = vec![0u8; res.len() + 16];
        let len = transport.write_message(&res, &mut encrypted).unwrap();
        stream.write_all(&encrypted[..len]).await.unwrap();
    }
}
```

---

## 5. Protocol Wire Format

```
TCP connection to server:9443 (not HTTPS — raw Noise over TLS-like port)

Message 1 (client → server):
  ┌──────────┬────────────────┬──────────────────────────────┐
  │ Length   │ Prologue       │ Noise IK Message 1           │
  │ (2 bytes)│ (32 bytes)     │ (depends on DH + cipher)     │
  ├──────────┼────────────────┼──────────────────────────────┤
  │ uint16 BE│ app_key (SHA-256│ client_ephemeral_pk ||       │
  │          │ of signing cert)│ encrypted(pk_dev) || tag     │
  └──────────┴────────────────┴──────────────────────────────┘
  Total: ~2 + 32 + 32 + 48 + 16 = ~130 bytes

Message 2 (server → client):
  ┌──────────┬──────────────────────────────┐
  │ Length   │ Noise IK Message 2           │
  │ (2 bytes)│                              │
  ├──────────┼──────────────────────────────┤
  │ uint16 BE│ server_ephemeral_pk ||       │
  │          │ encrypted(empty) || tag      │
  └──────────┴──────────────────────────────┘
  Total: ~2 + 32 + 16 + 16 = ~66 bytes

Encrypted data (bidirectional):
  ┌──────────┬────────────────┬──────────────┐
  │ Length   │ AEAD ciphertext│ Nonce (implicit)│
  │ (2 bytes)│ (plaintext + 16│ counter from    │
  │          │  byte tag)     │ transport state │
  └──────────┴────────────────┴──────────────┘
  Nonce is implicit — both sides track counter. No wire overhead.
```

---

## 6. Deployment

### 6.1 Server listens on a separate port

```
public API:  port 3000 (axum, REST/JSON — for app <-> server)
noise port:  port 9443 (raw TCP, Noise handshake — for transport setup)
```

The Noise port only does handshake + encrypted relay. After Noise transport is established, the client sends encrypted JSON requests which the server decrypts, processes via the same axum handlers, encrypts responses, and sends back.

### 6.2 Alternatives to separate port

If running two TCP listeners is inconvenient, Noise can tunnel over HTTP/2:

```
Option A: Raw TCP on 9443 (simpler)
Option B: Noise over WebSocket on /noise (no separate port, but WS overhead)
Option C: Noise over HTTP/2 stream (complex, not worth it)
```

Recommendation: **Option A** — separate raw TCP port. Simpler, lower overhead, no HTTP framing.

### 6.3 Android raw socket

Android supports raw TCP sockets. Use `java.net.Socket` or Kotlin coroutines with `java.nio.channels.AsynchronousSocketChannel`. No special permissions needed.

```kotlin
// Android: connect to Noise port
suspend fun connect(host: String, port: Int = 9443): NoiseSession {
    val socket = AsynchronousSocketChannel.open()
    socket.connect(InetSocketAddress(host, port)).await()
    return NoiseHandshake(appKey, deviceKey, serverKey).handshake(RawSocket(socket))
}
```

---

## 7. App Key Binding

### 7.1 How App Key Works

```
At compile time:
  - APK is built and signed with the app's signing certificate
  - Gradle task extracts SHA-256 of the signing cert
  - Injected as BuildConfig.APP_KEY_HASH

At runtime:
  - Client sends app_key as prologue in Noise handshake
  - Server includes prologue in all handshake hash computations
  - Any tampering with APK → different signing cert → different app_key → handshake fails
  - Server maintains allowlist: {accepted_app_keys} per community
```

### 7.2 Handling Build Variants

```gradle
// app/build.gradle.kts
android {
    signingConfigs {
        create("dev") {
            keyAlias = "pixheal-dev"
            keyPassword = "..."
            storeFile = file("dev.keystore")
        }
        create("release") {
            keyAlias = "pixheal"
            keyPassword = "..."
            storeFile = file("release.keystore")
        }
    }

    buildTypes {
        debug {
            signingConfig = signingConfigs.getByName("dev")
        }
        release {
            signingConfig = signingConfigs.getByName("release")
        }
    }
}

// BuildConfig.APP_KEY_HASH
// dev:     a1b2c3d4e5f6...
// release: f6e5d4c3b2a1...
```

Server stores both hashes — allows dev and release APKs to connect.

### 7.3 What App Key Prevents

| Attack | Stopped? |
|---|---|
| Attacker downloads official APK from Play Store, extracts code | ✓ Still has original signing cert — app_key matches |
| Attacker modifies APK, repackages with different cert | ✗ New signing cert → new app_key → server rejects |
| Attacker runs modified version of PixHeal | ✓ App key doesn't match — device can't authenticate |
| Attacker builds own client from source | ✓ Uses their own signing cert — server has no matching app_key |
| Attacker reverse-engineers protocol, calls endpoints directly | ⚠️ Server must also enforce rate limiting + ban suspicious patterns |

**Limitation**: App key proves the APK is authentic, but doesn't prove the user is legitimate. Every legitimate PixHeal user has the same app key. It's a network-level gate, not a user-level one.

---

## 8. Migrating to Noise from HTTPS

### Phase 1: Hybrid (both ports active)

```
Port 3000 (HTTP/JSON):  existing API (register, post, feed)
Port 9443 (Noise/TCP):  new transport (same API handlers, just encrypted)
```

Server runs both listeners. Android app can fall back to HTTPS if Noise handshake fails.

### Phase 2: Noise-only (HTTP port disabled)

```
Port 9443 (Noise/TCP): all traffic
Port 3000:             disabled or admin API only
```

---

## 9. Cargo Workspace Structure

```
pixheal-server/
├── Cargo.toml              # [workspace]
│   └── members = ["server", "admin-tui"]
├── server/
│   ├── Cargo.toml
│   ├── src/
│   │   ├── main.rs         # axum + noise listeners
│   │   ├── noise.rs        # Noise IK handshake handler
│   │   ├── routes.rs       # register, post, feed handlers
│   │   ├── admin.rs        # localhost admin API
│   │   └── db.rs           # SQLite queries
│   └── migrations/         # SQL schema
├── admin-tui/
│   ├── Cargo.toml
│   └── src/main.rs         # ratatui dashboard
└── shared/
    ├── Cargo.toml
    └── src/lib.rs          # shared types, crypto helpers
```

---

## 10. Key References

| Resource | URL |
|---|---|
| Noise Protocol Framework | https://noiseprotocol.org/noise.html |
| Noise IK specification | https://noiseprotocol.org/noise.html#interactive-patterns |
| noise-kotlin (Android) | https://github.com/sander/noise-kotlin |
| snow (Rust Noise implementation) | https://github.com/mcginty/snow |
| X25519 RFC 7748 | https://datatracker.ietf.org/doc/html/rfc7748 |
| ChaChaPoly RFC 8439 | https://datatracker.ietf.org/doc/html/rfc8439 |
| BLAKE2s RFC 7693 | https://datatracker.ietf.org/doc/html/rfc7693 |
| AndroidKeyStore | https://developer.android.com/training/articles/keystore |

---

*Document version 1.0 — 2026-07-23*
*References: Noise Protocol Framework Rev 34, noise-kotlin, snow crate*
