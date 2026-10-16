# Admin TUI over Cloudflare Tunnel (Zero Trust)

How an admin runs the TUI **on their own computer** and reaches the server's
admin API through a Cloudflare Tunnel protected by Zero Trust Access.

```
┌────────────────┐        ┌──────────────┐        ┌───────────────────┐
│  admin-tui     │ HTTPS  │  Cloudflare  │  out   │  VPS              │
│  (admin's      │───────▶│  edge +      │◀───────│  cloudflared      │
│   computer)    │        │  Zero Trust  │ tunnel │      │            │
└────────────────┘        └──────────────┘        │      ▼            │
   X-App-Key                                       │  127.0.0.1:3001   │
   CF-Access-Client-Id                             │  (admin API)      │
   CF-Access-Client-Secret                         └───────────────────┘
```

The admin API stays bound to `127.0.0.1:3001` on the VPS — the tunnel is the
only way in, and every request must present:

- `X-App-Key` — the trusted APK signing key SHA-1 (same value as
  `TRUSTED_APK_KEY` on the server), and
- `CF-Access-Client-Id` / `CF-Access-Client-Secret` — a Zero Trust service
  token, when Access protects the hostname.

> The admin API refuses to serve if `TRUSTED_APK_KEY` is empty on the server
> (HTTP 503) — there is no "auth disabled" mode.

## 1. Server side (VPS)

### Install cloudflared

```bash
# Debian/Ubuntu
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
  | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" \
  | sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt update && sudo apt install cloudflared
```

### Create the tunnel

```bash
cloudflared tunnel login          # opens a browser once, picks the zone
cloudflared tunnel create freesky-admin
cloudflared tunnel route dns freesky-admin admin.example.com
```

### Configure and run it

Copy [`deploy/cloudflared/config.yml`](../deploy/cloudflared/config.yml) to
`/etc/cloudflared/config.yml` and set the tunnel ID + hostname. Then:

```bash
sudo cloudflared service install
sudo systemctl enable --now cloudflared
```

The tunnel points `admin.example.com` at `http://127.0.0.1:3001`, where the
server listens. No firewall change, no exposed port.

### Protect it with Zero Trust Access

In the Cloudflare dashboard → **Zero Trust → Access → Applications**:

1. **Add an application** → *Self-hosted*, hostname `admin.example.com`.
2. **Policy**: allow the admins (e.g. emails, or a service token — see below).
3. **Service token** (required for the TUI, which cannot do a browser
   login): **Access → Service Auth → Service Tokens → Create**. Note the
   *Client ID* and *Client Secret* — the TUI sends them on every request.
4. In the application policy, allow the service token you just created.

> Alternative: skip Access entirely and rely on `X-App-Key` alone. Not
> recommended for a public hostname — use Access.

## 2. Client side (admin's computer)

### Install the TUI globally

```bash
cargo install --path admin-tui        # installs `admin-tui` into ~/.cargo/bin
```

or grab a release build of `admin-tui` and put it somewhere on `PATH`.

### Configure and run

```bash
export ADMIN_API_BASE="https://admin.example.com"
export APP_KEY="<40-hex SHA-1 of the APK signing cert>"     # same as TRUSTED_APK_KEY
export CF_ACCESS_CLIENT_ID="<service token client id>"
export CF_ACCESS_CLIENT_SECRET="<service token client secret>"

admin-tui
```

CLI flags work too: `admin-tui --api-base https://admin.example.com --app-key <SHA1>`.

All environment variables:

| Variable | Required | Purpose |
|---|---|---|
| `APP_KEY` / `--app-key` | yes | `X-App-Key` header (SHA-1, colons optional) |
| `ADMIN_API_BASE` / `--api-base` | no | Admin API base URL (default `http://127.0.0.1:3001`) |
| `CF_ACCESS_CLIENT_ID` | with Access | Service token client ID |
| `CF_ACCESS_CLIENT_SECRET` | with Access | Service token client secret |

### Verify the tunnel first (optional)

```bash
curl -sS \
  -H "CF-Access-Client-Id: $CF_ACCESS_CLIENT_ID" \
  -H "CF-Access-Client-Secret: $CF_ACCESS_CLIENT_SECRET" \
  -H "X-App-Key: $APP_KEY" \
  https://admin.example.com/admin/health
# → {"message":"success","data":{"ok":true}}
```

## Troubleshooting

| Symptom in TUI | Cause |
|---|---|
| `HTTP 302 ... blocked by Cloudflare Access?` | Service token missing/wrong, or the Access policy does not include the token |
| `HTTP 403 ... check the service-token policy` | Token valid but not allowed by the application's policy |
| `invalid app key (HTTP 401)` | `APP_KEY` does not match the server's `TRUSTED_APK_KEY` |
| `admin API disabled: TRUSTED_APK_KEY not configured (HTTP 503)` | Server has no `TRUSTED_APK_KEY` set |
| `cannot reach admin API at ...` | cloudflared not running, wrong hostname, or no DNS route |

## Security notes

- Keep the admin API on `127.0.0.1:3001`. Only cloudflared (on the VPS)
  should reach it; do not publish port 3001 to the internet.
- The service token is a bearer credential — store it in your shell env or a
  password manager, not in the repo. Rotate it from the dashboard if leaked.
- Every admin action (ban, unban, resolve, key rotate) is logged server-side
  via `tracing`; watch the server logs if in doubt.
