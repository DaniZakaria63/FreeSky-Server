# Admin TUI over SSH (the simple path)

How to open the admin dashboard. No Cloudflare, no service tokens, no tunnel
config, no credentials to type.

```
your laptop ──ssh──▶ VPS ──▶ admin-tui ──HTTP 127.0.0.1:3001──▶ freesky-server
```

## Why this is the default

The admin API is bound to `127.0.0.1:3001`, so it is only reachable from the
machine itself. SSH is therefore the whole access-control story: if you can log
into the VPS, you can administer the server, and if you cannot, you cannot.

It also removes a real hole. The admin API used to be published as
`admin-freesky.<domain>` through the tunnel, with **no** Zero Trust Access
application in front of it — so the only credential was the `X-App-Key` header,
which is the APK signing key. That value ships inside the APK and can be read
by anyone with `apksigner verify --print-certs`, which meant the admin API was
on the public internet guarded by a public string. It is no longer published
(see `deploy/cloudflared/config.yml`).

## One-time setup

The deploy workflow installs everything on the VPS
(`.github/workflows/deploy.yml` → `scripts/freesky-deploy.sh`):

| Path | What it is |
|---|---|
| `/usr/local/bin/admin-tui` | the dashboard binary |
| `/usr/local/bin/freesky-admin` | wrapper: reads the app key from `/etc/freesky.env` and runs the TUI |

To install them by hand instead:

```bash
cargo build --release -p freesky-admin-tui
scp target/release/admin-tui scripts/freesky-admin.sh <vps>:/tmp/
ssh <vps> 'sudo install -m755 -o root -g root /tmp/admin-tui /usr/local/bin/admin-tui && \
           sudo install -m755 -o root -g root /tmp/freesky-admin.sh /usr/local/bin/freesky-admin'
```

## Using it

```bash
ssh -t ubuntu@admin.dream-team.works freesky-admin
```

That is the entire login. Add a local alias if you like:

```bash
# ~/.bashrc
alias freesky-admin='ssh -t ubuntu@admin.dream-team.works freesky-admin'
```

Then `freesky-admin` opens the dashboard.

### First run on a fresh server

Press **`3`** (Key rotate) once. That creates the community group key; until it
exists every device registration fails with `no group key exists`. The
Community Key panel shows `[ok] Key exists` afterwards.

## Why `X-App-Key` is still sent

The wrapper reads `TRUSTED_APK_KEY` out of `/etc/freesky.env` with
`sudo -n` and passes it to the TUI, so you never have to know or type it.

It stays in the request on purpose: it is what stops *other* local processes
and non-sudo users on the VPS from banning users or rotating the group key.
Reading it needs passwordless sudo, so the set of people who can run
`freesky-admin` is the same set who could read the database anyway. The
credential is not security theatre — it is just no longer your problem.

There is no switch to turn it off, and no remote path that would replace it:
the admin API is unreachable from outside the machine by design, and beyond
this header the origin has nothing it could check. Anything on the box that can
read the key is already able to read the database.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `freesky-admin: /usr/local/bin/admin-tui not found` | the TUI has not been deployed; run the deploy workflow or the manual `scp` above |
| `freesky-admin: could not read TRUSTED_APK_KEY from /etc/freesky.env` | no passwordless sudo for the login you are using (`sudo -n true` should succeed), or the env file has no `TRUSTED_APK_KEY` |
| TUI shows `● disconnected` | `freesky-server` is not running: `systemctl status freesky-server` |
| TUI shows `[err] invalid app key (HTTP 401)` | `TRUSTED_APK_KEY` in `/etc/freesky.env` changed after the server started — restart the service |
| Dashboard empty / garbled | the terminal is too small; resize or the pty has no size (use `ssh -t`) |
