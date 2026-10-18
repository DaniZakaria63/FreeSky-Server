#!/usr/bin/env bash
# Open the Freesky admin TUI against the admin API running on this machine.
#
# Install to /usr/local/bin/freesky-admin on the VPS, then:
#
#     ssh -t ubuntu@<vps> freesky-admin
#
# The admin API listens on 127.0.0.1:3001 and requires an `X-App-Key` header.
# That value is already on this box in /etc/freesky.env, so there is nothing to
# remember or type — this wrapper reads it and hands it to the TUI.
#
# The key is read with `sudo -n`, so only users with passwordless sudo can run
# this. That is deliberate: the header is what stops any *other* local process
# from banning users or rotating the group key, so it stays even though you
# never have to see it.
#
# Overridable for testing: FREESKY_ENV_FILE, FREESKY_ADMIN_API_BASE,
# FREESKY_ADMIN_TUI.
set -euo pipefail

env_file="${FREESKY_ENV_FILE:-/etc/freesky.env}"
api_base="${FREESKY_ADMIN_API_BASE:-http://127.0.0.1:3001}"
tui="${FREESKY_ADMIN_TUI:-/usr/local/bin/admin-tui}"

if [ ! -x "$tui" ]; then
  echo "freesky-admin: $tui not found or not executable" >&2
  echo "  deploy the TUI first: .github/workflows/deploy.yml builds and installs it" >&2
  exit 1
fi

key="$(sudo -n sed -n 's/^TRUSTED_APK_KEY=//p' "$env_file" 2>/dev/null | head -1)"
if [ -z "$key" ]; then
  echo "freesky-admin: could not read TRUSTED_APK_KEY from $env_file" >&2
  echo "  needs passwordless sudo — check with: sudo -n true" >&2
  exit 1
fi

exec "$tui" --api-base "$api_base" --app-key "$key" "$@"
