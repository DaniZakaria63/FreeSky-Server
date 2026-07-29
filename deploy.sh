#!/usr/bin/env bash
set -euo pipefail

VPS_HOST="${1:-}"
VPS_USER="${2:-root}"
SSH_PORT="${3:-15220}"

if [ -z "$VPS_HOST" ]; then
  echo "Usage: $0 <vps-host> [user] [port]" 2>&1
  exit 1
fi

BIN="target/release/freesky-server"

echo "==> Building release binary..."
cargo build --release -p freesky-server

echo "==> Copying binary to $VPS_HOST..."
rsync -avz --delete -e "ssh -p $SSH_PORT" "$BIN" "$VPS_USER@$VPS_HOST:/usr/local/bin/freesky-server"

echo "==> Restarting service..."
ssh -p $SSH_PORT "$VPS_USER@$VPS_HOST" systemctl restart freesky-server

echo "==> Done."
