#!/usr/bin/env bash
set -euo pipefail

# Run ONCE on fresh VPS to prep Freesky server

echo "==> Creating freesky user..."
id -u freesky 2>/dev/null || useradd -r -s /sbin/nologin -d /var/lib/freesky freesky

echo "==> Creating directories..."
mkdir -p /var/lib/freesky
chown freesky:freesky /var/lib/freesky

echo "==> Installing systemd service..."
cp freesky-server.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable freesky-server

echo "==> Installing admin helpers..."
# freesky-deploy: root helper used by GitHub Actions to install new binaries.
# freesky-admin:  operator entry point — reads TRUSTED_APK_KEY from
#                 /etc/freesky.env and opens the TUI (docs/admin-tui-ssh.md).
install -m 755 -o root -g root scripts/freesky-deploy.sh /usr/local/sbin/freesky-deploy
install -m 755 -o root -g root scripts/freesky-admin.sh /usr/local/bin/freesky-admin
echo "    (admin-tui itself is shipped by .github/workflows/deploy.yml)"

echo "==> Creating .env template..."
if [ ! -f /etc/freesky.env ]; then
  cat > /etc/freesky.env << EOF
TURSO_URL=file:///var/lib/freesky/community.db
TRUSTED_APK_KEY=CHANGE_ME
DEBUG=false
EOF
  chmod 600 /etc/freesky.env
fi

echo "==> Done. Edit /etc/freesky.env, then: systemctl start freesky-server"
