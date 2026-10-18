#!/usr/bin/env bash
# Root helper that installs binaries staged in /tmp by GitHub Actions and
# restarts the service. Invoked over SSH as: sudo -n /usr/local/sbin/freesky-deploy
#
# Staged by the workflow:
#   /tmp/freesky-server     (required)
#   /tmp/admin-tui          (optional — installed when present)
#   /tmp/freesky-admin.sh   (optional — operator wrapper)
#   /tmp/freesky-deploy.sh  (optional — updates this helper)
#
# Install this file to /usr/local/sbin/freesky-deploy (root:root, 0755).
set -euo pipefail

if [ ! -f /tmp/freesky-server ]; then
  echo "freesky-deploy: /tmp/freesky-server not found" >&2
  exit 1
fi

install -m 755 -o root -g root /tmp/freesky-server /usr/local/bin/freesky-server
rm -f /tmp/freesky-server

if [ -f /tmp/admin-tui ]; then
  install -m 755 -o root -g root /tmp/admin-tui /usr/local/bin/admin-tui
  rm -f /tmp/admin-tui
  echo "freesky-deploy: installed admin-tui"
fi

if [ -f /tmp/freesky-admin.sh ]; then
  install -m 755 -o root -g root /tmp/freesky-admin.sh /usr/local/bin/freesky-admin
  rm -f /tmp/freesky-admin.sh
  echo "freesky-deploy: installed freesky-admin wrapper"
fi

# Self-update. Write a new file and rename it into place instead of installing
# over this script: `install` truncates the destination, and bash is still
# reading this file as it executes, so an in-place overwrite can make the
# running helper execute garbage. rename(2) is atomic and leaves the running
# copy on the old inode.
if [ -f /tmp/freesky-deploy.sh ]; then
  install -m 755 -o root -g root /tmp/freesky-deploy.sh /usr/local/sbin/.freesky-deploy.new
  mv -f /usr/local/sbin/.freesky-deploy.new /usr/local/sbin/freesky-deploy
  rm -f /tmp/freesky-deploy.sh
  echo "freesky-deploy: updated the deploy helper"
fi

systemctl restart freesky-server
systemctl is-active freesky-server
