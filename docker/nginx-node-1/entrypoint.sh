#!/bin/sh
# 0A.13 dev rig entrypoint: start sshd, then run nginx via the stock entrypoint.
set -e

# Start the SSH daemon in the background. Key-only root login is configured in
# /etc/ssh/sshd_config (PermitRootLogin prohibit-password, PasswordAuthentication no).
/usr/sbin/sshd

# Hand off to nginx:alpine's own entrypoint, preserving its CMD
# (`nginx -g 'daemon off;'`), so nginx stays in the foreground as PID 1.
exec /docker-entrypoint.sh "$@"
