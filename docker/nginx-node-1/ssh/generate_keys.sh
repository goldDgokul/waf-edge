#!/bin/sh
# Regenerate the dev-only keypair for the 0A.13 SSH activation rig.
#
# The PRIVATE key (id_ed25519) is gitignored and must never be committed: it is
# mounted read-only into waf-api so the API can authenticate to the dev node.
# The PUBLIC key becomes authorized_keys and IS committed (a public key is not a
# secret) so the node image builds reproducibly for anyone who clones the repo.
#
# WARNING: never reuse this keypair (or its authorized_keys) on any non-dev node.
# It is a throwaway dev credential; production nodes get operator-provisioned keys.
#
# Usage (from the repo root):
#   sh docker/nginx-node-1/ssh/generate_keys.sh
# then rebuild the node image so the new public key is baked in:
#   docker compose build nginx-node-1 && docker compose up -d --no-deps nginx-node-1

set -e
cd "$(dirname "$0")"

ssh-keygen -t ed25519 -N "" -f id_ed25519 -C "waf-dev-0A13"
cp id_ed25519.pub authorized_keys
echo "Generated id_ed25519 (private, gitignored) and authorized_keys (public, committed)."
