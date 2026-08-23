#!/usr/bin/env bash
# ISS-005 — SSH vers la VM de laboratoire (clé jetable, port 2222 local).
# Usage : vm-ssh.sh [commande…]  — sans commande : session interactive.
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE="$BASE_DIR/.state"
KEY="$STATE/ssh/id_ed25519"
PORT="${VIGILE_VM_SSH_PORT:-2222}"

exec ssh -i "$KEY" -p "$PORT" \
  -o UserKnownHostsFile="$STATE/known_hosts" \
  -o StrictHostKeyChecking=accept-new \
  -o ConnectTimeout=5 \
  vigile@127.0.0.1 "$@"
