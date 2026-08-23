#!/usr/bin/env bash
# ISS-005 — Construit l'ISO cloud-init NoCloud (volume « cidata ») à partir
# des gabarits cloud/ et d'une clé SSH jetable propre au laboratoire
# (sans phrase secrète : VM de test jetable, rien de sensible dedans).
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE="$BASE_DIR/.state"
CLOUD="$BASE_DIR/cloud"
KEY="$STATE/ssh/id_ed25519"

mkdir -p "$STATE/ssh"
if [ ! -f "$KEY" ]; then
  ssh-keygen -q -t ed25519 -N "" -C "vigile-vm-harness-jetable" -f "$KEY"
fi

PUB="$(cat "$KEY.pub")"
sed "s|__VIGILE_SSH_KEY__|$PUB|" "$CLOUD/user-data.tmpl" > "$STATE/user-data"
cp "$CLOUD/meta-data" "$STATE/meta-data"

genisoimage -quiet -output "$STATE/seed.iso" -volid cidata -joliet -rock \
  "$STATE/user-data" "$STATE/meta-data"
echo "OK : $STATE/seed.iso"
