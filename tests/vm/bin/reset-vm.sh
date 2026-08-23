#!/usr/bin/env bash
# ISS-005 — Réinitialise la VM de laboratoire à un état neuf
# (arrêt + suppression de l'overlay ; l'image de base est conservée).
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE="$BASE_DIR/.state"

"$BASE_DIR/bin/stop-vm.sh" >/dev/null 2>&1 || true
rm -f "$STATE/vigile-f44.qcow2" "$STATE/console.log" "$STATE/known_hosts"
echo "OK : VM réinitialisée (prochain run-vm.sh repartira d'un état neuf)"
