#!/usr/bin/env bash
# ISS-005 — Attend que la VM réponde en SSH (premier démarrage :
# cloud-init + génération des clés d'hôte peuvent prendre 1 à 3 minutes).
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for i in $(seq 1 60); do
  if "$BASE_DIR/bin/vm-ssh.sh" -o BatchMode=yes true >/dev/null 2>&1; then
    echo "OK : SSH prêt après environ $((i * 10)) s"
    exit 0
  fi
  sleep 10
done

echo "ÉCHEC : SSH inaccessible après 600 s — examiner .state/console.log" >&2
exit 1
