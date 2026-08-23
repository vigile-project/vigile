#!/usr/bin/env bash
# ISS-005 — Arrête la VM de laboratoire : d'abord proprement (shutdown SSH),
# puis de force si nécessaire. Ne touche ni l'overlay ni l'image de base.
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE="$BASE_DIR/.state"
PIDFILE="$STATE/vm.pid"

if [ ! -f "$PIDFILE" ]; then
  echo "Aucune VM connue"
  exit 0
fi
PID="$(cat "$PIDFILE")"
if ! kill -0 "$PID" 2>/dev/null; then
  rm -f "$PIDFILE"
  echo "VM déjà arrêtée"
  exit 0
fi

"$BASE_DIR/bin/vm-ssh.sh" "sudo shutdown -h now" >/dev/null 2>&1 || true
for _ in $(seq 1 15); do
  if ! kill -0 "$PID" 2>/dev/null; then
    rm -f "$PIDFILE"
    echo "OK : VM arrêtée proprement"
    exit 0
  fi
  sleep 2
done

kill "$PID" 2>/dev/null || true
sleep 2
kill -9 "$PID" 2>/dev/null || true
rm -f "$PIDFILE"
echo "VM arrêtée (forcement après expiration du délai)"
