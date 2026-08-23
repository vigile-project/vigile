#!/usr/bin/env bash
# ISS-016 — Exécute les tests d'intégration PostgreSQL de vigile-store
# contre un PostgreSQL 17 rootless (podman), puis nettoie.
set -euo pipefail

NAME=vigile-test-pg
PORT="${VIGILE_PG_PORT:-54329}"

cd "$(dirname "$0")/.."

podman rm -f "$NAME" >/dev/null 2>&1 || true
podman run -d --name "$NAME" \
  -e POSTGRES_PASSWORD=vigile -e POSTGRES_DB=vigile \
  -p "127.0.0.1:${PORT}:5432" \
  docker.io/library/postgres:17-alpine >/dev/null
trap 'podman rm -f "$NAME" >/dev/null 2>&1 || true' EXIT

echo "Attente de PostgreSQL…"
for _ in $(seq 1 60); do
  if podman exec "$NAME" pg_isready -U postgres -d vigile >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

cd rust
VIGILE_PG_CONN="host=127.0.0.1 port=${PORT} user=postgres password=vigile dbname=vigile" \
  PATH="$HOME/.cargo/bin:$PATH" cargo test -p vigile-store -- --ignored --nocapture
