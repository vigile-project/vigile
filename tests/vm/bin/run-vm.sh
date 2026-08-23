#!/usr/bin/env bash
# ISS-005 — Démarre la VM de laboratoire Vigile.
#
# QEMU en mode utilisateur : aucun privilège root, aucun démon libvirt,
# réseau SLIRP avec seul 22 redirigé vers 127.0.0.1:2222 (aucun port
# exposé sur le réseau local). L'image de base reste intacte (overlay
# qcow2 de 40 Go créé au-dessus).
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE="$BASE_DIR/.state"
IMAGE="$STATE/images/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2"
OVERLAY="$STATE/vigile-f44.qcow2"
SSH_PORT="${VIGILE_VM_SSH_PORT:-2222}"

[ -f "$IMAGE" ] || "$BASE_DIR/bin/fetch-image.sh"
[ -f "$STATE/seed.iso" ] || "$BASE_DIR/bin/mkseed.sh"

if [ -f "$STATE/vm.pid" ] && kill -0 "$(cat "$STATE/vm.pid")" 2>/dev/null; then
  echo "VM déjà démarrée (pid $(cat "$STATE/vm.pid"))"
  exit 0
fi

if [ ! -f "$OVERLAY" ]; then
  qemu-img create -f qcow2 -F qcow2 -b "$IMAGE" "$OVERLAY" 40G
fi

qemu-system-x86_64 \
  -machine q35 -accel kvm -cpu host -smp 4 -m 4096 \
  -drive file="$OVERLAY",format=qcow2,if=virtio \
  -cdrom "$STATE/seed.iso" \
  -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22" \
  -device virtio-net-pci,netdev=n0 \
  -display none -daemonize -pidfile "$STATE/vm.pid" \
  -serial "file:$STATE/console.log"

echo "VM démarrée (pid $(cat "$STATE/vm.pid")). Console : $STATE/console.log"
echo "Attendre SSH : $BASE_DIR/bin/wait-ssh.sh"
