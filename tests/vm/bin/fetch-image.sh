#!/usr/bin/env bash
# ISS-005 — Télécharge l'image Fedora Cloud 44 de base et vérifie :
#   1. la signature OpenPGP du fichier CHECKSUM (si une clé Fedora est
#      présente localement — hôte Fedora : distribution-keys) ;
#   2. l'empreinte SHA-256 de l'image contre ce CHECKSUM signé.
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGES="$BASE_DIR/.state/images"
URL_BASE="${VIGILE_IMAGE_URL:-https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images}"
IMAGE="Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2"
CHECKSUM="Fedora-Cloud-44-1.7-x86_64-CHECKSUM"

mkdir -p "$IMAGES"
[ -s "$IMAGES/$IMAGE" ] || curl -fL --retry 3 -o "$IMAGES/$IMAGE" "$URL_BASE/$IMAGE"
[ -s "$IMAGES/$CHECKSUM" ] || curl -fL --retry 3 -o "$IMAGES/$CHECKSUM" "$URL_BASE/$CHECKSUM"

# 1. Vérification OpenPGP du CHECKSUM (best effort : essayer chaque clé
#    Fedora locale jusqu'à vérification ; échec bloquant si des clés
#    existent mais qu'aucune ne vérifie — jamais l'inverse).
TMP_HOME="$(mktemp -d)"
trap 'rm -rf "$TMP_HOME"' EXIT
verified=""
for k in $(ls -1 /usr/share/distribution-keys/RPM-GPG-KEY-*fedora* 2>/dev/null \
                | sort -rV; \
           ls -1 /etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-*-primary 2>/dev/null \
                | sort -rV); do
  [ -f "$k" ] || continue
  gpg --homedir "$TMP_HOME" --quiet --import "$k" 2>/dev/null || true
done
if gpg --homedir "$TMP_HOME" --verify "$IMAGES/$CHECKSUM" >/dev/null 2>&1; then
  echo "OK : CHECKSUM signé (clés Fedora locales)"
else
  echo "ÉCHEC : signature du CHECKSUM invalide (aucune clé Fedora locale ne la vérifie)" >&2
  exit 1
fi

# 2. SHA-256 : la ligne utile est « SHA256 (<nom>) = <hex> » ; ignorer les
#    lignes de commentaire « # <nom> : <taille> » (leçon du 2026-08-21).
expected="$(grep -E "^SHA256 \($IMAGE\) = [0-9a-f]{64}$" "$IMAGES/$CHECKSUM" \
  | grep -oE '[0-9a-f]{64}' | head -1 || true)"
if [ -z "$expected" ]; then
  echo "ÉCHEC : image absente du CHECKSUM officiel" >&2
  exit 1
fi
actual="$(sha256sum "$IMAGES/$IMAGE" | cut -d' ' -f1)"
if [ "$expected" != "$actual" ]; then
  echo "ÉCHEC : empreinte invalide (attendu $expected, obtenu $actual)" >&2
  exit 1
fi
echo "OK : $IMAGE (sha256 ${actual:0:16}…)"
