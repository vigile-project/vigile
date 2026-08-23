#!/usr/bin/env bash
# Scénario « smoke » — s'exécute DANS la VM de laboratoire :
#   bin/vm-ssh.sh bash < scenarios/smoke.sh
#
# Rappel de sécurité labo : fapolicyd est INSTALLÉ mais JAMAIS démarré ni
# activé ici — uniquement sa validation hors ligne est exercée. Aucune
# politique bloquante ne doit résulter de ce scénario (§26 cahier des
# charges, phase 1).
set -euo pipefail

echo "== Vigile ISS-005 : smoke Fedora 44 =="
cat /etc/fedora-release
uname -r
echo "-- réseau --"
ip -brief address show | grep -v "^lo"
echo "-- fapolicyd : avant installation --"
rpm -q fapolicyd || echo "(non installé)"
echo "-- installation (sans activation) --"
sudo dnf -y -q install fapolicyd
rpm -q fapolicyd
sudo systemctl disable --now fapolicyd 2>/dev/null || true
systemctl is-active fapolicyd || true
echo "-- validation hors ligne des règles livrées --"
sudo fapolicyd-cli --check-rules 2>&1 | head -10 || true
echo "== SMOKE OK =="
