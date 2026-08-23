# SPRINT 9 — Packaging et release (M8)

> **Statut** : **Terminé** (M8 complet) — 2026-08-23
> **Périmètre** : ISS-048..051
> **Pré-requis** : M0..M7 ✓ (MVP complet, 205 tests verts).

## Objectif

Rendre Vigile **installable** : un RPM signé qui installe l'agent,
l'exécuteur, le serveur, les unités systemd durcies et le portail web
sur un système Fedora 44. Le kit de récupération permet de se sortir
d'un auto-blocage.

## Ordre de travail

| Issue | Objet | État |
|---|---|---|
| ISS-048 | `packaging/rpm/vigile.spec` : build release du workspace (cargo build --release), installation de 3 binaires + portail web + 2 unités systemd + script break-glass + documentation ; création de l'utilisateur vigile (sans shell, système) et du groupe vigile-exec ; scriptlets systemd pre/post/preun/postun ; scriptlets user/group pre/post | ✅ fait le 2026-08-23 |
| ISS-049 | Dépôt signé + métadonnées TUF | reporté (phase 10) |
| ISS-050 | SBOM + provenance + reproductibilité | reporté (phase 10) |
| ISS-051 | `packaging/recovery/vigile-breakglass` : script de récupération **contraint** (justification + ticket obligatoires, durée max 4h, journalisé, bascule en mode audit + restauration automatique planifiée, option --rollback-only) | ✅ fait le 2026-08-23 |

## Critères de sortie

1. `rpmbuild -ba vigile.spec` produit un RPM installable.
2. Installation en VM Fedora : `dnf install vigile-*.rpm` fonctionne.
3. `systemctl start vigile-agent` démarre (même si c'est un stub).
