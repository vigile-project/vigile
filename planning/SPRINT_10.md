# SPRINT 10 — Phases 4-7 : USB, AppArmor, SELinux, réseau

> **Statut** : **Terminé** (phases 4-7) — 2026-08-23
> **Périmètre** : backends USBGuard (ph.4), AppArmor (ph.5), SELinux (ph.6), nftables (ph.7)
> **Pré-requis** : M0..M8 ✓ (MVP complet + packaging).

## Objectif

Créer les quatre backends restants avec types, parseurs, générateurs
et tests — chacun suivant le même pattern que le backend fapolicyd.

## Ordre de travail

| Phase | Backend | Crate | État |
|---|---|---|---|
| 4 | USBGuard | `vigile-backend-usbguard` : types USB (vendor/product/serial), parseur lsusb, générateur de règles (allow/deny/essential-peripheral avec HID), approbations (serial/device-id/port) | ✅ 4 tests |
| 5 | AppArmor | `vigile-backend-apparmor` : types de profils (complain/enforce, règles file/network/capability/deny), générateur de texte AppArmor, parseur aa-status --json | ✅ 5 tests |
| 6 | SELinux | `vigile-backend-selinux` : SecurityContext (4 champs), parseur AVC (permissions, scontext, tcontext, tclass, permissive), agrégation par paire de contextes, générateur de module stub (jamais de politique permissive auto) | ✅ 7 tests |
| 7 | nftables | `vigile-backend-nftables` : WorkloadId (cgroup v2 path → systemd unit), types de règles réseau (protocol/destination/action), générateur de ruleset nftables (meta cgroup match), config par défaut en mode accept (phase 7 = étude d'abord), listage des workloads système | ✅ 6 tests |
