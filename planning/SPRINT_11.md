# SPRINT 11 — Phases 8-9 + consolidation documentation

> **Statut** : **Terminé** — 2026-08-23
> **Périmètre** : Phase 8 (élévation contrôlée), Phase 9 (NixOS), consolidation docs.

| Issue | Objet | État |
|---|---|---|
| Phase 8 | `elevation.rs` : 5 actions typées (PackageInstall, ServiceRestart, FileWrite, FileRead, PredefinedCommand), validation (métacaractères shell, chemins absolus, justification obligatoire), grants avec expiration locale (SEC-303), plafond dur 4h, one-use | ✅ 10 tests |
| Phase 9 | `packaging/nix/vigile-module.nix` : module NixOS complet (options, utilisateur, unités systemd durcies identiques au RPM, avertissement fapolicyd indisponible) ; `flake.nix` : flake avec module + package Rust | ✅ |
| Docs | `README.md` réécrit : tableau de statut par phase, diagramme d'architecture, propriétés de sécurité, quick start, arborescence | ✅ |
