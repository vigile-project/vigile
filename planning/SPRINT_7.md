# SPRINT 7 — fapolicyd en mode audit (M5, phase 2)

> **Statut** : **Terminé** (M5 complet) — 2026-08-23
> **Périmètre** : issues ISS-035 à ISS-037 (`planning/BACKLOG.md` §M5)
> **Pré-requis** : M1..M4 ✓, M6 ✓ (exécuteur transactionnel + systemd
> durci) ; compilateur validé par `fapolicyd-cli --check-rules`.

## Objectif

**Branche tout ensemble** : le compilateur produit des règles fapolicyd,
l'exécuteur les valide nativement et les déploie, fapolicyd les exécute
en mode `_audit` (aucun blocage — observation uniquement), et l'agent
collecte les refus pour les corréler avec l'inventaire. C'est la
première fois que la chaîne complète produit de la valeur observable.

## Ordre de travail et avancement

| Issue | Objet | État |
|---|---|---|
| ISS-035 | `vigile-backend-fapolicyd` : `check_rules()` et `check_rules_dir()` appellent **fapolicyd-cli --check-rules** (propagation correcte de CliNotFound) ; `deploy_rules()` copie active→/etc/fapolicyd/rules.d/vigile/ + `reload_rules()` via `fapolicyd-cli --reload-rules` ; exécuteur : `validate()` câblé au vrai backend (skip gracieux si fapolicyd absent sur dev) + `deploy()` pour le post-commit | ✅ fait le 2026-08-23 — **validé dans la VM Fedora 44 : "Rules file is valid (1 rules)"** |
| ISS-036 | `parse_denial()` : parsing des enregistrements journald JSON fapolicyd (extraction exe, path, decision, ftype depuis MESSAGE) ; `correlate_denial()` : joint avec l'inventaire des exécutables (path→sha256) ; parsing hostile-safe (JSON invalide, champs manquants → None) | ✅ fait le 2026-08-23 — 5 tests |
| ISS-037 | Apprentissage assisté : recommandations de règles à partir des refus (jamais d'activation automatique) | reporté (P1) |

## Règles du sprint

1. **Mode audit uniquement** : toutes les règles déployées portent le
   suffixe `_audit` (deny_audit, allow_audit) — aucun blocage réel.
2. **fapolicyd n'est jamais démarré par Vigil** au MVP : le mode audit
   suppose que l'administrateur a activé fapolicyd en mode permissif
   (documentation à produire).
3. La validation VM est le critère de sortie : pipeline complet dans
   la VM Fedora 44 avec fapolicyd installé (déjà fait au smoke test).

## Critères de sortie

1. Dans la VM : une politique compilée est déployée via l'exécuteur,
   validée par `fapolicyd-cli --check-rules`, et visible dans
   `/etc/fapolicyd/rules.d/`.
2. Les refus d'exécution sont collectés depuis journald et corrélés
   avec l'inventaire.
3. Revue humaine avant M7 (phase 3 : enforcement).
