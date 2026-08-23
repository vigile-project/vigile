# SPRINT 4 — Compilateur de politiques (M3)

> **Statut** : **Terminé** (M3 complet) — 2026-08-23
> **Périmètre** : issues ISS-023 à ISS-026 (`planning/BACKLOG.md` §M3)
> **Pré-requis** : M1 ✓, M2 validé par l'humain le 2026-08-22 ✓ ;
> capacités fapolicyd 2.0 cartographiées (spike ISS-008) ✓.

## Objectif

Le cœur produit : **compiler** une politique `policy/v0` validée en
artefacts fapolicyd déterministes, **refuser** ce qui se contredit,
**déclarer** ce qui n'est pas applicable (jamais l'ignorer), et
**simuler/diffuser** avant tout déploiement (SEC-802).

## Ordre de travail et avancement

| Issue | Objet | État |
|---|---|---|
| ISS-023 | `compiler.rs` + `model.rs` (types verrouillés au schéma par `deny_unknown_fields`) : règles fapolicyd 2.0 déterministes (5 formes de règles, préfixes `_audit` par défaut — doctrine phase 2), manifeste avec SHA-256 de chaque artefact, avertissements (granularité trust=1, trust.d différé au learning), `COMPILER_VERSION` dans le header des règles ET le manifeste ; entrées `trust.d` différées (schéma v0 sans chemins par hash — documenté en avertissement) | ✅ fait le 2026-08-23 — **règles validées par `fapolicyd-cli --check-rules` dans la VM (3 règles valides)** |
| ISS-024 | Table C1..C7 complète + C1 étendu (chemins non normalisés rejetés : relatifs, `..`, `//`) ; C6 testé en défense en profondeur (le schéma rejète d'abord, le compilateur re-vérifie — SEC-208+603) ; C7 : `custom` sans hash = erreur, `distribution` sans hash = accepté avec avertissement de granularité | ✅ fait le 2026-08-23 — 11 tests |
| ISS-025 | `non_applicable[]` avec backend + phase d'arrivée + raison pour filesystem/network/usb **présents dans la politique** ; `usb.decision=not-applicable` dans la source → PAS déclaré (rien à déclarer) ; chaque entrée porte sa raison et sa phase | ✅ fait le 2026-08-23 — 3 tests |
| ISS-026 | `simulate.rs` : parse les formes émises par le compilateur, **first-match** (sémantique fapolicyd), `SimResult` avec numéro de ligne de la règle ; diff récursif de politiques avec chemins en notation point et tableaux énumérés élément par élément (ajoutés/supprimés) | ✅ fait le 2026-08-23 — 5 tests (dont fuzz : tout événement → toujours une décision, jamais de panic) |
| (validation) | **Réussi le 2026-08-23** : `policy-workstation-firefox.v0.json` compilée (3 règles, mode enforce car `strategy: canary`) → copiée dans la VM → `fapolicyd-cli --check-rules` = **"Rules file is valid (3 rules)"** | ✅ |

## Règles du sprint

1. Le compilateur est **pur** : aucune E/S, aucun réseau, aucun temps
   wall-clock dans les sorties (déterminisme SEC-209 testé).
2. Mode audit-only **par défaut** en phase 2 : les décisions générées
   portent le suffixe `_audit` tant que le rollout n'est pas en
   enforcement — jamais de blocage généré directement (§26).
3. Toute limite du schéma v0 (ex. paquet sans chemins par fichier) se
   traduit en erreur ou avertissement explicite, jamais en silence.

## Critères de sortie

1. ✅ `examples/policy-workstation-firefox.v0.json` compile → 3 règles
   déterministes + manifeste → **`fapolicyd-cli --check-rules` = valid**
   dans la VM Fedora 44.
2. ✅ Table C1..C7 couverte par 11 tests négatifs.
3. ✅ Simulation : hash épinglé passe à travers interprète interdit ;
   inconnu → deny_audit ; stratégies enforce → deny sans suffixe.
4. ⏳ Revue humaine avant M4 (serveur HTTP) — **en attente**.
