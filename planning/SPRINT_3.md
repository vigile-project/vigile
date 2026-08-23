# SPRINT 3 — Inventaire applicatif (M2)

> **Statut** : En cours — ouvert le 2026-08-22
> **Périmètre** : issues ISS-017 à ISS-022 (`planning/BACKLOG.md` §M2)
> **Pré-requis** : M1 complet ✓ ; VM de laboratoire ✓ ; registre
> persistant ✓.

## Objectif

La première brique **côté agent** : savoir sur quoi on tourne (ISS-017),
ce qui est installé (ISS-018/019/020), ce qui se passe (ISS-021) et
comment le remonter sans saturer rien (ISS-022). Aucune politique, aucun
blocage — M2 est purement observation.

## Ordre de travail et avancement

| Issue | Objet | État |
|---|---|---|
| ISS-017 | `platform.rs` (os-release strict, familles par ID/ID_LIKE) + `capabilities.rs` (matrice embarquée 8 backends × 5 familles, sondes locales sous racine virtuelle, déclaré ∧ présent → effectif, famille inconnue = tout `unavailable` — ADR-0009) | ✅ fait le 2026-08-22 — 9 tests |
| ISS-018 | `packages.rs` : format de requête rpm (séparateur US pour éviter les collisions de tabulations), parseur pur (champs obligatoires nom+EVR, lignes malformées sautées jamais fatales), extraction du Key ID signataire, lanceur `rpm -qa` fin | ✅ fait le 2026-08-22 — 4 tests |
| ISS-019 | Exécutables hors paquets : parcours des chemins standards + `$HOME`, filtre bit exécutable + non-symlink, SHA-256 (`sha2` à adopter avec journal) | à faire |
| ISS-020 | `exec_detection.rs` : magie ELF, parsing shebang hostile-safe (truncature, CRLF, non-UTF8, `#!` vide), classification de fichier, familles d'interpréteurs y compris **`/usr/bin/env` avec drapeaux (`-S`)** — le vecteur TM-021 | ✅ fait le 2026-08-22 — 6 tests (1 bug réel trouvé par test : `-S` pris pour l'interpréteur) |
| ISS-021 | Collecte journald : sous-processus `journalctl -o json` + parseur pur testable ; files bornées à priorités | à faire |
| ISS-022 | Envoi différé : outbox avec priorités, diffs incrémentaux, calcul de backoff avec jitter (pur, testable) — le transport réseau arrive avec ISS-030 | à faire |

## Règles du sprint

1. Parseurs purs et testables ; effets de système (processus, fichiers)
   derrière des fonctions racinées (`root: &Path`) ou des traits.
2. Aucune collecte de contenu de fichier — métadonnées seulement
   (SEC-1001).
3. Chaque issue = un commit ; gates workspace à chaque étape.

## Critères de sortie

1. Sur la VM de laboratoire Fedora : l'agent produit un inventaire
   complet (distribution, capacités, paquets, exécutables, scripts).
2. Tests négatifs sur chaque parseur (entrées hostiles, troncatures).
3. Revue humaine avant M3 (compilateur de politiques).
