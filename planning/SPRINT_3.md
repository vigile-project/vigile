# SPRINT 3 — Inventaire applicatif (M2)

> **Statut** : **Terminé** (M2 complet) — 2026-08-22
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
| ISS-019 | `executables.rs` : parcours raciné (chemins standards + home explicite), bit exécutable, **symlinks jamais suivis** (fichiers ET racines — usrmerge piégé par la VM), SHA-256 streamé (`sha2` 0.11 adoptée), bornes (`MAX_FILES`), racines absentes ≠ erreur, clés relatives à la racine virtuelle | ✅ fait le 2026-08-22 — 5 tests |
| ISS-020 | `exec_detection.rs` : magie ELF, parsing shebang hostile-safe (truncature, CRLF, non-UTF8, `#!` vide), classification de fichier, familles d'interpréteurs y compris **`/usr/bin/env` avec drapeaux (`-S`)** — le vecteur TM-021 | ✅ fait le 2026-08-22 — 6 tests (1 bug réel trouvé par test : `-S` pris pour l'interpréteur) |
| ISS-021 | `journal.rs` (parseur journalctl NDJSON hostile-safe, tableaux d'octets conservés sans perte, lanceur fin) + `spool.rs` (**file bornée à priorités : la télémétrie est évincée en premier, la sécurité JAMAIS**, saturation sécurité comptée pour alerte — FM-17) | ✅ fait le 2026-08-22 — 9 tests |
| ISS-022 | `outbox.rs` : diff d'inventaire incrémental (ajoutés/modifiés/supprimés) + backoff exponentiel à jitter **injecté** (bornes prouvables pour tout RNG, cap, pas de débordement) — transport réseau différé à ISS-030 | ✅ fait le 2026-08-22 — 5 tests |

## Règles du sprint

1. Parseurs purs et testables ; effets de système (processus, fichiers)
   derrière des fonctions racinées (`root: &Path`) ou des traits.
2. Aucune collecte de contenu de fichier — métadonnées seulement
   (SEC-1001).
3. Chaque issue = un commit ; gates workspace à chaque étape.

## Critères de sortie

1. ✅ **VM Fedora 44 (2026-08-22)** : `vigile-agent inventory` produit
   l'inventaire complet réel — plateforme fedora 44, **431/432 paquets
   signés** (rpm 6 / OPENPGP), capacités (fapolicyd présent → supported
   depuis le smoke), 3 exécutables hors paquets plantés pour l'occasion
   (script `env -S`, script bash, ELF) avec kind + SHA-256.
2. ✅ Tests négatifs sur chaque parseur (entrées hostiles, troncatures,
   base64 non paddé, paquet OpenPGP falsifié).
3. ⏳ Revue humaine avant M3 (compilateur de politiques) — **en attente**.

## Bugs réels trouvés par les tests/VM (à retenir)

- rpm 6.0.2 vide `%{SIGPGP:pgpsig}` → signatures dans `%{OPENPGP}`
  (paquet OpenPGP base64, Key ID extrait du sous-paquet issuer).
- usrmerge : `/usr/local/sbin` est un symlink → racines de scan
  elles-mêmes vérifiées (sinon doublons).
- Transcription manuelle d'un long vecteur de test = coquille → le
  `const` du test rpm6 est régénéré depuis une capture réelle.
