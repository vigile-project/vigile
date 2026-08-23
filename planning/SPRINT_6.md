# SPRINT 6 — Exécuteur et transactions (M6)

> **Statut** : En cours — ISS-038 close, ISS-039..041 restantes
> **Périmètre** : issues ISS-038 à ISS-041 (`planning/BACKLOG.md` §M6)
> **Pré-requis** : M1..M4 ✓ ; M6 est le prérequis de M5 (fapolicyd
> audit) et M7 (enforcement).

## Objectif

Le **composant privilégié minimal** (ADR-0002) : l'exécuteur qui applique
les artefacts de politique via un protocole IPC local strict. C'est la
frontière de confiance TB-2 — la plus critique du produit.

## Ordre de travail et avancement

| Issue | Objet | État |
|---|---|---|
| ISS-038 | `vigile-ipc` : **catalogue fermé** de 8 actions (Ping, GetState, StageArtifacts, ValidateArtifacts, Commit, Rollback, HealthCheck, AckGeneration) avec tag interne `deny_unknown_fields` ; enveloppe avec vérification de version `ipc/v1` ; **validation des chemins d'artefacts** (relatifs, pas `..`, pas `//`, pas de contrôle, ≤16 composantes, ≤512 octets) ; **validation des hash de bundle** (SHA-256 hex) ; socket Unix avec cadrage 4 octets BE + JSON, `SO_PEERCRED` (UID vérifié AVANT tout traitement), limite de taille de trame, client et serveur | ✅ fait le 2026-08-23 — 13 tests (roundtrips, actions inconnues, protocole erroné, JSON hostile, validation de chemins, validation de hash, UID erroné, trame oversized) |
| ISS-039 | Actions Stage/Validate/Commit avec chemins normalisés, O_NOFOLLOW, fsync, permissions minimales | à faire |
| ISS-040 | Transaction complète + LKG + rollback + tests d'interruption à chaque étape | à faire |
| ISS-041 | Unités systemd durcies (agent + exécuteur) + seccomp justifié | à faire |

## Décision de format IPC

**JSON (serde strict)** plutôt que CBOR pour le MVP :
- Nous avons déjà `serde_json` avec `deny_unknown_fields` — la sécurité
  du schéma est identique.
- Le socket est local (pas de concern de bande passante).
- CBOR sera adopté si la taille des artefacts le justifie (documenté
  comme évolution, pas un changement de sécurité).

## Règles du sprint

1. Le catalogue d'actions est **fermé** : toute action non listée est
   rejetée avec `UnknownAction`, jamais interprétée.
2. L'UID de l'appelant est vérifié par `SO_PEERCRED` avant TOUT
   traitement — un mauvais UID ferme la connexion immédiatement.
3. Aucune action ne prend de chemin arbitraire : les artefacts sont
   référencés par hash de bundle, les chemins sont calculés par
   l'exécuteur dans ses périmètres gérés.
4. Tests négatifs obligatoires : actions inconnues, JSON hostile,
   tailles excédées, UID wrong.
