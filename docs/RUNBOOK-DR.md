# RUNBOOK — Reprise après sinistre (ISS-092)

> **Exercé et chronométré le 2026-09-25** (labo, Fedora 44).
> Objectif : remettre le serveur Vigile en service après perte complète du
> répertoire de données, avec re-vérification de bout en bout.

## Données en jeu (`VIGILE_DATA_DIR`, labo : `/tmp/vigile-data`)

| Fichier | Perte = |
|---|---|
| `ca-root.*`, `ca-inter.*` | tous les certificats agents deviennent invérifiables |
| `deploy-seed.bin` | les règles déjà déployées ne vérifient plus leur signature |
| `deployed-policy.json` | plus aucune politique servie (recompilation nécessaire) |
| `admin-tokens.json` | retour en mode labo (jetons générés/imprimés) |
| `agents.json` | registre de révocation vide (les quarantaines sont perdues) |

**Sauvegarde** : copie du répertoire entier (clés en 0600 — support chiffré,
cf. KEY_MANAGEMENT.md). Une copie par jour suffit en labo ; RPO production à
définir avec l'exploitant.

## Scénario 1 — Perte du serveur (data dir détruit)

1. Restaurer : `cp -r <backup> $VIGILE_DATA_DIR` (0 s pour 8 fichiers)
2. Redémarrer `vigile-server` — le journal doit montrer, dans l'ordre :
   `PKI loaded from …` · `admin tokens loaded from admin-tokens.json` ·
   `deployed policy restored from disk`
3. Vérifier : `vigile-agent sync <url>` → `Policy available`
   (l'identité agent existante reste valide : même CA)

**Mesuré** : rétablissement total (restauration → service vérifié avec
enrôlement d'un nouvel agent) ≈ **110 s**, dont l'essentiel est du temps
d'orchestration humaine ; les opérations elles-mêmes sont sub-secondes.

## Scénario 2 — Agent bloqué / poste verrouillé

Utiliser `packaging/recovery/vigile-breakglass` (justification + ticket,
TTL, journalisé) — procédure détaillée dans RECOVERY_AND_BREAK_GLASS.md.

## Scénario 3 — Compromission de la CA (racine)

1. **Arrêter le serveur** (ne plus émettre aucun certificat).
2. `POST /admin/v1/agents/quarantine` pour chaque agent suspect tant que
   le serveur tourne (CRL à chaud, effet immédiat).
3. Régénérer une hiérarchie : purger le data dir et redémarrer —
   **tous les agents doivent se ré-enrôler** (nouvelle CA, nouveaux
   jetons à usage unique). La reprise est le scénario 1 + vagues
   d'enrôlement.
4. Journaliser l'incident (audit local + SECURITY.md si diffusion).

## Scénario 4 — Règles déployées suspectes

`rm /etc/fapolicyd/rules.d/90-vigile.rules && fapolicyd-cli --reload-rules`
— le poste revient à sa politique antérieure ; l'agent ne redéployera
qu'après vérification de signature (ISS-088).

## Leçons de l'exercice (2026-09-25)

- Un redémarrage **sans** `VIGILE_DATA_DIR` charge silencieusement le
  répertoire par défaut (`~/.local/share/vigile`) et une autre CA :
  toujours vérifier la ligne `PKI loaded from …` au démarrage.
  → amélioration tracée : refuser de démarrer si le data dir cible
  contient une hiérarchie différente de la dernière connue (option
  `--require-fingerprint`).
- La latence de reprise est dominée par l'orchestration, pas par le
  produit : la restauration elle-même est une copie de fichiers.
