# ADR-0002 — Séparation agent / exécuteur privilégié

**Statut** : Accepté — validé avec la Phase 0 le 2026-08-21
**Date** : 2026-08-21

## Contexte

L'application des politiques exige des écritures root (règles fapolicyd,
rechargements, artefacts). Le composant qui parle au réseau (synchronisation,
télémétrie) est le plus exposé. Mélanger les deux offrirait à un attaquant
distant un chemin direct vers root. Cahier des charges §4-B.

## Options étudiées

| Option | Avantages | Inconvénients |
|---|---|---|
| **Agent unique privilégié** | Simplicité de déploiement | Surface d'attaque réseau → root maximale ; interdit par le cahier des charges |
| **Agent non privilégié + exécuteur minimal (recommandé)** | Le réseau n'a jamais root ; l'exécuteur n'a pas de réseau ; auditabilité des actions privilégiées | Complexité IPC ; discipline de catalogue d'actions |
| Agent + sudo de commandes fixes | Réutilise sudo | Moins typé, historique d'audit plus faible, difficile à contraindre finement |
| Setuid helper unique | Simple | Binaire setuid : trop risqué |

## Décision (recommandée)

1. `vigile-agent` : service système non privilégié (utilisateur `vigile`),
   gère réseau, vérification des signatures, compilation locale, files.
2. `vigile-executor` : service **root minimal** sans réseau, accessible
   uniquement via socket Unix locale (`SO_PEERCRED`), protocole `ipc/v1` à
   **actions strictement typées** (catalogue fermé — AGENT_PROTOCOL.md §6).
3. L'exécuteur : ne jamais interpréter de shell ; chemins normalisés dans
   des périmètres gérés ; O_NOFOLLOW ; re-vérification des hash ; limites
   tailles/délais/débit ; unités systemd durcies ; seccomp justifié et
   testé ; journal local de chaque action.
4. `vigile-userd` : composant de session, sans privilège, sans accès aux
   clés, ne peut pas écrire de politiques.

## Conséquences

- Toute élévation passe par une action nommée, versionnée, auditable.
- Le catalogue IPC doit rester minuscule ; tout ajout = version majeure +
  analyse de menace dédiée.
- La vérification cryptographique est faite par l'agent **et re-vérifiée
  (hash) par l'exécuteur** — défense en profondeur TB-2.

## Alternatives rejetées

sudo setuid-fication des actions : moins expressif pour la limitation de
débit/taille et l'audit structurel ; conservé en complément éventuel pour la
phase 8 (élévation utilisateur), décision reportée.

## Risques et critères de révision

- Dérive du catalogue vers des actions trop génériques : revue systématique
  en gate de PR (checklist sécurité).
- Performance IPC : négligeable attendue (actions rares) ; mesurée quand même.
