# FEUILLE DE ROUTE

> **Statut** : **Validé** — Phase 0 approuvée par décision humaine le 2026-08-21
> **Version** : 0.1 — 2026-08-21
> **Décisions ouvertes** : priorisation finale par le valideur humain ; découpage des sprints dans `planning/BACKLOG.md`
> **ADR liés** : tous (les gates de phase valident les ADR associés)
> **Hypothèses clés** : chaque phase se termine par une **revue humaine go/no-go** documentée ; aucune phase suivante n'est entamée sans validation explicite ; le MVP correspond aux phases 0→3.

## Vue d'ensemble

| Phase | Objet | Sortie caractéristique | Gate de sortie (extraits) |
|---|---|---|---|
| 0 — Cadrage | Présent dépôt | Documents + ADR + backlog | Validation humaine du lot complet |
| 1 — Labo & inventaire | Fedora GNOME | Agent, enrôlement mTLS, inventaire, portail minimal, **aucune politique bloquante** | Tests B Fedora ; audit d'enrôlement ; §30 partiel |
| 2 — fapolicyd audit | Observation | Adaptateur fapolicyd, compilation, simulation, apprentissage, recommandations | T-BYPASS ; aucune activation auto |
| 3 — Enforcement & approbation | Cœur produit | Règles signées, approbations, exceptions, canary, rollback, anti-auto-blocage, notification GNOME, audit complet | Catégorie D entière ; rollback prouvé ; MVP atteint |
| 4 — USBGuard | USB | Inventaire, blocage par défaut, workflow approbation, tests BadUSB | Tests clavier/souris/dock/YubiKey + BadUSB |
| 5 — Debian/Ubuntu + AppArmor | Extension | DEB, apt/dpkg, AppArmor complain→enforce, matrice d'écarts | Tests B Debian-like |
| 6 — SELinux | Confinement | Modèle abstrait, modules contrôlés, analyse AVC, permissif ciblé | Non-régression ; jamais de politique permissive générée |
| 7 — Réseau par application | Étude→proto | Prototype d'identité de charge (cgroups v2/scopes/nftables) **avant** implémentation | Prototype démontrant identité stable |
| 8 — Élévation | Contrôle | Actions structurées, polkit/sudo minimal, approbation, expiration | Pas de shell root générique |
| 9 — NixOS | Déclaratif | Module NixOS, secrets hors store, tests VM NixOS, stratégie de coexistence | ADR-0008 appliqué ; rollback par générations |
| 10 — Durcissement production | Qualification | Audit externe, pentest, charge, DR, rotation, pilote, RC | Critères §30 du cahier des charges |
| 11 — Multi-tenant & échelle | Périphérie | Isolation tenants, HA, réplication, grands parcs | Tests anti-fuite + IDOR complets |

## Dépendances entre phases

```
0 ─→ 1 ─→ 2 ─→ 3 (MVP) ─→ 4 (USB)
                └───────→ 5 (Debian) ─→ 6 (SELinux)
                └───────→ 7 (réseau)  ─→ 8 (élévation)
                └───────→ 9 (NixOS)
      3..9 ──────────────→ 10 (qualification) ─→ 11 (multi-tenant/HA)
```

## Jalons de validation humaine obligatoires

1. Fin de phase 0 — **franchie le 2026-08-21** (validation humaine du lot
   complet, ADR inclus).
2. Avant la **première** activation d'enforcement sur une machine physique
   (après phases 2→3 en labo).
3. Avant chaque élargissement d'anneau au-delà du labo.
4. Avant toute activation USB de production (FM-12 tranché).
5. Revue go/no-go de qualification production (phase 10).

## Critères d'acceptation du document

- [ ] Ordre et gates validés par le valideur humain.
- [ ] MVP confirmé comme phases 0→3 strictement (§26).

## Risques connus

- Glissement du périmètre (phases 4+ attirées trop tôt) : mitigation par
  gates et NON_GOALS.
- Phase 7 risquée techniquement : traitée comme étude d'abord (prototype
  obligatoire avant implémentation).
- Charge de test multi-distributions : lissée par phases 5/9.
