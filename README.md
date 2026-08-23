# Vigile — Plateforme libre de contrôle applicatif Zero Trust pour Linux

> **Nom** : « Vigile » — projet (DEC-01, 2026-08-21). Dépôt officiel :
> `github.com/vigile-project/vigile` (amendement DEC-01 du 2026-08-22 : le
> login GitHub « vigile » est un compte personnel inactif ; crates
> `vigile*` libres sur crates.io). Reste avant médiatisation : recherche de
> marques (INPI/EUIPO).

## Qu'est-ce que ce dépôt ?

Dépôt de **cadrage (Phase 0)** d'une plateforme libre d'administration
centralisée de la sécurité des postes et serveurs Linux : inventaire des
applications, allowlisting avec refus par défaut, approbations, confinement,
contrôle USB, télémétrie et audit — dans une logique Zero Trust.

**Aucun code d'application n'est encore produit.** Cette phase contient
exclusivement des documents de conception, un modèle de menace, des ADR et un
plan de travail. **Aucune affirmation du type « sécurisé », « Zero Trust
atteint », « production-ready » ou « conforme » ne doit être déduite de la
présence de ces documents.** Ces qualités ne pourront être revendiquées
qu'après tests, revue indépendante et validation humaine formelle (critères :
`docs/ROADMAP.md`, §30 du cahier des charges).

## État

| Élément           | État                                            |
|-------------------|-------------------------------------------------|
| Phase 0 (cadrage) | **Validée le 2026-08-21** |
| Sprint 1 (bootstrap) | En cours — fondation créée (ossature, licence, CI, schéma `policy/v0`) |

## Cartographie des documents

| Document | Objet |
|---|---|
| `docs/PROJECT_CHARTER.md` | Mission, valeurs, gouvernance, licence |
| `docs/PRODUCT_REQUIREMENTS.md` | Exigences fonctionnelles, personas, MVP |
| `docs/SECURITY_REQUIREMENTS.md` | Exigences de sécurité vérifiables (SEC-xxx) |
| `docs/NON_GOALS.md` | Non-objectifs explicites et justifiés |
| `docs/GLOSSARY.md` | Vocabulaire partagé |
| `docs/ARCHITECTURE.md` | Composants, flux, topologies |
| `docs/THREAT_MODEL.md` | Menaces STRIDE, arbres d'attaque, limites |
| `docs/TRUST_BOUNDARIES.md` | Frontières de confiance et vérifications |
| `docs/DISTRIBUTION_COMPATIBILITY.md` | Matrice de capacités par distribution |
| `docs/POLICY_MODEL.md` | Schéma des politiques, compilation, signature |
| `docs/AGENT_PROTOCOL.md` | Enrôlement, mTLS, messagerie agent, IPC local |
| `docs/KEY_MANAGEMENT.md` | Hiérarchie de clés, rotation, compromission |
| `docs/UPDATE_SECURITY.md` | TUF, paquets signés, SBOM, anti-rollback |
| `docs/FAILURE_MODES.md` | Comportements de défaillance (fail-closed) |
| `docs/RECOVERY_AND_BREAK_GLASS.md` | Break-glass, PRA, récupération hors ligne |
| `docs/TEST_STRATEGY.md` | Stratégie de tests et budgets de performance |
| `docs/SUPPLY_CHAIN_SECURITY.md` | Chaîne logicielle, CI, reproductibilité |
| `docs/ROADMAP.md` | Phases 0→11 avec critères de sortie |
| `docs/CONTRIBUTING.md` | Contribution, revue, usage de l'IA |
| `docs/SECURITY.md` | Signalement de vulnérabilités |
| `docs/spikes/` | Rapports de spikes du sprint 1 (JCS, PKI/TLS, fapolicyd, TUF) |
| `adr/ADR-0001…0010` | Décisions d'architecture proposées |
| `planning/REPOSITORY_LAYOUT.md` | Arborescence cible du dépôt |
| `planning/BACKLOG.md` | Backlog priorisé, issues atomiques, dépendances |
| `planning/RISKS.md` | Risques, dont bloquants |
| `planning/DECISIONS_NEEDED.md` | Décisions humaines nécessaires |
| `planning/SPRINT_1.md` | Proposition de sprint 1 |
| `planning/SECURITY_REVIEW_CHECKLIST.md` | Checklist de revue de sécurité |

## Règles de lecture

- Tout élément marqué **NON VÉRIFIÉ** doit être confirmé dans une source
  primaire avant d'être utilisé comme base d'une garantie (voir
  `docs/GLOSSARY.md` et la méthode §28 du cahier des charges).
- Chaque document indique : statut, décisions ouvertes, hypothèses, ADR liés,
  critères d'acceptation et risques connus.
- Les ADR sont au statut « Accepté » depuis la validation humaine de la
  Phase 0 (2026-08-21).

## Licence du projet

Décision DEC-02 (2026-08-21) : **AGPL-3.0-or-later** pour le code
(fichier `LICENSE`), **CC BY-SA 4.0** pour la documentation
(`docs/LICENSE-docs.txt`).

Décisions associées prises le même jour : nom « Vigile » (DEC-01),
forge GitHub (DEC-03), anglais public / français interne (DEC-15 —
traduction progressive des documents Phase 0). Journal complet :
`planning/DECISIONS_NEEDED.md`.
