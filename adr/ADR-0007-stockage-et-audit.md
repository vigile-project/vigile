# ADR-0007 — Stockage et audit

**Statut** : Accepté — validé avec la Phase 0 le 2026-08-21
**Date** : 2026-08-21

## Contexte

Le plan de contrôle doit stocker : configuration, état des agents,
inventaires (volumineux), politiques, approbations, journal d'audit
(intègre), télémétrie (très volumineuse). Cahier des charges §17 :
PostgreSQL candidat ; audit append-only côté application, exportable,
difficile à altérer sans détection ; jamais de secrets dans les journaux.

## Options étudiées

| Option | Avantages | Inconvénients |
|---|---|---|
| **PostgreSQL unique avec cloisonnement logique strict** (MVP) | Une technologie à sécuriser/sauvegarder ; transactions ACID ; partitionnement natif pour le volume | Télémétrie très volumineuse = à surveiller |
| PostgreSQL + magasin télémétrie dédié (ex. column store/OTel) | Scalabilité télémétrie | Deux stacks dès le MVP : prématuré |
| Bases spécialisées multiples dès le départ | « Microservices-ready » | Coût opérationnel immédiat, dispersion |

## Décision (recommandée)

1. **PostgreSQL** pour toutes les données MVP, avec **séparation logique**
   en schémas distincts (config, agents, inventaire, politiques,
   approbations, audit, télémétrie) et comptes/permissions SQL distincts —
   les frontières internes sont préservées pour extraction ultérieure.
2. **Journal d'audit** : table append-only côté application (pas de UPDATE/
   DELETE par le compte applicatif — droits révoqués), chaînage
   cryptographique (hash de l'entrée incluant le hash précédent) +
   signature périodique, export WORM/externe, réplication différée possible.
   Contenu conforme §17 (acteur, avant/après, justification, ticket…).
   Interdits : mots de passe, tokens complets, clés, variables sensibles,
   lignes de commande avec secrets sans rédaction testée.
3. Télémétrie : partitionnement par temps, rétention configurable ;
   l'éventuel magasin dédié (OTel/column store) est **différé** et sera un
   ADR séparé, déclenché par les tests de charge phase 10.
4. Multi-tenant (phase 11) : `tenant_id` présent sur toutes les tables dès
   le MVP, index compris, aucune requête sans filtre serveur.

## Conséquences

- Sauvegarde/restauration : un seul vecteur (PG chiffré) — tests de
  restauration obligatoires et périodiques.
- Le chaînage d'audit rend les insertions concurrentes séquentielles :
  débit borné acceptable pour l'audit (pas pour la télémétrie, qui n'est pas
  chaînée).

## Alternatives rejetées

Stack multiple immédiate : prématurée (règle du MVP strict) ; le
cloisonnement logique prépare la migration sans y contraindre.

## Risques et critères de révision

- Volume télémétrie > budget : ADR d'extraction à écrire avec données de
  charge réelles (phase 10).
- Audit altérable par le superuser SQL : mitigé par export externe
  continu + contrôles ; risque résiduel documenté (l'attaquant OS-level
  complet est hors périmètre applicatif).
