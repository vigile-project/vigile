# ADR-0004 — Format et signature des politiques

**Statut** : Accepté — validé avec la Phase 0 le 2026-08-21
**Date** : 2026-08-21

## Contexte

Les politiques sont l'artefact le plus critique : malveillante, elle ouvre le
parc ; rejouée, elle fige un état ancien. Elles transitent par un serveur
potentiellement compromis (TM-001) et doivent être vérifiables **localement**
par l'agent, sans le serveur. Cahier des charges §4-C et §7.

## Options étudiées

| Option | Avantages | Inconvénients |
|---|---|---|
| **JSON canonique (RFC 8785) + Ed25519 détachée, enveloppe enrichie** | Vérifiable localement ; déterminisme (canonisation) ; algèbre de signature simple ; schémas auditables à l'œil | JSON verbeux ; canonisation à implémenter/tester sérieusement |
| JWT/JWS | Standard répandu | Sémantique orientée identité/expiration ; mauvais ajustement aux versions/générations monotones ; pièges canoniques |
| COSE/CBOR signé | Compact, binaire, moderne | Moins lisible ; outillage de relecture plus rare (friction d'audit) |
| Protobuf + signature | Compact, typé | Nécessite le schéma pour lire ; révision humaine moins directe |

## Décision (recommandée)

1. Charge utile : **JSON canonique selon RFC 8785** (JCS), schéma versionné
   `policy/vN` (JSON Schema strict, champs inconnus rejetés).
2. Signature : **Ed25519 détachée(s)** sur le digest canonique ; enveloppe
   transportant tous les champs §7 : id, tenant, version monotone,
   **génération** (compteur global anti-réordonnancement), digest, dates,
   audience, groupe cible, version minimale d'agent, version de schéma,
   signataires, références d'approbation.
3. Seuils : labo 1/1 ; **enforcement production 2/3** (DEC-09).
4. Ordre de vérification côté agent figé (POLICY_MODEL.md §7) ; tout échec =
   refus net et journalisé, jamais de « mieux-disant ».

## Conséquences

- La canonisation JCS devient un module critique : property-based tests
  obligatoires + fuzzing (TEST_STRATEGY.md §2).
- Déterminisme : le couple (entrée canonique, version de compilateur) ⇒
  octets identiques, testé en CI (SEC-209).
- Les politiques restent lisibles (diff, simulation, revue humaine 4 yeux).

## Alternatives rejetées

JWS/JWT : modèle de claims inadapté (versions/générations, seuils multiples).
COSE binaire : à réévaluer uniquement si le volume justifie (peu probable :
les politiques sont rares).

## Risques et critères de révision

- Erreur d'implémentation de la canonisation = faille : mitigée par tests
  croisés avec vecteurs de test officiels JCS et relecture.
- Réviser si besoin de volumes élevés (capteurs) — pas le cas des politiques.
