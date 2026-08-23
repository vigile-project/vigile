# ADR-0003 — REST, gRPC ou combinaison

**Statut** : Accepté — validé avec la Phase 0 le 2026-08-21
**Date** : 2026-08-21

## Contexte

Deux familles de communication : (a) agent ↔ serveur, en environnement
cloisonné, sortant uniquement, mTLS, tailles bornées ; (b) portail/CLI ↔
serveur. Cahier des charges §16 : contrats versionnés, évaluer REST, gRPC ou
combinaison, puis justifier.

## Options étudiées

| Option | Avantages | Inconvénients |
|---|---|---|
| **REST/HTTPS + mTLS (JSON strict, OpenAPI)** | Trivial à travers proxys/cloisons ; outillage universel ; débogage simple ; contrats générés | Pas de flux bidirectionnel natif ; encodage plus verbeux |
| gRPC | Multiplexage, streaming, contrats protobuf | HTTP/2 + buffers souvent filtrés en environnement cloisonné ; surcouche opérationnelle ; observabilité moins uniforme |
| Combinaison REST + gRPC streaming | Meilleur des deux | Double stack à sécuriser/versionner/tester dès le MVP |

## Décision (recommandée)

1. **REST sur HTTPS + mTLS** pour tous les canaux au MVP :
   - `/agent/v1/*` : pull de politiques, événements par lots, heartbeats ;
   - `/admin/v1/*` : portail + CLI.
2. Schémas **stricts** (champs inconnus rejetés sur les messages critiques),
   OpenAPI généré et publié, pagination, idempotence, quotas, anti-rejeu
   (nonce+compteur), backoff avec jitter.
3. Le streaming (nécessaire seulement si la télémétrie volumineuse l'exige)
   sera réévalué **après** les tests de charge (phase 10-11) via un ADR
   dédié — pas anticipé.

## Conséquences

- Aucun port entrant sur les machines ; compatible proxys sortants.
- Encodage JSON borné (limites de taille) ; lots d'événements agrégés.
- La version de protocole est explicite dans le chemin et re-négociable.

## Alternatives rejetées

gRPC au MVP : friction en environnement cloisonné et double stack de
sécurité ; critère décisif : « le premier paquet qui doit passer un proxy
hostile ne doit pas exiger HTTP/2 ».

## Risques et critères de révision

- Verbeux pour la télémétrie à grande échelle : mesure phase 10 ; bascule
  partielle possible (canal télémétrie uniquement) si budget dépassé.
- JSON strict : discipline de schéma à tenir (tests de rejet des champs
  inconnus obligatoires).
