# SPRINT 2 — Identité et enrôlement (M1)

> **Statut** : En cours — ouvert le 2026-08-22
> **Périmètre** : issues ISS-011 à ISS-016 (`planning/BACKLOG.md` §M1)
> **Pré-requis** : sprint 1 terminé ✓ ; prototype PKI validé ✓ (rapport
> `docs/spikes/ISS-011-prototype-pki.md`) ; **décision humaine DEC-07
> attendue** pour l'adoption définitive de la stack.

## Objectif

Première brique produit du plan de contrôle : l'**identité des agents** —
PKI interne (racine hors ligne simulée + intermédiaire), enrôlement à token
à usage unique, rotation/révocation, détection de clonage, enveloppe
anti-rejeu, registre des agents. Aucune politique, aucun enforcement : M1
est purement identité/inventaire.

## Ordre de travail et avancement

| Issue | Objet | État |
|---|---|---|
| (prélim.) | Prototype PKI (6 points d'ISS-006) | ✅ fait le 2026-08-22 — 6/6 tests, GO, rapport écrit |
| ISS-011 | Crate `vigile-pki` : hiérarchie CA Ed25519 (racine + intermédiaire contraint), émission agent/serveur à profils contraints, CRL par émetteur, adaptateurs spki 0.8 ; dépendances adoptées via `[workspace.dependencies]` + journal `rust/DEPENDENCIES.md` (DEC-07 tranchée) | ✅ fait le 2026-08-22 — 9 tests (dont les 6 scénarios du prototype rejoués), gates workspace verts |
| ISS-012 | Enrôlement : token à usage unique signé Ed25519 + CSR (preuve de possession vérifiée) + émission + **14 tests dont 13 négatifs** (rejeu, expiré, pas encore valide, falsifié, mauvaise clé, mauvais tenant, champ inconnu, type erroné, CSR falsifié, empreinte vide, illisible) + end-to-end avec handshake mTLS réel | ✅ fait le 2026-08-22 |
| ISS-013 | Rotation : décision de renouvellement T-30 j (`should_renew`), émission à fenêtre de validité explicite (chevauchement prouvé), rotation avec **nouvelle clé**, révocation de l'ancien certificat, certificat expiré refusé, **CRL expirée refusée quand `enforce_revocation_expiration`** (découverte : rustls **ignore** les CRL expirées par défaut — fail-open documenté, à activer en production) | ✅ fait le 2026-08-22 — 5 tests |
| ISS-014 | Registre d'identités (`registry.rs`) : 3 détections — empreinte machine divergente sous même agent (clone), **compteur monotone régressé** (snapshot ancien) ou rejoué à l'identique, ré-enrôlement d'une empreinte déjà prise ; **quarantaine collante** (réactivation admin seule), quarantaine manuelle, journal d'événements auditable. Limite documentée : clone strictement identique non simultané → détection au niveau serveur (ISS-030) et par rotation de clé + CRL | ✅ fait le 2026-08-22 — 8 tests |
| ISS-015 | Enveloppe de message `agent/v1` (`envelope.rs`) : nonce serveur à **tour unique par message accepté**, horodatage RFC3339 à dérive bornée (±10 min, DEC-09), compteur monotone délégué au registre (régression → quarantaine), protocole épinglé, schéma strict (`deny_unknown_fields`), request-id validé. Un message rejeté ne consomme jamais le nonce (un souci d'horloge ne désynchronise pas agent/serveur) | ✅ fait le 2026-08-22 — 11 tests |
| ISS-016 | Registre agents + inventaire machine (schémas PostgreSQL, ADR-0007) | à faire |

## Découverte structurante du prototype

rustls vérifie la révocation sur **toute la chaîne** par défaut
(`revocation_check_depth = Chain`) : le service de révocation Vigile devra
**émettre une CRL par émetteur** (racine → intermédiaires ;
intermédiaire → feuilles). Statut inconnu = **refus** par défaut
(fail-closed, ADR-0010) — ne jamais activer
`allow_unknown_revocation_status()`.

## Hors périmètre

Serveur HTTP complet (M4), moteur de politiques (M3), inventaire
applicatif (M2), TUF opérationnel (ISS-029, sprint suivant), TPM.

## Critères de sortie

1. Chaque SEC-101..107 pertinente couverte par au moins un test négatif.
2. `cargo test` workspace vert + clippy strict + fmt (CI locale).
3. Rapport de sprint mis à jour ; revue humaine avant M2.
