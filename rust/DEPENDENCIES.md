# Adoption log — workspace dependencies (checklist §1 SUPPLY_CHAIN_SECURITY.md)

Chaque entrée : version épinglée, licence, dernière release constatée au
moment de l'adoption, rôle, et preuve d'évaluation. Revue de renouvellement
à chaque release du projet.

| Crate | Version | Licence | Dernière release (constatée) | Rôle | Évaluation | Décision |
|---|---|---|---|---|---|---|
| serde_json | 1.0.x | MIT OR Apache-2.0 | 2026-07-20 | Sérialisation JSON + canonisation JCS | Spike ISS-007 (vecteurs officiels RFC 8785) ; feature `float_roundtrip` obligatoire | Adoptée 2026-08-21 |
| ryu | 1.0.x | Apache-2.0 OR BSL-1.0 | 2026-02-08 | Chiffres les plus courts (JCS) | Spike ISS-007 | Adoptée 2026-08-21 |
| jsonschema | 0.50.x | MIT | 2026-08-20 | Validation stricte `policy/v0` (sans réseau) | ISS-010 (7 vecteurs) ; très active | Adoptée 2026-08-21 |
| rcgen | 0.14.x | MIT OR Apache-2.0 | 2026-08-10 | Émission X.509 (CA interne) | Spike ISS-006 + prototype ISS-011 (6/6) | Adoptée 2026-08-22 (DEC-07) |
| rustls | 0.23.x | Apache-2.0 OR ISC OR MIT | 2026-07-29 | mTLS (backend **ring**) | Prototype ISS-011 ; 2 avis RustSec historiques corrigés | Adoptée 2026-08-22 (DEC-07) |
| rustls-pki-types | 1.x | MIT OR Apache-2.0 | actif | Types DER partagés | Transitivement requise par rustls | Adoptée 2026-08-22 (DEC-07) |
| x509-cert | 0.3.x | Apache-2.0 OR MIT | 2026-07-09 | CRL (`CrlBuilder`), parsing X.509 | Prototype ISS-011 (révocation feuille + intermédiaire) | Adoptée 2026-08-22 (DEC-07) |
| der | 0.8.x | Apache-2.0 OR MIT | 2026-07-09 | Encodage ASN.1 | Transitivement requise par x509-cert | Adoptée 2026-08-22 (DEC-07) |
| ed25519-dalek | 2.2.x | MIT OR Apache-2.0 | active | Signature Ed25519 (CRL) | Prototype ISS-011 ; adaptateurs spki 0.8 écrits | Adoptée 2026-08-22 (DEC-07) |
| signature | 3.0.x | Apache-2.0 OR MIT | 2026 | Traits de signature | **Obligatoire en v3** (unicité de version avec x509-cert — voir rapport prototype) | Adoptée 2026-08-22 (DEC-07) |
| serde | 1.x | MIT OR Apache-2.0 | active | Structures des claims d'enrôlement (champs fixes → sérialisation déterministe) | ISS-012 | Adoptée 2026-08-22 |
| getrandom | 0.3.x | MIT OR Apache-2.0 | 0.3.4 présente dans l'arbre | Aléa des identifiants de token (RNG OS) | ISS-012 | Adoptée 2026-08-22 |
| time | 0.3.x | Apache-2.0 OR MIT | active | Fenêtres de validité des certificats | Déjà transitive de rcgen ; usage limité | Adoptée 2026-08-22 (DEC-07) |

**Risque transversal noté** : `ring 0.17.14` sans release depuis 2025-03
(constat factuel) — variante aws-lc-rs disponible par feature flag si
nécessaire (rapport ISS-011 §4).

**À évaluer avant adoption (interdites sans nouvelle entrée ici)** :
tokio/axum (ISS-030), PostgreSQL driver (ISS-016), tough (ISS-029),
zeroize (secrêts en mémoire, à traiter avec le service de signature).
