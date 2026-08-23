# SPIKE ISS-009 — Implémentations TUF

> **Statut** : Terminé (GO) — 2026-08-21
> **Issue** : ISS-009 ; décisions éclairées : ADR-0005, UPDATE_SECURITY.md
> **Méthode** : vérification le jour même (crates.io API, GitHub API, OSV/RustSec, spécification TUF). Non vérifié = marqué.

## Recommandation

**Adopter `tough` 0.24.0 côté client (dans l'agent Vigile) + `tuftool`
pour le prototype de dépôt ; évaluer RSTUF pour la production.** Ne pas
réimplémenter TUF en interne (analyse §3).

## 1. Tableau comparatif (vérifié 2026-08-21)

| Critère | **tough** | `tuf` (rust-tuf) | sigstore-tuf | impl. interne |
|---|---|---|---|---|
| Version | **0.24.0** (2026-07-10) | 0.3.0-**beta14** (2025-10-20) | 0.11.0 (2026-07-08) | — |
| Licence | MIT OR Apache-2.0 | MIT / Apache-2.0 | Apache-2.0 | — |
| Téléchargements (total/récents) | 2 126 462 / 640 651 | 43 081 / **213** | 237 601 | — |
| Dépôt | github.com/awslabs/tough, non archivé, push 2026-07-10 | theupdateframework/rust-tuf, actif mais erratique | sigstore/sigstore-rust, actif | — |
| Maturité | Stable, releases régulières | README : « Beta Software… may not be suitable for production » | Stable, écosystème Sigstore | à construire |
| Vérification client | **oui** (cœur de la lib) | oui | oui (trust root Sigstore) | à écrire |
| Création/signature de dépôt | via **tuftool 0.17.0** (root add-key/remove-key/set-threshold/sign, create, delegation, clone) + tough-kms/ssm | en lib | non ciblé | à écrire |
| Seuils k-of-n, rotation root | oui (rotation en deux étapes vN+1/vN+2) | oui | n/a | à écrire |
| Avis de sécurité | **12 GHSA**, tous antérieurs à 0.24.0 (aucun ouvert) | 0 (signal faible : adoption nulle) | NON VÉRIFIÉ exhaustivement | inconnu par définition |

Autres constats : `in-toto` 0.4.0 (2024-12-11, actif) = complément
attestations, hors périmètre TUF ; `olpc-cjson` 0.1.4 = JSON canonique si
implémentation interne (déconseillée) ; **Uptane en Rust : inexistant**
(constat vérifié) ; ⚠️ une crate `libdd-tuf` 0.3.1 (2026-08-19) déclare le
dépôt rust-tuf comme repository sans en émaner — à ne pas dépendre
(intention NON VÉRIFIÉE, faits constatés).

## 2. Outillage serveur (hors Rust)

| Outil | Version | Statut |
|---|---|---|
| python-tuf (référence) | v7.0.0 (2026-05-18) | actif |
| go-tuf v2 | v2.4.2 (2026-05-19) | actif |
| **RSTUF** (Repository Service for TUF : API + worker + CLI) | — | actif (pushes août 2026), option production la plus sérieuse |
| tuf-on-ci (publication via CI) | v0.20.0 | actif |

`tuftool` suffit pour le prototype Vigile ; RSTUF à évaluer avant production
(UPDATE_SECURITY.md).

## 3. Pourquoi pas une implémentation interne

L'historique de `tough` documente exactement le coût d'une réimplémentation :
sur ~6 ans, une équipe AWS a corrigé **12 failles**, toutes dans les
subtilités que Vigile devrait réécrire — rollback non détecté, cycles de
délégations, délégations terminales ignorées, **unicité des signataires dans
les seuils** (RUSTSEC-2020-0024), path traversal sur les targets. Une
implémentation interne n'aurait ni cet historique d'audit, ni les tests
d'interopérabilité, ni la communauté de signalement. **Décision :
réutiliser `tough` et couvrir les exigences Vigile par des tests négatifs
propres** (§4).

## 4. Prototype de validation (préalable à l'adoption — issue dédiée)

1. Round-trip : dépôt créé par `tuftool create` (root 2-of-3), consommé par
   `tough` (file:// puis https://).
2. Anti-rollback : rejeu de timestamp/snapshot/targets anciens → échec.
3. Anti-freeze : métadonnées expirées → échec ; horloge dérivée.
4. Seuils : 1 signature sur 3 → échec ; **2 signatures de la même clé →
   échec** (régression RUSTSEC-2020-0024).
5. Rotation root en deux étapes ; refus si un maillon manque.
6. Délégations : tests négatifs (cycle, terminale, métadonnée non validée).
7. Politiques = targets TUF (agent + bundles de règles, rôles distincts).
8. Épinglage `tough = "=0.24.0"` + cargo-deny/audit + veille OSV en CI.
9. FIPS si requis (`--features fips`) — statut NON VÉRIFIÉ, à tester.
10. Côté serveur : publication via tuftool puis évaluation RSTUF.

## 5. Sources

crates.io API (tough, tuf, sigstore-tuf, tuftool, in-toto, olpc-cjson) ;
github.com/awslabs/tough (README, tuftool, security-advisories) ;
github.com/theupdateframework/rust-tuf ; api.osv.dev ; spécification TUF
1.0.36 (modifiée 2026-08-05, theupdateframework.github.io/specification) ;
github.com/repository-service-tuf ; github.com/theupdateframework/{python-tuf,go-tuf,tuf-on-ci}.

## Conclusion

**GO** : ADR-0005 reste fondé — `tough` 0.24.0 (MIT/Apache-2.0, AWS, très
active, aucun avis ouvert) est la brique client ; `tuftool` pour le
prototype ; RSTUF à évaluer pour la production. L'implémentation interne est
rejetée. RISK-05 : levé sous condition du prototype ci-dessus.
