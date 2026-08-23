# SPIKE ISS-006 — Bibliothèques PKI / mTLS / TPM

> **Statut** : Terminé (GO conditionnel) — 2026-08-21
> **Issue** : ISS-006 ; décisions éclairées : DEC-07, ADR-0002/0003
> **Méthode** : vérification le jour même sur sources primaires (API crates.io, docs.rs, dépôts GitHub, rustsec.org, repology). Tout fait non confirmé est marqué NON VÉRIFIÉ.

## Recommandation (stack proposée)

| Brique | Choix | Justification vérifiée |
|---|---|---|
| TLS / mTLS | **rustls 0.23.43** | Série 0.23.x très active (37 releases depuis 2024, dernière 2026-07-29) ; mTLS client via `WebPkiClientVerifier` ; CRL supportées depuis 0.22.0 ; Ed25519 confirmé dans le code |
| Émission certificats (CA interne) | **rcgen 0.14.9** | Racine + intermédiaire couverts : `is_ca`/path-length, EKU, `name_constraints`, `crl_distribution_points`, `custom_extensions` ; Ed25519 (`PKCS_ED25519`) confirmé ; 0.14.9 publié le 2026-08-10, dépôt sous l'org **rustls** |
| Génération des CRL | **x509-cert 0.3.0** (feature `builder`, `CrlBuilder`) | **rcgen ne génère pas de CRL** (vérifié : uniquement les points de distribution) — `x509-cert` 0.3.0 (stable, 2026-07-09, RustCrypto) fournit `CrlBuilder` |
| Échanges CA hors ligne | PKCS#8/PEM via rcgen + `der` 0.8.1 | Pas de « remote signing » dans rcgen (absent du Cargo.toml) — inutile pour le modèle racine hors ligne |
| TPM 2.0 (optionnel) | **tss-esapi 7.7.0** | Dépôt actif (push 2026-08-19), Apache-2.0, projet Parsec ; exige tpm2-tss système ≥ 4.1.3 (ou feature `bundled`) |
| Backend crypto | **à décider par prototype** (voir point d'attention) | Les défauts divergent entre rustls et rcgen |

## Point d'attention majeur : backend crypto

Vérifié dans les Cargo.toml amont :
- **rustls 0.23.43** : défaut = `aws_lc_rs` (aws-lc-rs 1.18.0, 2026-08-07) ; ring en feature optionnelle.
- **rcgen 0.14.9** : défaut = `ring` ; `aws_lc_rs` et `fips` optionnels.
- **ring 0.17.14** : dernière release le **2025-03-11** (aucune depuis ~17 mois — fait constaté, cause NON VÉRIFIÉE).

Sans alignement explicite, on embarque les **deux** piles C. Recommandation :
`rustls` avec feature `ring` + rcgen par défaut (empreinte simple, pas de
cmake/NASM), **ou** tout aws-lc-rs si exigence FIPS (statut FIPS exact de
rustls 0.23.43 : NON VÉRIFIÉ). Ed25519 confirmé côté aws-lc-rs (vérification
et signature) ; côté signing avec ring : NON VÉRIFIÉ (prototype).

## Tableau de due diligence

| Crate | Version | Dernière release | Licence | Maintenance | RustSec |
|---|---|---|---|---|---|
| rustls | 0.23.43 | 2026-07-29 | Apache-2.0 OR ISC OR MIT | Très active (org rustls) | 2 avis, corrigés (≥0.23.18 / ≥0.23.5) |
| rcgen | 0.14.9 | 2026-08-10 | MIT OR Apache-2.0 | Active (org rustls) | 0 |
| x509-cert | 0.3.0 | 2026-07-09 | Apache-2.0 OR MIT | Active (RustCrypto/formats) | aucun trouvé (NON VÉRIFIÉ exhaustivement) |
| der | 0.8.1 | 2026-07-09 | Apache-2.0 OR MIT | Active | idem |
| openssl | 0.10.81 | 2026-06-12 | Apache-2.0 | Active | **10 avis historiques** dont 2 récents → rejetée |
| tss-esapi | 7.7.0 | 2026-04-24 | Apache-2.0 | Active (Parsec) | 0 |
| step-ca (externe) | 0.30.2 | 2026 | Apache-2.0 | Active mais **absent des dépôts Fedora/EPEL** | rejetée (service Go externe, hors boussole « pur Rust embarqué ») |

## Ce que le prototype de validation doit trancher (ISS-011)

1. Alignement backend : `cargo tree` sans aws-lc-sys (variante ring), puis variante aws-lc-rs si FIPS requis.
2. Chaîne complète racine→intermédiaire→client rcgen, validée par rustls (`WebPkiClientVerifier` + CRL) ; comportement des `name_constraints`.
3. Ed25519 bout en bout avec le backend ring (signing NON VÉRIFIÉ avec ring).
4. CRL générée par `x509-cert` consommée par rustls (interop des deux crates à démontrer ; 0.3.0 récent).
5. Comportement rustls sur expiration de CRL / statut « unknown » (politique à figer pour Vigile, DEC-09).
6. tss-esapi 7.7.0 contre tpm2-tss 4.x de Fedora (vérifier la version packagée).

## Sources (extrait)

- crates.io : rustls, rcgen, x509-cert, der, openssl, tss-esapi, tss-esapi-sys, ring, aws-lc-rs
- github.com/rustls/rustls (releases v/0.22.0 — CRL/WebPkiClientVerifier ; Cargo.toml v/0.23.43 — features défaut)
- docs.rs/rcgen/0.14.9 (CertificateParams, KeyPair) ; github.com/rustls/rcgen (sign_algo.rs — Ed25519)
- docs.rs/x509-cert/0.3.0 (builder/CrlBuilder)
- rustsec.org/packages/rustls.html et /openssl.html
- github.com/parallaxsecond/rust-tss-esapi (README, exigences tpm2-tss)
- repology.org/project/step-ca/versions (absence Fedora)

## Conclusion

**GO** : la stack rustls + rcgen + x509-cert (CRL) + tss-esapi (option) couvre
le modèle de KEY_MANAGEMENT.md sans dépendance système (hors TPM optionnel).
Décision finale DEC-07 après le prototype ci-dessus. `openssl` et `step-ca`
sont rejetées en l'état.
