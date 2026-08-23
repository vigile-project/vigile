# PROTOTYPE PKI — Sprint 2 (ISS-011) : validation de la stack DEC-07

> **Statut** : Terminé (GO) — 2026-08-22
> **Issue** : prototype préalable à ISS-011 (décision DEC-07)
> **Code** : `spikes/pki-chain/` (jetable, hors workspace)
> **Résultat** : ✅ **GO sur les 6 points ouverts du spike ISS-006** — 6/6 tests, clippy 0 avertissement, backend crypto **ring unique** (aucun aws-lc dans `cargo tree`).

## 1. Points tranchés

| # | Point ouvert (ISS-006) | Verdict | Preuve |
|---|---|---|---|
| 1 | Alignement backend (ring vs aws-lc-rs, défauts divergents) | **OK — ring seul** (`ring 0.17.14`, `cargo tree` sans aws-lc) | `cargo tree` |
| 2 | Chaîne racine→intermédiaire→client (contraintes, EKU) | **OK** — CA/path-length 0 via rcgen `Issuer`, EKU clientAuth/serverAuth | t01 |
| 3 | **Ed25519 bout en bout avec ring** (signing TLS NON VÉRIFIÉ) | **OK — confirmé** : signature handshake client + vérification serveur + CA Ed25519 | t02 |
| 4 | CRL x509-cert → rustls (interopérabilité) | **OK — avec adaptateurs** (voir §2) : révocation feuille **et** intermédiaire effectives | t04, t06 |
| 5 | CRL « propre » ne bloque pas les autres | **OK** | t05 |
| 6 | Client sans certificat | **OK — refus fail-closed** | t03 |

## 2. Découvertes à reporter dans l'implémentation réelle

### 2.1 Versionnement des crates : piège résolu

`x509-cert 0.3` dépend de **spki 0.8 + signature 3.0** alors que
`ed25519-dalek 2.2` (feature `pkcs8`) n'implémente que spki 0.7 / signature
2.x. Si le projet dépend de `signature = "2"`, **cargo fait cohabiter deux
versions** et les bornes du `CrlBuilder` échouent silencieusement (E0277 sur
`Signer`/`Keypair`). Solution : dépendre de **`signature = "3"`** + couche
d'adaptateurs (~100 lignes, `spikes/pki-chain/src/adapters.rs`) :
`Ed25519Sig` (SignatureEncoding + SignatureBitStringEncoding, octets par
valeur — dalek n'expose pas d'emprunt `&[u8]`), `Ed25519Pub`
(EncodePublicKey SPKI), `Ed25519Signer` (Signer + Keypair +
DynSignatureAlgorithmIdentifier, OID 1.3.101.112 sans paramètres).

### 2.2 Modèle de révocation rustls (input conception majeur)

- `revocation_check_depth = Chain` **par défaut** : la révocation est
  vérifiée sur **toute** la chaîne → il faut **une CRL par émetteur**
  (racine → CRL des intermédiaires ; intermédiaire → CRL des feuilles),
  conformément à RFC 5280. Révoquer l'intermédiaire coupe toute la chaîne
  (t06) — c'est le comportement voulu pour Vigile.
- `unknown_revocation_policy = Deny` **par défaut** : un statut de
  révocation indéterminé est une **erreur** — fail-closed conforme à
  ADR-0010. Relaxation possible par `allow_unknown_revocation_status()`
  (à ne jamais activer côté agents Vigile).
- `enforce_next_update` optionnel (politique d'expiration des CRL) — **non
  testé ici**, à couvrir par ISS-013 (rotation/expiration).
- webpki exige : CRL **v2**, `nextUpdate` **présent**, section extensions
  **présente**, pas de delta-CRL — le `CrlBuilder` satisfait tout ça.

### 2.3 API notables (vérifiées empiriquement)

- **rcgen 0.14** : émission par `params.signed_by(&key, &Issuer)` ;
  `Issuer::from_ca_cert_der(&cert, &key)` (feature `x509-parser`) ;
  `CertificateParams::default()` + `distinguished_name` pour les CA ;
  `CertificateParams::new` attend `Vec<String>` (SAN).
- **x509-cert 0.3** : `CrlBuilder::new(&Certificate, CrlNumber)` →
  `.with_next_update(Option<Time>)` → `.with_certificates(iter)` →
  `.build::<_, SigType>(&signer)` ; `SerialNumber::new(&[u8])` ;
  accès aux champs par **accesseurs** (`tbs_certificate()`,
  `serial_number()`, `get_extension::<T>()` renvoie
  `(criticalité, valeur)`).
- **rustls 0.23.43** : `builder_with_provider(provider)
  .with_safe_default_protocol_versions()?` (renvoie un `Result` !) ;
  `WebPkiClientVerifier::builder(roots).with_crls(...)`.

## 3. Ce qui reste hors de ce prototype (issues suivantes)

- ISS-011 (réel) : portage dans le workspace (crate identité du serveur +
  adaptateurs + magasin de CRL), revue d'adoption des dépendances.
- ISS-013 : rotation avec chevauchement de validité, expiration de CRL,
  `enforce_next_update`.
- ISS-012/015 : token d'enrôlement JWS à usage unique, enveloppe
  anti-rejeu (nonce+compteur).
- nameConstraints (rcgen les supporte — non testés ici, à couvrir avec
  l'émission réelle).
- TPM (tss-esapi) : reporté, optionnel (jamais dépendance du MVP).

## 4. Conclusion pour DEC-07

**Recommandation confirmée et éprouvée** : rustls 0.23 (feature `ring`) +
rcgen 0.14 (+`x509-parser`) + x509-cert 0.3 (CRL) + signature 3 + couche
d'adaptateurs Ed25519. Risque résiduel noté : ring 0.17.14 sans release
depuis 2025-03 (constat inchangé du spike ISS-006) — la variante aws-lc-rs
reste disponible par feature flag si nécessaire. **Décision humaine
DEC-07 : prête à être prise.**
