# Vigile 0.1.0-rc1 — note de release

**25 septembre 2026** — premier candidat release. Contrôle d'application
Zero Trust pour Linux (AGPL-3.0). **Qualifié pour le labo et le mode
audit/observation** ; le mode enforcing sur parc réel reste hors périmètre
de cette RC (voir ci-dessous).

## Ce que cette RC sait faire

- **Contrôle applicatif** : compilation de politiques (schéma validé,
  contrôles de contradiction C1-C8) vers des règles fapolicyd, déployées
  par un agent transactionnel (validation native avant écriture, rollback
  LKG).
- **Chaîne de confiance complète** : PKI Ed25519 persistante (racine +
  intermédiaire), mTLS obligatoire sur l'API agent, **règles signées
  Ed25519 vérifiées avant tout déploiement**, manifestes SHA-256.
- **Enrôlement réel** : jetons à usage unique + CSR (la clé privée ne
  quitte jamais l'agent), révocation **à chaud** (CRL regénérée sans
  redémarrage — testé : `CertificateRevoked` à la connexion suivante).
- **Durcissement serveur** : parseur HTTP strict (fuzzé, 10 tests
  déterministes), jetons admin hachés et fournis par l'opérateur,
  journal d'audit à chaînage SHA-256.
- **Reprise** : persistance complète (CA, graine de signature, politique,
  registre agents) — exercice DR chronométré ≈ 110 s (RUNBOOK-DR.md).

## Qualification (phase 10)

Revue sécurité A→I complète : `docs/security/REVIEW-2026-09-PHASE10.md`.
Fuzz : 1 bug réel trouvé et corrigé (Content-Length malformé coercé).
42 suites de tests vertes, clippy sans avertissement, `panic!`/`unwrap`
interdits par lints workspace.

## Limites connues (hors enforcing)

- Épinglage d'empreinte CA au bootstrap d'enrôlement (090-2, P2)
- Modes de défaillance de la persistance à documenter (090-4, P2)
- Reproductibilité bit-à-bit des binaires : empreintes publiées
  (`packaging/artifacts-0.1.0-rc1.sha256`) mais build reproductible
  complet à démontrer avec le pipeline RPM
- SBOM généré depuis Cargo.lock (249 composants,
  `packaging/sbom-0.1.0-rc1.json`)

## Empreintes

Voir `packaging/artifacts-0.1.0-rc1.sha256` (vigile-server,
vigile-agent — x86_64, Fedora 44, Rust 1.98.0).
