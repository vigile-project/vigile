# Spike ISS-007 — Canonisation JSON RFC 8785 (JCS)

Code **jetable** de validation pour la décision ADR-0004 (politiques signées
après canonisation JCS).

- Implémente : tri des clés par unités de code UTF-16, échappement JCS
  (formes courtes, hexa minuscule), sérialisation des nombres ECMAScript
  reconstruite sur les chiffres les plus courts de `ryu`.
- Dépendances : `serde_json`, `ryu` (évaluation d'adoption requise avant
  report dans `vigile-policy` — check-list docs/SUPPLY_CHAIN_SECURITY.md §1).
- Tests : les 6 paires de vecteurs officiels du RFC (testdata du dépôt
  cyberphone/json-canonicalization) + exemples et frontières ECMAScript.

Exécution : `cargo test` depuis ce répertoire.

Résultat : voir `docs/spikes/ISS-007-canonisation-jcs.md`.
