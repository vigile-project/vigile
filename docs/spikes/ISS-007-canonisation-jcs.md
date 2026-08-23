# SPIKE ISS-007 — Canonisation JSON RFC 8785 (JCS)

> **Statut** : Terminé (GO) — 2026-08-21
> **Issue** : ISS-007 ; décision éclairée : ADR-0004
> **Code** : `spikes/jcs-canonicalization/` (jetable, hors workspace)
> **Résultat** : ✅ **GO** — implémentation validée sur les vecteurs officiels du RFC.

## Objectif

Prouver qu'une canonisation JSON conforme RFC 8785 (prérequis de la
signature des politiques, ADR-0004) est réalisable en Rust avec des
dépendances mineures, et découvrir les pièges avant d'engager
l'implémentation dans `vigile-policy`.

## Méthode

Implémentation (`serde_json` + `ryu` uniquement) puis confrontation aux
**6 paires de vecteurs officiels** du dépôt de référence du RFC
(cyberphone/json-canonicalization, `testdata/`) complétées par des tests
des frontières ECMAScript (1e21, 1e-6/-7, -0, 5e-324, 2^53+1) et du tri
des clés par unités de code UTF-16.

## Résultats

**Tous les tests passent** (`cargo test` : 4 unitaires + 6 vecteurs
officiels). Trois points de conception validés :

1. **Tri des clés** : ordre par unités de code **UTF-16**, pas par points de
   code (différence réelle pour les caractères hors BMP face à
   U+E000..U+FFFF — couvert par un test dédié).
2. **Nombres** : sérialisation ECMAScript `Number::toString` reconstruite à
   partir des chiffres les plus courts de `ryu` (ryu ne suit pas les seuils
   ECMAScript ; la re-mise en forme par algorithme ECMA-262 est nécessaire
   et suffisante).
3. **Chaînes** : formes courtes obligatoires (`\b \t \n \f \r`), `\uXXXX`
   minuscule — l'échappement par défaut de serde_json n'est **pas**
   conforme (pas de `\b`, `\f` courts) : échappement propre implémenté.

## Découvertes critiques (à reporter dans l'implémentation réelle)

| # | Découverte | Conséquence |
|---|---|---|
| 1 | **`serde_json` sans la feature `float_roundtrip` analyse les flottants avec une erreur possible de 1 ULP** (constaté : `333333333.33333329` → …25 au lieu de …33, vecteur `values.json` en échec avant correction) | **OBLIGATOIRE** : `serde_json = { features = ["float_roundtrip"] }` partout où un JSON distant est parsé avant signature/vérification — à inscrire dans SEC-202/ADR-0004 et à tester par vecteur |
| 2 | ryu suffit pour les chiffres les plus courts ; aucune dépendance de formatage ECMAScript existante n'est nécessaire | Dépendances finales limitées à `serde_json` (+`float_roundtrip`) et `ryu` |
| 3 | `-0` sérialisé `0` ; entiers > 2^53 arrondis au double (sémantique JCS) | Le compilateur de politiques doit refuser les nombres non entiers/non sûrs dans les champs où ils n'ont pas de sens (dates en RFC3339, versions entières 32 bits) |

## Prochaines étapes (issues)

- ISS-010 : reporter la canonisation + la validation par schéma dans
  `vigile-policy` (avec `float_roundtrip`), tests rejoués depuis
  `tests/vectors/`.
- Ajouter le vecteur « 1 ULP » aux tests anti-régression du workspace.

## Limites

- Le fuzzing du parseur n'est pas couvert par ce spike (à faire en CI
  continue sur `vigile-policy`, cf. TEST_STRATEGY.md §C).
- `serde_json::Map` peut être ordonné (feature `preserve_order`) ou BTree :
  le tri est fait à l'écriture, indépendant — vérifié par tests.
