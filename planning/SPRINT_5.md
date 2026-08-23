# SPRINT 5 — Serveur HTTP + API (M4)

> **Statut** : **Terminé** (M4 complet) — 2026-08-23
> **Périmètre** : issues ISS-030 à ISS-034 (`planning/BACKLOG.md` §M4)
> **Pré-requis** : M1 ✓, M2 ✓, M3 ✓ (compilateur, règles validées
> fapolicyd-cli) ; PKI + enveloppe + registre persistant disponibles.

## Objectif

Le **point d'entrée** : un serveur HTTP avec mTLS agent qui accepte les
enrôlements, sert les politiques compilées, collecte les heartbeats et
journalise tout. C'est la première brique visible de l'extérieur.

## Décision d'architecture (ADR-0011 à créer)

**Parseur HTTP/1.1 strict écrit à la main** (pas de framework) :

- L'agent est NOTRE code (les deux bouts sont contrôlés) — pas besoin
  d'interoperabilité navigateur sur `/agent/v1/*`.
- Limites strictes : 16 KiB d'en-têtes, 16 MiB de corps, HTTP/1.1
  uniquement, GET et POST uniquement.
- Tout ce qui n'est pas attendu est **rejeté** (405/400/413/431),
  jamais interprété.
- La surface du parseur est **fuzzée** en CI (TEST_STRATEGY §C).

L'API admin (`/admin/v1/*`) et le portail web (ISS-032) arriveront dans
un second temps avec une évaluation de framework dédiée (DEC-06) —
ils font face à des navigateurs, pas à notre agent.

## Ordre de travail et avancement

| Issue | Objet | État |
|---|---|---|
| ISS-030 | `vigile-server` : parseur HTTP/1.1 **strict** (HTTP/1.1 seul, GET/POST seuls, 16 KiB headers, 16 MiB body, Transfer-Encoding → 501, version → 505) + routes `/agent/v1` (enroll avec token+CSR base64+nonce initial, heartbeat, policy) + extraction CN depuis le certificat client DER (walk ASN.1 minimal) | ✅ fait le 2026-08-23 — 13 tests d'intégration (10 hostiles/négatifs, 3 enrôlement complet incl. rejeu et expiration) |
| ISS-031 | `auth.rs` (TokenAuth : jetons porteurs par rôle, hiérarchie Viewer < Admin < PlatformAdmin, validation) + routes `/admin/v1` (status, audit, audit/verify, enrollment-tokens) ; sans jeton → 401, mauvais jeton → 401, rôle insuffisant → 403 | ✅ fait le 2026-08-23 — 3 tests (hiérarchie RBAC, validation jetons, unicité) + 2 intégration (401 sans/avec mauvais jeton) |
| ISS-033 | `audit.rs` : AuditJournal avec **chaînage SHA-256** (hash = SHA-256(précédent \|\| entrée)), append-only, vérification complète en O(n), détection de falsification ET de suppression, `head_hash()` exposé ; journal persistant via la table `agents.security_events` (trigger append-only, ISS-016) — ce module fournit la couche chaînage | ✅ fait le 2026-08-23 — 7 tests (chaîne valide, falsification détectée, suppression détectée, journal vide, séquences monotones, performance 1000 entrées, vérification) |
| ISS-032 | Portail web (TypeScript strict) | reporté à M5 (DEC-06) |
| ISS-034 | CLI admin minimal | reporté (P1) |

## Critères de sortie

1. ✅ Un agent (test) s'enrôle, reçoit certificat + nonce (ISS-030, 13 tests).
2. ✅ Parseur HTTP hostile-safe (10 tests négatifs).
3. ✅ Admin API : 401 sans jeton, 401 mauvais jeton, hiérarchie RBAC (ISS-031).
4. ✅ Audit : chaînage SHA-256 vérifiable, falsification et suppression
   détectées (ISS-033, 7 tests dont perf 1000 entrées).
5. ⏳ Revue humaine avant M5 (phase 2 : fapolicyd audit).
