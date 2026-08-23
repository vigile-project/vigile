# SPRINT 5 — Serveur HTTP + API (M4)

> **Statut** : En cours — ISS-030 close, ISS-031/033 restantes
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
| ISS-031 | API `/admin/v1` minimale + RBAC initial (rôles viewer/admin) | à faire |
| ISS-033 | Journal d'audit serveur : append-only + chaînage SHA-256 | à faire |
| ISS-032 | Portail web (TypeScript strict) | reporté (DEC-06) |
| ISS-034 | CLI admin minimal | reporté (P1) |

## Critères de sortie

1. Un agent (binaire de test) s'enrôle, reçoit sa politique et envoie
   un heartbeat via mTLS sur le serveur en écoute.
2. Rejeu d'enveloppe rejeté ; agent sans certificat rejeté.
3. Parseur HTTP : requêtes hostiles (troncées, oversized, méthodes
   inconnues) rejetées proprement.
4. Revue humaine avant M5 (phase 2 : fapolicyd audit).
