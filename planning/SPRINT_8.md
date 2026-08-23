# SPRINT 8 — Enforcement + approbations + portail (M7, phase 3)

> **Statut** : En cours — ISS-043/044 closes, ISS-042/032 restantes
> **Périmètre** : ISS-042..045 (M7) + ISS-032 (portail, différé de M4)
> **Pré-requis** : M1..M6 ✓, M5 ✓ (fapolicyd en mode audit validé VM).

## Objectif

**Basculer de l'observation à l'action** : les règles deviennent bloquantes
(`deny` au lieu de `deny_audit`), les utilisateurs peuvent demander des
exceptions via un workflow d'approbation, et des seuils de sécurité
arrêtent automatiquement un déploiement qui tourne mal. Le portail web
donne une interface humaine à tout ça.

## Ordre de travail

| Issue | Objet | Priorité |
|---|---|---|
| ISS-042 | Enforcement : le compilateur émet `deny` (pas `deny_audit`) quand le rollout est canary/rings/percentage ; liste protégées vérifiée (safety.protected_services toujours présentes dans les règles) | P0 |
| ISS-044 | `approval.rs` : `ApprovalRequest` (hash+chemin+justification obligatoire SEC-304), `ApprovalScope` (OneTime/Duration/Machine/Signer), `ApprovalDecision` avec **expiration locale** (SEC-303 : fonctionne sans serveur), `check()` contre un hash à un instant donné, `validate()` (non-signer DOIT expirer, hash SHA-256, approver non vide) | ✅ fait le 2026-08-23 — 7 tests (one-time actif→expiré, mauvais hash, durée, non-signer sans expiry = erreur, signer permanent OK, erreurs de validation) |
| ISS-043 | `thresholds.rs` : `DeploymentMonitor` avec `ThresholdConfig` (défaut : 100 déniels/agent/min, 3 échecs santé, 5 rollbacks/5min — DEC-09) ; `record_denial()` (fenêtre glissante par agent), `record_health()` (échecs consécutifs), `record_rollback()` (fenêtre) ; pause automatique + `PauseReason` typé ; `resume()` admin avec reset des compteurs ; événements pendant une pause → restent en pause | ✅ fait le 2026-08-23 — 7 tests (seuil déniels, agents séparés, échecs santé, reset sur succès, seuil rollbacks, pause/resume manuel, pause reste active) |
| ISS-045 | Notification GNOME | P1 (différé) |
| ISS-032 | Portail web minimal (TypeScript strict) | P0 (différé de M4) |

## Stratégie d'implémentation

### ISS-042 (enforcement)
Le compilateur a déjà `audit_mode()` qui retourne false pour
canary/rings/percentage. Ce qui manque :
- Vérification que `safety.protected_services` est non-vide en mode
  enforcement (le terminal `deny` doit toujours être précédé d'allows
  pour les services critiques)
- Test : une politique en mode enforcement produit `deny` (pas
  `deny_audit`)

### ISS-044 (approbations)
Types Rust pour les demandes et décisions :
```rust
struct ApprovalRequest { id, agent_id, executable_hash, path, reason, timestamp }
struct ApprovalDecision { request_id, scope (OneTime|Duration|Machine|Hash), approver, timestamp, expires_at }
```
API : POST /admin/v1/approvals (créer), GET /admin/v1/approvals (lister),
POST /admin/v1/approvals/:id/decision (décider).

### ISS-043 (seuils)
Compteur de déniels par fenêtre (ex: >100/minute → pause) :
```rust
struct DenialThreshold { window_secs: u64, max_denials: u64 }
struct DeploymentMonitor { denial_count, paused: bool }
```

### Portail (ISS-032)
Minimum viable : React + TypeScript strict + Vite.
Pages : login (token), agents (liste), policies (liste), audit (journal).
Pas de CDN externe, CSP stricte.
