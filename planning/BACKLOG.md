# BACKLOG PRIORISÉ ET ISSUES ATOMIQUES

> **Statut** : **Validé** — Phase 0 approuvée par décision humaine le 2026-08-21
> **Version** : 0.1 — 2026-08-21
> **Décisions ouvertes** : priorisation finale ; estimations indicatives (S ≤ 2 j, M ≤ 1 sem, L > 1 sem)
> **ADR liés** : tous
> **Hypothèses clés** : chaque issue est atomique, testée (définition of done commune), rattachable à une PR unique ; P0 = bloquant MVP, P1 = important MVP, P2 = suites.

**Définition of done commune** : code + tests unitaires + tests négatifs
pour les fonctions de sécurité + doc mise à jour + revue humaine + CI verte
(+ test VM si comportement système). Une issue de sécurité sans test négatif
n'est pas « done ».

> **Avancement (2026-08-22, sprint 2 ouvert)** : M0 **complet** (détail
> dans `planning/SPRINT_1.md`). Sprint 2 (M1) : prototype PKI validé (6/6),
> **ISS-011 close** (crate `vigile-pki`, DEC-07 tranchée, journal
> `rust/DEPENDENCIES.md`), **ISS-012 close** (enrôlement + 13 tests
> négatifs), **ISS-013 close** (rotation T-30 j, chevauchement, CRL
> expirée — fail-open rustls documenté), **ISS-014 close** (registre :
> clone/snapshot/rejeu, quarantaine collante + audit, 8 tests),
> **ISS-015 close** (enveloppe `agent/v1` : nonce à tour unique,
> horloge bornée ±10 min, séquence via registre, schéma strict — 11
> tests), **ISS-016 close** (`vigile-store` : migrations séparées par
> domaine, événements append-**par trigger**, `PgStore` jumeau persistant
> du registre, inventaire machines — **8/8 tests sur PostgreSQL 17 réel**
> via podman rootless). **M1 complet** : 59 tests workspace (clippy 0) +
> 8 tests PostgreSQL. **M2 ouvert (sprint 3)** : ISS-017 close
> (os-release + matrice de capacités embarquée, 9 tests), ISS-018 close
> (adaptateur rpm, 4 tests), ISS-020 close (ELF + shebang + `env -S`,
> 6 tests). 78 tests workspace verts. ISS-019/020/021/022 closes
> (exécutables + SHA-256 via `sha2` 0.11, journald + file bornée à
> priorités, diff incrémental + backoff à jitter) ; **M2 complet** :
> inventaire réel validé dans la VM Fedora 44 (`vigile-agent inventory`,
> 431/432 paquets signés rpm 6). 101 tests workspace verts, clippy 0.
> **M3 complet** (sprint 4, 2026-08-23) : ISS-023..026 closes —
> compilateur déterministe (règles validées par fapolicyd-cli natif dans
> la VM), contradictions C1..C7, non-applicables déclarés, simulateur
> first-match + diff. 122 tests workspace verts, clippy 0. **M4 complet** (sprint 5, 2026-08-23) : ISS-030 close (serveur
HTTP/mTLS + 13 tests), ISS-031 close (admin API + RBAC + jetons
porteurs), ISS-033 close (audit chaîné SHA-256 + falsification
détectée + 7 tests). 157 tests workspace verts, clippy 0. Prochain
jalon : **M5** (phase 2 — fapolicyd audit via l'agent).

> **Avancement (2026-08-21, soir)** : M0 **complet** — ISS-001/002/003
> faites ; spikes ISS-006 (PKI/TLS, GO conditionnel), ISS-007 (JCS, GO —
> `float_roundtrip` obligatoire), ISS-008 (fapolicyd 2.0-F44, GO avec
> périmètre explicite), ISS-009 (TUF → `tough` 0.24.0, GO) terminés —
> rapports dans `docs/spikes/` ; ISS-010 faite (schéma + canonisation +
> validation stricte intégrés à `vigile-policy`, 15 suites de tests
> vertes) ; ISS-004 close (canal + clé OpenPGP publiés dans
> `docs/SECURITY.md` + **GitHub Private Vulnerability Reporting activé le
> 2026-08-22** sur `github.com/vigile-project/vigile`, vérifié) ; ISS-005
> faite (harnais `tests/vm/` : image F44 vérifiée GPG+SHA-256, smoke
> complet avec fapolicyd 2.0-1.fc44 installé et jamais démarré,
> `--check-rules` validé). **Sprint 1 terminé.**

## M0 — Bootstrap (sprint 1)

| ID | Issue | P | Est. | Dépend de |
|---|---|---|---|---|
| ISS-001 | Créer l'ossature du dépôt (REPOSITORY_LAYOUT) + workspace cargo + `web/` vide + licences (après DEC-02) | P0 | S | DEC-02, DEC-03 |
| ISS-002 | CI minimale : fmt, clippy -D warnings, tests, cargo-deny/audit, SAST, analyse secrets | P0 | S | ISS-001 |
| ISS-003 | Templates de PR (volet sécurité, attribution IA, check-list dépendances) + guide CONTRIBUTING appliqué | P0 | S | ISS-001 |
| ISS-004 | Publication des contacts et clé de SECURITY.md + tableau versions | P0 | S | DEC-03 |
| ISS-005 | Harnais VM QEMU/libvirt : provision Fedora 44/43 WS+Server, exécution de scénarios (DEC-17) | P0 | M | ISS-001 |
| ISS-006 | Spike : bibliothèques TLS/PKI (rustls etc.), émission/rotation de certificats, limitations (DEC-07) | P0 | M | — |
| ISS-007 | Spike : canonisation JSON RFC 8785 en Rust + vecteurs de test officiels | P0 | S | — |
| ISS-008 | Spike : lecture/parsing des règles fapolicyd + capacités réelles (memfd, namespaces — NON VÉRIFIÉ) | P0 | M | — |
| ISS-009 | Spike : implémentations TUF en Rust, état de maintenance (ADR-0005) | P0 | M | — |
| ISS-010 | JSON Schema `policy/v0` + crate de validation (rejet champs inconnus) | P0 | S | ISS-007 |

## M1 — Identité et enrôlement

| ID | Issue | P | Est. | Dépend de |
|---|---|---|---|---|
| ISS-011 | PKI : AC racine/intermédiaire, émission certificats agents, profils contraints | P0 | M | ISS-006 |
| ISS-012 | Protocole d'enrôlement : token JWS à usage unique + CSR + émission + tests négatifs (rejeu, TTL, non signé) | P0 | M | ISS-011 |
| ISS-013 | Rotation automatique + chevauchement de validité + test révocation | P0 | M | ISS-012 |
| ISS-014 | Détection de clonage/quarantaine + tests (clone VM, snapshot ancien) | P0 | M | ISS-012 |
| ISS-015 | Enveloppe de message anti-rejeu (nonce+compteur+fraîcheur) + tests bornes d'horloge | P0 | M | ISS-012 |
| ISS-016 | Registre agents + inventaire machines côté serveur (schémas ADR-0007) | P0 | M | ISS-011 |

## M2 — Inventaire

| ID | Issue | P | Est. | Dépend de |
|---|---|---|---|---|
| ISS-017 | Détection distribution/capacités (matrice signée chargée localement) | P0 | M | ISS-010, ISS-016 |
| ISS-018 | Adaptateur dnf/rpm : paquets + provenance + signataire | P0 | M | ISS-017 |
| ISS-019 | Inventaire des exécutables hors paquets + SHA-256 (chemins standards + $HOME) | P0 | M | ISS-017 |
| ISS-020 | Détection interpréteurs/scripts/shebang + exécutions indirectes | P0 | M | ISS-019 |
| ISS-021 | Collecte journald/audit (refus fapolicyd, santé) + files bornées priorisées | P0 | M | ISS-019 |
| ISS-022 | Envoi différé/incremental + quotas + backoff jitter | P0 | S | ISS-021 |

## M3 — Politique : schéma, compilateur, signature

| ID | Issue | P | Est. | Dépend de |
|---|---|---|---|---|
| ISS-023 | Compilateur IR→fapolicyd.rules + entrées de confiance, déterminisme + hash d'artefacts | P0 | L | ISS-010, ISS-008 |
| ISS-024 | Détection de contradictions (POLICY_MODEL §3.3) + tests table | P0 | M | ISS-023 |
| ISS-025 | Déclaration des champs non applicables par backend (manifeste d'artefacts) + tests négatifs | P0 | M | ISS-023 |
| ISS-026 | Diff + simulation (corpus d'événements) rendus côté portail/CLI | P0 | M | ISS-023 |
| ISS-027 | Enveloppe signée (Ed25519, seuils, génération) + vérification locale complète ordre §7 | P0 | M | ISS-007, ISS-012 |
| ISS-028 | Service `vigile-signer` isolé + journal des signatures | P0 | M | ISS-027 |
| ISS-029 | Chaîne TUF opérationnelle (métadonnées, expiration, tests rollback/freeze) | P0 | L | ISS-009 |

## M4 — Serveur + portail (minimal)

| ID | Issue | P | Est. | Dépend de |
|---|---|---|---|---|
| ISS-030 | API `/agent/v1/*` complète + OpenAPI publiée + tests interversions | P0 | L | ISS-015, ISS-016 |
| ISS-031 | API `/admin/v1/*` + RBAC (rôles §8) + tests matriciels 403 | P0 | L | ISS-030 |
| ISS-032 | Portail : login MFA/OIDC, groupes, inventaire, politiques (vue), déploiements | P0 | L | ISS-031, DEC-06 |
| ISS-033 | Journal d'audit append-only + chaînage + export + tests d'altération | P0 | M | ISS-031 |
| ISS-034 | CLI minimal (statut agents, groupes, diff de politiques) | P1 | M | ISS-031 |

## M5 — fapolicyd audit (phase 2)

| ID | Issue | P | Est. | Dépend de |
|---|---|---|---|---|
| ISS-035 | Application des artefacts fapolicyd en mode audit-only via exécuteur + transaction complète | P0 | L | ISS-023, ISS-040 |
| ISS-036 | Collecte des refus + corrélation inventaire + tableau de bord « qu'aurait-on bloqué » | P0 | M | ISS-035 |
| ISS-037 | Apprentissage assisté : recommandations de règles (jamais d'activation auto) | P1 | M | ISS-036 |

## M6 — Exécuteur et transactions (pré-requis M5/M7)

| ID | Issue | P | Est. | Dépend de |
|---|---|---|---|---|
| ISS-038 | IPC `ipc/v1` : socket, SO_PEERCRED, CBOR typé, catalogue fermé, fuzzing | P0 | L | ISS-010 |
| ISS-039 | Actions : Stage/Validate/Commit avec chemins normalisés, O_NOFOLLOW, fsync, perms | P0 | L | ISS-038 |
| ISS-040 | Transaction complète + LKG + rollback + tests d'interruption à chaque étape | P0 | L | ISS-039 |
| ISS-041 | Unités systemd durcies (agent + exécuteur) + seccomp justifié + audit capabilities | P0 | M | ISS-038 |

## M7 — Enforcement, canary, approbations (phase 3)

| ID | Issue | P | Est. | Dépend de |
|---|---|---|---|---|
| ISS-042 | Activation enforcement par groupe/anneau uniquement + listes protégées (SEC-801) | P0 | L | ISS-035, ISS-040 |
| ISS-043 | Seuils automatiques d'arrêt + pause (SEC-803) + tests de seuil | P0 | M | ISS-042 |
| ISS-044 | Workflow approbation : demandes, décisions bornées, expiration locale (SEC-303) | P0 | L | ISS-030, ISS-027 |
| ISS-045 | Notification GNOME (`vigile-userd`) : workflow bloqué + statut + prototype portails | P0 | M | ISS-044 |
| ISS-046 | Tests catégorie D (auto-blocage) automatisés en VM — gate anneaux | P0 | L | ISS-042, ISS-005 |
| ISS-047 | Break-glass : implémentation conforme RECOVERY_AND_BREAK_GLASS + T-BG-01..05 | P0 | M | ISS-040 |

## M8 — Packaging et release

| ID | Issue | P | Est. | Dépend de |
|---|---|---|---|---|
| ISS-048 | RPM signé + unités + ancre de confiance + test installation propre | P0 | M | ISS-041 |
| ISS-049 | Dépôt signé + métadonnées TUF publiées + procédure release signée humain | P0 | M | ISS-029, ISS-048 |
| ISS-050 | SBOM + provenance + test de reproductibilité RPM | P0 | M | ISS-048 |
| ISS-051 | Kit de récupération signé + runbook 1 page + exercice labo | P1 | S | ISS-047 |

## Hors MVP (créées aux phases 4+) — pré-inscrites

ISS-052..059 : USBGuard (phase 4) ; ISS-060..066 : Debian/Ubuntu+AppArmor
(phase 5) ; ISS-067..072 : SELinux (phase 6) ; ISS-073..076 : réseau (phase
7) ; ISS-077..080 : élévation (phase 8) ; ISS-081..086 : NixOS (phase 9) ;
ISS-087..093 : qualification production (phase 10). Détail à figer à l'entrée
de chaque phase (les documents `docs/` fixent déjà les exigences).

## Risques bloquants (extrait — voir RISKS.md)

- DEC-02/03 non tranchées → ISS-001/004 bloqués.
- Résultats des spikes ISS-006/008/009 conditionnent ISS-011/023/029.

## Critères d'acceptation

- [ ] Backlog validé (priorités, périmètre sprint 1 = M0).
- [ ] Toute exigence SEC/FR « Must » reliée à au moins une issue.
