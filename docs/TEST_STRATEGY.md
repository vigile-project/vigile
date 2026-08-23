# STRATÉGIE DE TESTS

> **Statut** : **Validé** — Phase 0 approuvée par décision humaine le 2026-08-21
> **Version** : 0.1 — 2026-08-21
> **Décisions ouvertes** : DEC-17 (infrastructure CI/VM : Testing Farm, self-hosted, forge), DEC-18 (budgets de performance définitifs)
> **ADR liés** : ADR-0001, ADR-0007, ADR-0009
> **Hypothèses clés** : aucun code privilégié sans tests négatifs (règle §1 du cahier des charges) ; les budgets ci-dessous sont des **propositions à valider avant optimisation** (§22-F).

## 1. Niveaux et gates

| Niveau | Où | Gate |
|---|---|---|
| Lint/format/audit deps | CI, chaque PR | bloquant (clippy -D warnings, rustfmt, cargo-audit/deny) |
| Unitaires + property-based | CI, chaque PR | bloquant, couverture des modules sécurité ≥ 90 % (proposition) |
| Intégration (VM) | CI labo (VM éphémères) | bloquant pour merge vers main |
| Sécurité/négatifs | CI + revue | bloquant par fonctionnalité (SEC ↔ tests) |
| Auto-blocage (catégorie D) | labo, avant chaque activation d'anneau | bloquant par anneau |
| Chaos (E) | labo périodique + avant releases | bloquant avant release |
| Performance (F) | labo, par jalon | budgets §6 |

## 2. A — Tests unitaires (extraits obligatoires)

Parseurs (politiques, IPC, journaux) ; validation de schémas ; compilateur
(déterminisme, contradictions) ; autorisations (RBAC matriciel) ; signatures
(canonisation RFC 8785, seuils) ; expiration ; anti-rejeu ; normalisation
des chemins (table de cas : `..`, symlinks, doubles slashs, unicode) ;
rollback. Property-based (ex. `proptest`) sur : canonisation, normalisation,
compilateur (entrées générées ⇒ jamais de panic), machine d'états des
transactions.

## 3. B — Intégration par distribution

| Plateforme | Harnais | Couverture MVP |
|---|---|---|
| Fedora WS 44/43 (GNOME/Wayland) | VM QEMU/libvirt pilotées (cloud-init + scripts de test) | enrôlement, inventaire, fapolicyd audit, enforcement, rollback, notifications |
| Fedora Server 44/43 | idem, headless | idem sans GNOME |
| RHEL-compat / Debian / Ubuntu / NixOS | idem + NixOS VM tests (`nixosTests`) | phases 5/9 |

Chaque scénario d'intégration est rejoué : x86_64 + aarch64 (si disponible).

## 4. C — Tests de sécurité (mapping THREAT_MODEL)

Séries nommées : `T-SRV-*` (serveur hostile : politiques non signées, mal
signées, anciennes, seuil insuffisant, mauvaise audience), `T-AGENT-*`
(agent hostile, rejeu, horloge, downgrade, révocation), `T-LOCAL-*` (root :
kill agent, remplacement binaire ; non-root : flood, path traversal,
symlink, TOCTOU), `T-BYPASS-*` (interpréteurs : `bash -c`, stdin,
`python -`, env détournée ; memfd ; LD_PRELOAD ; bibliotheques), `T-TEN-*`
(IDOR, confusion tenant — dès le MVP), `T-UPD-*` (RPM altéré, dépôt hostile,
métadonnées TUF périmées/rejouées), `T-BG-*` (break-glass : TTL, journal,
alerte, révocation), `T-CLONE-*` (clonage, snapshot ancien), fuzzing continu
des parseurs (politique, IPC, journaux — corpus + générateur), disque plein,
interruption d'écriture à chaque étape de transaction, rollback impossible,
corruption locale multi-niveaux.

## 5. D — Tests d'auto-blocage (gate par anneau)

Scénarios exécutés en VM **avant chaque activation d'un nouvel anneau** :
boot complet ; login GNOME ; SSH (si déclaré critique) ; `dnf update` ;
résolution DNS ; renouvellement de certificats ; redémarrage de l'agent ;
rollback ; 72 h hors ligne (proposition initiale) ; récupération locale
(runbook). Échec d'un seul scénario = anneau bloqué.

## 6. E — Chaos et F — Performance (budgets proposés)

Chaos : coupure réseau/DNS, kill PostgreSQL, kill serveur, changement
d'heure (± bornes), suppression de certificat, corruption de cache, manque
mémoire, saturation d'événements (FM-01..18 rejoués).

| Budget (proposition DEC-18) | Cible |
|---|---|
| CPU agent en régime établi | < 1 % moyen |
| Mémoire résidente agent + exécuteur | < 100 Mo |
| Impact au boot | < 2 s |
| Latence d'application d'une politique | < 5 s |
| Latence overhead par exécution surveillée | mesurée, publiée, sans régression > 10 % entre releases |
| Parcs simulés | 100 / 1 000 / 10 000 agents (harnais de charge dédié) |
| Pics d'approbation, distribution simultanée, volume d'audit | scénarios dédiés, seuils définis avec SLO |

## 7. Organisation CI/CD

- Runners **éphémères** jetables ; permissions minimales ; secrets courts.
- Matrice interversions obligatoire : {agent N, N-1} × {serveur N, N-1}.
- Nuit : fuzzing prolongé + chaos + build de reproductibilité.
- Artefacts de test archivés (journaux VM) pour analyse post-échec.

## 8. Critères d'acceptation du document

- [ ] Chaque exigence SEC a au moins un test nommé (table de traçabilité
      SEC ↔ tests, générée en CI).
- [ ] Harnais VM choisi et opérationnel (décision DEC-17).
- [ ] Budgets §6 validés (humain) et convertis en jobs de performance.

## 9. Risques connus

- Coût des VM multi-distributions : priorisation Fedora (MVP), nightly pour
  les autres.
- Fuzzing continu coûteux : commencer par les parseurs critiques uniquement.
- Les tests d'auto-blocage ne couvrent que des scénarios connus ; la
  simulation §12 du cahier des charges reste la défense principale.
