# REVUE DE SÉCURITÉ — Phase 10 (ISS-090)

> **Date** : 2026-09-24
> **Périmètre** : workspace complet après ISS-087/088/089 (mTLS, signatures,
> persistance, enrôlement). Référentiel : `planning/SECURITY_REVIEW_CHECKLIST.md`.
> **Convention** : ✅ conforme (preuve citée) · ⚠️ justifié par écrit ·
> ❌ écart → issue tracée.

## A. Privilège minimal

- ✅ Aucun nouveau chemin privilégié sans analyse : `agent deploy` (root,
  écrit `/etc/fapolicyd/rules.d/`) documenté SPRINT_12 ; l'enrôlement
  s'exécute **sans root**.
- ✅ Catalogue d'actions fermé : `vigile-ipc` inchangé depuis la phase 3
  (8 actions typées, testé).
- ✅ `unsafe` : **un seul bloc** du workspace (`vigile-ipc/src/socket.rs:99`,
  SO_PEERCRED), isolé, justifié par commentaire dédié, couvert par tests.
- ✅ Unités systemd durcies existantes (`packaging/systemd/` + HARDENING.md) ;
  les nouveaux binaires n'ajoutent aucune unité.
- ⚠️ Jetons admin imprimés au démarrée : **lab only**, documenté dans le code
  (« in production these come from configuration/secrets management »).
  Écart → **ISS-090-1** : source de jetons configurable.
- ⚠️ Jetons passés par variables d'environnement ( jamais en argument de
  processus ) : `VIGILE_ENROLL_TOKEN`, `VIGILE_ADMIN_TOKEN` — conforme à la
  règle (pas d'argument, pas d'URL) ; l'exposition `/proc/*/environ` reste
  limitée au propriétaire du processus.

## B. Cryptographie et identité

- ✅ Règles servies : **signature Ed25519 vérifiée par l'agent avant tout
  écriture disque** (ISS-088, test négatif live : clé corrompue → REFUSED).
- ✅ Manifeste : SHA-256 des artefacts contrôlé côté agent (fail-closed).
- ✅ mTLS : certificats client **obligatoires** sur `/agent/v1/*`
  (401 + audit sinon) ; hiérarchie étrangère rejetée (test
  `foreign_hierarchy_is_not_trusted`).
- ✅ CRL fail-closed (ADR-0010) : `WebPkiClientVerifier` construit avec CRLs
  aux deux niveaux ; jamais `allow_unknown_revocation_status()`.
- ✅ Anti-rejeu enrôlement : jetons à usage unique (`InMemorySingleUseStore`,
  re-testé live : réutilisation → 401).
- ⚠️ Enrôlement bootstrap : la **première** connexion CA saute la
  vérification serveur (`DangerousNoVerify`) — authentifiée par jeton admin,
  documentée pour vérification d'empreinte hors bande en production.
  Écart → **ISS-090-2** : épinglage d'empreinte CA en option.
- ❌ Révocation agents réelle : CRLs vides générées à la volée ; le registre
  agents + vraies CRL ne sont pas câblés dans le verifier TLS.
  → **ISS-090-3**.

## C. Protocole et entrées

- ✅ Parseur HTTP strict maison : HTTP/1.1, GET/POST uniquement, 16 KiB
  en-têtes / 16 MiB corps, `Transfer-Encoding` refusé (`http.rs`, testé).
- ✅ Schéma politique validé (JSON Schema + `deny_unknown_fields` au niveau
  action ; limitation `serde(flatten)` documentée phase 2).
- ⚠️ Fuzz/DoS du parseur : limites en place mais non fuzzées.
  → reste couvert par **ISS-091**.
- ✅ Pas de shell dans l'agent (Command::new sans shell), staging sans
  symlink (O_NOFOLLOW côté executor), chemins absolus.

## D. Transactions et défaillance

- ✅ Executor : staging → validation native → **rename atomique** → LKG
  préservée (tests d'interruption phase 3, toujours verts).
- ✅ Persistance politique : écriture atomique tmp+rename (ISS-089).
- ⚠️ FAILURE_MODES §4 : à compléter avec les nouveaux modes
  (persistance corrompue → régénération + warning, déjà implémenté et
  testé live). → **ISS-090-4** (documentation).

## E. Auto-blocage

- ✅ Compilation : contrôle C8 anti-auto-blocage + simulation avant tout
  déploiement bloquant (phases 2-3, inchangées).
- ✅ Hygiène labo documentée (SPRINT_12) : jamais d'enforcing avec des
  règles non-Vigile dans `rules.d/`.

## F. Audit et confidentialité

- ✅ Toute action sensible journalisée : compilation, signature, enrôlement,
  émission de jeton, **refus anonyme** (`agent.policy-denied`), échecs.
- ✅ Aucun secret en journal : les jetons ne sont jamais loggés (affichés
  une fois au démarrage, hors journal d'audit).

## G. Tests

- ✅ 41 suites vertes workspace entier ; tests négatifs pour chaque garantie
  nouvelle (signature invalide, hash divergent, anonyme, hiérarchie
  étrangère, jeton réutilisé).
- ⚠️ Tests VM non rejoués cette phase (binaires serveur/agent testés en
  direct sur le poste labo). → à rejouer avec ISS-093.

## H. Chaîne logistique

- ✅ Aucune nouvelle dépendance externe ce sprint (rustls, dalek, sha2,
  signature, getrandom : déjà adoptées, `rust/DEPENDENCIES.md`).
- ✅ Lockfile : diffs expliqués dans les messages de commit.
- ✅ Aucun `curl | sh` ; les binaires sont construits localement.

## I. Documentation

- ✅ SPRINT_12 à jour ; ROADMAP cohérent.
- ⚠️ README : le portail est passé en https — vérifié sans référence
  périmée `http://…:8443`, mais le quick start ne mentionne pas le
  bootstrap CA navigateur. → **ISS-090-5** (mineur).

## Écarts tracés (entrée backlog)

| Issue | Objet | Priorité |
|---|---|---|
| ISS-090-1 | Jetons admin depuis config/secrets (pas générés/imprimés) | P1 |
| ISS-090-2 | Épinglage d'empreinte CA pour le bootstrap enrôlement | P2 |
| ISS-090-3 | Registre agents + CRL réelles câblées au verifier TLS | P1 |
| ISS-090-4 | FAILURE_MODES §4 : modes de persistance | P2 |
| ISS-090-5 | README : https + avertissement certificat labo | P3 |

## Conclusion

Aucun écart bloquant pour la qualification en mode **audit/observation**.
Les écarts P1 (090-1, 090-3) conditionnent le passage en **enforcing**
et doivent être résolus avant ISS-093 (RC).
