# FRONTIÈRES DE CONFIANCE

> **Statut** : **Validé** — Phase 0 approuvée par décision humaine le 2026-08-21
> **Version** : 0.1 — 2026-08-21
> **Décisions ouvertes** : DEC-11 (emplacement physique/logique du service de signature)
> **ADR liés** : ADR-0002, ADR-0003, ADR-0004, ADR-0005
> **Hypothèses clés** : une frontière est définie par les actifs de chaque côté et par les vérifications exigées à tout franchissement.

## TB-1 — Machine administrée ↔ Serveur central

| | |
|---|---|
| **Canal** | HTTPS sortant uniquement (pull), mTLS |
| **Traverse** | politiques signées, métadonnées TUF, événements, demandes d'approbation, heartbeats |
| **Menaces** | réseau hostile, DNS hostile, proxy TLS hostile, rejeu, downgrade, serveur imposteur, agent imposteur |
| **Vérifications côté agent** | chaîne TLS jusqu'à l'ancre locale (fichier root-owned, fournie par paquet signé) ; signature Ed25519 des enveloppes ; versions/générations monotones ; fraîcheur des métadonnées ; audience ; schéma strict |
| **Vérifications côté serveur** | certificat client agent (émis par la PKI), non révoqué, anti-rejeu (nonce+compteur), cohérence identité/inventaire machine |
| **Décision si échec** | rejet du message ; l'agent conserve sa dernière politique valide (fail-closed) |

## TB-2 — Agent non privilégié ↔ Exécuteur privilégié

| | |
|---|---|
| **Canal** | Socket Unix locale `/run/vigile/executor.sock` + `SO_PEERCRED` |
| **Traverse** | actions strictement typées (appliquer artefact vérifié, recharger backend, test de santé, rollback) |
| **Menaces** | agent compromis tentant une élévation, utilisateur local hostile, TOCTOU, symlink, tempête de requêtes |
| **Vérifications côté exécuteur** | UID/GLS de l'appelant ; version du protocole ; schéma strict des actions ; chemins normalisés et dans les périmètres gérés ; signature déjà vérifiée en amont (l'exécuteur re-vérifie le hash des artefacts) ; limites de débit/taille |
| **Décision si échec** | action refusée + journal local + événement de sécurité |

## TB-3 — Session utilisateur ↔ Composants de l'agent

| | |
|---|---|
| **Canal** | bus de session (notifications bureau) + IPC limité vers `vigile-userd` |
| **Traverse** | notifications, création de demandes d'approbation, statut |
| **Menaces** | usurpation d'interface, injection d'URI, exécution de contenu serveur, exfiltration via demandes |
| **Vérifications** | aucun contenu exécutable provenant du serveur ; URI validées ; `vigile-userd` sans privilège, sans accès aux clés ; requêtes de statut en lecture seule et non sensibles |

## TB-4 — Administrateur ↔ Portail/API

| | |
|---|---|
| **Canal** | HTTPS + session courte ; OIDC ; MFA (WebAuthn recommandé) |
| **Traverse** | toutes les opérations d'administration |
| **Menaces** | compte admin compromis, CSRF, XSS, SSRF, IDOR, confusion de tenant |
| **Vérifications** | RBAC serveur (jamais côté client), step-up avant opérations critiques, CSRF/CSP stricte, `tenant_id` résolu serveur, justification+ticket pour actions sensibles |

## TB-5 — Service de signature ↔ Reste du plan de contrôle

| | |
|---|---|
| **Canal** | appel explicite depuis le service de distribution/compilation ; pas de réseau entrant vers le signataire |
| **Traverse** | enveloppes politiques prêtes, métadonnées TUF |
| **Menaces** | vol de clé opérationnelle, signature d'artefacts non approuvés, journalisation falsifiée |
| **Vérifications** | quatre yeux (l'approbation précède et conditionne la signature), seuil k-of-n pour enforcement production, journal d'audit des signatures, identité du demandeur vérifiée |

## TB-6 — Serveur ↔ Base de données

| | |
|---|---|
| **Canal** | PostgreSQL, réseau restreint ou socket locale, identité dédiée |
| **Menaces** | base compromise, injection SQL, fuite inter-tenant |
| **Vérifications** | requêtes paramétrées uniquement, compte applicatif à privilèges minimaux, chiffrement au repos recommandé, audit append-only (droits SQL restreints) |

## TB-7 — Inter-tenant (différée mais dessinée)

| | |
|---|---|
| **Canal** | — (phase 11) |
| **Exigences dès le MVP** | `tenant_id` présent sur tout objet, résolu côté serveur, jamais confiance au client ; tests anti-fuite planifiés (`TEST_STRATEGY.md` §C) |

## TB-8 — CI/CD ↔ Dépôt ↔ Utilisateurs des paquets

| | |
|---|---|
| **Canal** | forge, registres de paquets signés, métadonnées TUF |
| **Menaces** | pipeline compromis, mainteneur malveillant, dépendance compromise, miroir hostile |
| **Vérifications** | branches protégées, revue obligatoire, commits signés, releases signées par humain, SBOM+provenance, vérification côté agent (signature avant installation) — détail `SUPPLY_CHAIN_SECURITY.md` |

## Matrice de propriétés par frontière

| Frontière | Authentification | Intégrité | Anti-rejeu | Confidentialité |
|---|---|---|---|---|
| TB-1 | mTLS + PKI dédiée | Signature Ed25519 + TUF | Nonce + compteur + fraîcheur | TLS |
| TB-2 | SO_PEERCRED (UID) | Hash d'artefacts + schéma | Idempotence + limites | Socket locale (permissions) |
| TB-3 | Bus session utilisateur | Schéma strict + URI validées | Limites de débit | Données non sensibles seulement |
| TB-4 | OIDC + MFA + session courte | CSRF tokens, CSP | Expiration session | TLS + cookies sécurisés |
| TB-5 | Identité mutuelle interne | Signature à seuil | Journal horodaté | Isolation réseau |
| TB-6 | Identité SQL minimale | Requêtes paramétrées | — | TLS/chiffrement au repos |
| TB-8 | Signatures + revue | SBOM/provenance | Tags immuables | — |

## Critères d'acceptation du document

- [ ] Chaque frontière liste ses vérifications et son comportement d'échec.
- [ ] Chaque flux d'`ARCHITECTURE.md` §4 passe par des frontières nommées.
- [ ] Aucun flux ne traverse une frontière sans mécanisme de vérification.

## Risques connus

- TB-2 est la frontière la plus critique (cible d'élévation locale) ; sa
  surface doit rester minuscule et être fuzzée (`TEST_STRATEGY.md` §C).
- TB-5 dépend de procédures humaines (quatre yeux) : à tester par exercice,
  pas seulement par code.
