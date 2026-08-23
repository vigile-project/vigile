# PROTOCOLE AGENT

> **Statut** : **Validé** — Phase 0 approuvée par décision humaine le 2026-08-21
> **Version** : 0.1 — 2026-08-21 — protocole `agent/v1` (contrat à figer avec OpenAPI + tests interversions)
> **Décisions ouvertes** : DEC-13 (périodes de polling adaptatif exactes), DEC-07 (bibliothèque TLS/PKI)
> **ADR liés** : ADR-0002, ADR-0003, ADR-0004, ADR-0005
> **Hypothèses clés** : architecture **pull** (aucune connexion entrante vers les machines) ; REST/JSON strict sur HTTPS+mTLS ; les schémas refusent les champs inconnus pour les messages critiques.

## 1. Principes

1. Seul l'agent initie les connexions (sortant 443) — compatible avec les
   environnements cloisonnés ; aucun port en écoute sur les machines.
2. Chaque message est : authentifié (mTLS), intégral (signatures au niveau
   politique + TLS), anti-rejoué (nonce+compteur+fraîcheur), borné (taille,
   débit), idempotent quand approprié (clés d'idempotence).
3. Contrats versionnés : `agent/v1` ; toute incompatibilité est refusée
   explicitement, jamais devinée.
4. Aucune donnée secrète dans les URLs ; pagination obligatoire sur toute
   collection ; timeouts et backoff exponentiel avec jitter.

## 2. Enrôlement (`agent/v1/enrollment`)

### Séquence

1. **Opérateur** crée un token d'enrôlement (portail/CLI) : JWS signé par le
   serveur, à usage unique, TTL court (proposition : ≤ 24 h), lié au tenant
   et optionnellement à un groupe cible.
2. **Installation** : le paquet RPM (signé, vérifié par dnf/rpm) installe
   l'agent **sans aucun secret** ; l'ancre de confiance (certificat CA du
   serveur) est un fichier root-owned installé par le paquet.
3. **Agent** : génère une paire Ed25519/ECDSA localement (option TPM 2.0 —
   clé non extractible, jamais obligatoire) ; produit une CSR avec empreinte
   machine (machine-id, DMI, EK pub si TPM).
4. **POST /agent/v1/enroll** {token signé, CSR, empreinte machine} sur TLS avec
   ancre locale (validation stricte ; pas de TOFU réseau). Amendé le
   2026-08-22 (ISS-012) : le token n'est **pas** un JWS mais une enveloppe
   `HEX(payload_json).HEX(signature_ed25519)` — claims à champs fixes
   (`serde_json` déterministe), même logique de signature qu'ADR-0004 ;
   vérifié côté serveur uniquement (preuve présentée par l'agent), schéma
   strict `deny_unknown_fields`, typ `vigile-enroll/v1`, consommation
   « à usage unique » **en dernier** (un contrôle en échec ne brûle jamais
   un token légitime).
5. **Serveur** : vérifie token (unique, non expiré, signature), vérifie
   non-réutilisation (table à usage unique), émet certificat client (durée
   proposée : 90 j, renouvellement automatique à T-30 j), enregistre l'agent
   (inventaire + groupe par défaut).
6. **Réponse** : certificat client + configuration initiale signée + identité
   `agent_id` (UUID).
7. **Renouvellement** : mTLS avec le certificat courant ; pas de
   ré-enrôlement implicite.
8. **Ré-enrôlement** : uniquement sur décision admin explicite (nouveau
   token) — jamais automatique.

### Propriétés de sécurité visées (à prouver par tests)

| Scénario hostile | Comportement attendu |
|---|---|
| Token intercepté et rejoué | Refus (usage unique) + événement de sécurité |
| DNS compromis | Échec de validation TLS (ancre locale ≠ DNS) |
| Proxy TLS hostile (MITM) | Refus (chaîne jusqu'à l'ancre locale) |
| Image clonée avec certificat | Quarantaine au premier contact (doublon) |
| Heure locale incorrecte | Enrôlement refusé si hors bornes de dérive ; renouvellement protégé par chevauchement de validité |
| Agent contactant un ancien serveur | Refus (ancre locale + versions de métadonnées) |

## 3. Enveloppe de message (agent → serveur)

```json
{
  "protocol": "agent/v1",
  "agent_id": "uuid",
  "sequence": 48152,          // compteur monotone par agent
  "server_nonce": "…",        // obtenu au heartbeat précédent
  "timestamp": "RFC3339",
  "request_id": "uuid",       // idempotence
  "kind": "events|heartbeat|result|approval_request",
  "body": { }
}
```

- `sequence` régressif ou `server_nonce` inconnu → rejet + alerte.
- Dérive horaire tolérée bornée (proposition : ± 10 min ; DEC-09) au-delà de
  laquelle les messages sont rejetés mais l'**enforcement local continue**.
- Réponses serveur : même discipline (idempotence, pagination, champs
  inconnus rejetés sur les messages critiques).

## 4. Points de terminaison (agent)

| Route | Sens | Objet |
|---|---|---|
| `POST /agent/v1/enroll` | → | Enrôlement (§2) |
| `POST /agent/v1/heartbeat` | → | Vivacité, nonce suivant, état (backends, santé) |
| `GET /agent/v1/policy?stream=<group>&since=<version>` | ← | Enveloppe de politique signée + métadonnées TUF |
| `POST /agent/v1/policy/result` | → | Résultat de transaction (succès/échec/rollback + journaux) |
| `POST /agent/v1/events` | → | Lots d'événements (bornés, priorisés, agrégés) |
| `POST /agent/v1/approval-requests` | → | Demandes des utilisateurs (workflow bloqué) |
| `POST /agent/v1/inventory` | → | Diffs d'inventaire |
| `GET /agent/v1/config` | ← | Configuration signée (non critique) |

Erreurs : typées (`invalid_signature`, `stale_version`, `schema_mismatch`,
`rate_limited`, `revoked`, `audience_mismatch`…) avec sémantique documentée ;
le code `schema_mismatch` impose une mise à jour signée de l'agent, jamais
une interprétation à deviner.

## 5. Flux d'application (résumé)

Vérifications serveur (mTLS, signature, seuil, digest canonique, schéma,
audience, monotonicité, fraîcheur, version minimale, capacité locale) →
transaction locale via l'exécuteur (sauvegarde LKG → écriture temporaire →
validation native → remplacement atomique → rechargement → santé →
confirmation | rollback) → `policy/result`. Détail :
`FAILURE_MODES.md`, `POLICY_MODEL.md` §7.

## 6. IPC local agent ↔ exécuteur (`ipc/v1`)

- Socket Unix `/run/vigile/executor.sock` (mode 0660, `vigile:vigile-exec`),
  authentification par `SO_PEERCRED` (UID/GLS attendus), messages CBOR
  versionnés, schéma strict, tailles bornées (proposition : 16 Mo max),
  délai d'inactivité, profondeur de file maximale.
- **Catalogne d'actions (exhaustif en v1 — tout ajout = version majeure)** :

| Action | Paramètres (typés) | Effet |
|---|---|---|
| `Ping` | — | Vivacité |
| `GetState` | — | État, versions appliquées, santé backends |
| `StageArtifacts` | `bundle_hash`, `artifacts[]` (nom relatif **normalisé**, contenu, mode, propriétaire, contexte SELinux) | Écriture en zone temporaire sécurisée (O_NOFOLLOW, fsync, perms min.) |
| `ValidateArtifacts` | `backend`, `tool` | Validation native (ex. `fapolicyd --check` — commande fixe, pas de shell) |
| `Commit` | `bundle_hash` | Remplacement atomique + rechargement backend + retour santé |
| `Rollback` | `to: last_known_good` | Restauration LKG (jamais de version arbitraire) |
| `HealthCheck` | `suite: standard` | Suite de santé standardisée (SEC-802) |
| `AckGeneration` | `generation` | Point de non-retour ( purge de la sauvegarde précédente) |

- Interdits par construction : commandes shell, chemins non normalisés,
  chemins hors périmètres gérés, contenu non vérifié (l'exécuteur
  re-vérifie le hash du bundle avant tout `StageArtifacts`/`Commit`),
  actions non listées ci-dessus, versions d'IPC non négociées.
- Chaque action produit une entrée de journal local (action, paramètres
  hashés, résultat, avant/après).

## 7. Contrats administratifs (portail/CLI)

REST/OpenAPI versionné (`/admin/v1`), mêmes exigences transverses :
pagination, idempotence, quotas, CSRF/CSP, cookies sécurisés, prévention
IDOR, tenant résolu serveur. Spécification OpenAPI générée depuis le code et
publiée à chaque release (tests de compatibilité interversions obligatoires).

## 8. Compatibilité interversions

- Le serveur supporte `agent/v1` uniquement au MVP ; toute évolution =
  `agent/v2` en double publication pendant N releases (politique DEC-14).
- Matrice de compatibilité testée en CI : {agent N, N-1} × {serveur N, N-1}.
- Une politique `min_agent_version` supérieure au binaire local → refus
  explicite + demande de mise à jour (jamais de devinette).

## 9. Limites, quotas, backoff

- Lots d'événements : ≤ 1 000 événements / ≤ 5 Mo ; priorités (sécurité >
  santé > télémétrie) ; files locales bornées (SEC-604).
- Polling adaptatif : proposition initiale 60 s nominal, 5 s après action
  admin, retour exponentiel en cas d'erreur (jitter obligatoire) — valeurs
  à calibrer (DEC-13) par tests de charge (100/1k/10k agents).
- Quotas serveur par agent et par tenant ; `429` avec `Retry-After`.

## 10. Critères d'acceptation du document

- [ ] OpenAPI `agent/v1` + `admin/v1` publiées avec le premier code.
- [ ] Chaque propriété §2 (tableau) a un test négatif dédié.
- [ ] Le catalogue IPC §6 est jugé complet pour le MVP par la revue.

## 11. Risques connus

- CBOR vs JSON pour l'IPC : choix technique à figer au spike (DEC-12) ;
  l'exigence « schéma strict + versionné » prime sur le format.
- Charge du polling à grande échelle : mitigé par adaptation + tests
  de performance (phase 10-11).
