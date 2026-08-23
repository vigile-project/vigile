# ARCHITECTURE

> **Statut** : **Validé** — Phase 0 approuvée par décision humaine le 2026-08-21
> **Version** : 0.1 — 2026-08-21
> **Décisions ouvertes** : DEC-06 (framework web), DEC-07 (bibliothèques crypto/CA), DEC-10 (monolith modulaire vs microservices au MVP)
> **ADR liés** : ADR-0001, ADR-0002, ADR-0003, ADR-0004, ADR-0005, ADR-0007
> **Hypothèses clés** : MVP mono-serveur sans Kubernetes ; les frontières internes du serveur sont d'abord des frontières de modules (crates), préservées pour une extraction ultérieure en services.

## 1. Vue d'ensemble

```mermaid
flowchart LR
  subgraph CP [Control plane — vigile-server]
    API[API administrative REST]
    AGW[Endpoints agents\n(mTLS, pull)]
    IDE[Service identité\n+ PKI agents]
    POL[Moteur de politiques\n+ compilateur]
    REG[Registre agents\n+ inventaire]
    APP[Service approbation]
    DIST[Service distribution\n(anneaux, canari)]
    AUD[Journal d'audit]
    SIG[Service de signature\n(séparé, accès restreint)]
    WEB[Portail web]
    CLI[CLI admin]
  end
  DB[(PostgreSQL)]
  subgraph HOST [Machine administrée]
    A[vigile-agent\n(non privilégié)]
    E[vigile-executor\n(privilégié, minimal)]
    U[vigile-userd\n(session utilisateur)]
    B[Backends :\nfapolicyd · SELinux · nftables ·\nUSBGuard · journald/audit]
  end
  CLI --> API
  WEB --> API
  A -- "HTTPS mTLS\n(pull + événements)" --> AGW
  A -- "IPC local étroit\n(actions typées)" --> E
  E --> B
  B --> A
  U -- "bus session\n(notifications)" --> A
  CP --> DB
  SIG -. "signe politiques\n+ métadonnées" .-> DIST
```

## 2. Plan de contrôle (`vigile-server`)

| Composant | Rôle | MVP |
|---|---|---|
| API administrative (REST/OpenAPI) | Contrat versionné pour portail et CLI | Oui |
| Endpoints agents | Pull de politiques, envoi d'événements, heartbeat (mTLS) | Oui |
| Service identité / PKI | Enrôlement, émission, rotation, révocation des certificats agents ; identités admin via OIDC/MFA | Oui (PKI intégrée, racine hors ligne) |
| Moteur + compilateur de politiques | IR → artefacts par backend, validation, contradiction, simulation, diff, hash | Oui |
| Registre + inventaires | Agents, machines, applications, groupes | Oui |
| Service d'approbation | Demandes, décisions bornées, expiration | Oui |
| Service de distribution | Anneaux, canary, pourcentages, pause/annulation, seuils d'arrêt | Oui |
| Journal d'audit | Append-only, chaînage, export | Oui |
| RBAC/ABAC | Rôles §8, quatre yeux, tenant_id systématique | Oui (ABAC plus tard) |
| File d'événements | Buffer persistant avant traitement | Oui (tables PG) |
| Service de signature | Signe enveloppes politiques et métadonnées ; **isolé**, clés opératoires, seuils | Oui (binaire séparé, machine restreinte) |
| Portail web | UI TypeScript strict | Oui (minimal) |
| CLI admin | Mêmes API | Oui (minimal) |
| Gestion tenants/organisations | Isolation multi-tenant | Non (champ présent partout, activation phase 11) |
| Télémétrie volumineuse | Stockage dédié | Partiel (partitionnement PG ; store dédié plus tard) |

**Choix MVP** : un binaire serveur unique (crates séparées : `api`, `policy`,
`identity`, `approval`, `distribution`, `audit`, `store`) + un binaire
`vigile-signer` séparé. Les frontières sont des traits Rust et des contrats
internes, pour permettre une extraction en services sans réécriture (DEC-10).
Développement en conteneurs rootless ; production : VM/nœud unique sans
Kubernetes obligatoire.

## 3. Plan de données — machine administrée

| Composant | Rôle | Privilèges |
|---|---|---|
| `vigile-agent` (service système) | Synchronisation, collecte, compilation locale des artefacts reçus, orchestration des transactions, files d'événements | Aucun (utilisateur dédié `vigile`) |
| `vigile-executor` (service système) | Application **d'actions strictement typées** : écriture d'artefacts, rechargement de backends, tests de santé, rollback | root minimal, capabilities réduites, seccomp, systemd durci |
| `vigile-userd` (service utilisateur) | Notifications GNOME, création de demandes, statut | Aucun (session utilisateur) |
| Adaptateurs distribution | dnf/rpm (MVP), apt/dpkg (ph.5), nix (ph.9) | Via l'exécuteur uniquement |
| Adaptateurs sécurité | fapolicyd (MVP), SELinux (ph.6), AppArmor (ph.5), nftables (ph.7), USBGuard (ph.4) | Via l'exécuteur uniquement |

L'exécuteur n'expose **aucune** action générique : pas de commande shell, pas
de chemin arbitraire, pas de configuration non signée. Le catalogue complet
des actions est spécifié dans `AGENT_PROTOCOL.md` §6.

### Emplacements (MVP Fedora)

| Chemin | Contenu | Propriétaire |
|---|---|---|
| `/etc/vigile/` | Configuration (signée), ancre de confiance (certificat CA serveur), unités | root:root 0644/0755 |
| `/var/lib/vigile/` | Identité agent (clé+cert), LKG, cache de politiques, journal de transactions, files d'événements | `vigile` / root selon sous-rép. |
| `/run/vigile/` | Socket IPC (agent↔exécuteur), PID, état runtime | root:vigile 0750 |
| `/var/lib/fapolicyd/` etc. | Artefacts générés pour les backends (écrits par l'exécuteur uniquement) | root |

## 4. Flux principaux

### 4.1 Enrôlement (détail dans AGENT_PROTOCOL.md)

1. Un opérateur crée un token d'enrôlement à usage unique (portail/CLI).
2. Le paquet RPM installe l'agent **sans secret** ; l'ancre de confiance vient
   de la signature du paquet et d'un fichier CA root owned-by-root.
3. L'agent génère sa paire de clés localement (option TPM), transmet CSR+token.
4. Le serveur valide le token (unique, TTL), émet un certificat client, enregistre
   l'empreinte machine (machine-id, DMI, EK pub si TPM).
5. Rejeu de token ou doublon → refus + événement de sécurité (quarantaine).

### 4.2 Synchronisation de politique

1. L'agent interroge (pull, mTLS) : « politique pour groupe G, version > V ».
2. Le serveur répond : enveloppe signée + métadonnées TUF.
3. L'agent vérifie signature, schéma, audience, version/génération monotones,
   fraîcheur, version minimale d'agent.
4. Transaction locale (§11 du cahier des charges) via l'exécuteur : simulation,
   sauvegarde LKG, écriture temporaire, validation native, remplacement
   atomique, rechargement, santé, confirmation — sinon rollback.
5. Résultat envoyé au serveur (succès/échec/rollback) + audit.

### 4.3 Application bloquée → approbation

Interception du refus (fapolicyd/journal) → métadonnées minimales →
notification GNOME (`vigile-userd`) → demande facultative → serveur (analyse
de provenance : paquet, hash, signataire) → décision humaine bornée →
politique d'exception signée distribuée par le canal normal → relance.

## 5. Topologies

| Topologie | Usage | Notes |
|---|---|---|
| Labo : 1 serveur VM + N VM clientes | Développement, anneaux 1-3 | Repro via scripts/libvirt |
| Production petite échelle : 1 serveur (+ sauvegardes) | ≤ quelques centaines d'agents | MVP cible |
| Production critique : serveur + réplique lecture, signature isolée | Avant qualification « production » | DR testé |
| HA complète | Phase 11 | Hors MVP |

## 6. Durcissement par composant

- **vigile-executor** : `NoNewPrivileges=yes` (sauf nécessité prouvée),
  `ProtectSystem=strict` + `ReadWritePaths` minimaux, `ProtectHome=read`,
  `PrivateTmp=yes`, `CapabilityBoundingSet=` minimal, `SystemCallFilter=`
  testé, socket IPC avec `SO_PEERCRED`, limites de tailles/délais, audit de
  chaque action.
- **vigile-agent** : utilisateur dédié sans shell, `ProtectSystem=full`,
  accès réseau uniquement au serveur (sortant), files bornées.
- **vigile-server** : exécution dédiée, TLS terminé en interne, secrets via
  fichiers/environnement restreints (jamais en URL), `Content-Security-Policy`
  stricte sur le portail, cookies sécurisés.
- **vigile-signer** : machine/volume isolé, pas de réseau entrant, opéré
  manuellement, journalisation des signatures vers le serveur.

## 7. Interfaces et contrats

| Interface | Contrat | Document |
|---|---|---|
| Agent ↔ serveur | REST/HTTPS mTLS versionné, schémas stricts | `AGENT_PROTOCOL.md` |
| Portail/CLI ↔ serveur | REST/OpenAPI versionné | `AGENT_PROTOCOL.md` §8 |
| Agent ↔ exécuteur | IPC local, actions typées CBOR versionnées | `AGENT_PROTOCOL.md` §6 |
| Modèle de politique | Schéma versionné + canonisation + signature | `POLICY_MODEL.md` |
| Compilation | IR → artefacts déterministes par backend | `POLICY_MODEL.md` §5 |
| Mises à jour | Métadonnées TUF + paquets signés | `UPDATE_SECURITY.md` |

## 8. Critères d'acceptation du document

- [ ] Chaque composant du cahier des charges §4 est placé (ou explicitement
      différé avec phase).
- [ ] Chaque flux traverse des frontières décrites dans TRUST_BOUNDARIES.md.
- [ ] La séparation privilégié/non privilégié est claire et minimale.
- [ ] La topologie MVP est déployable sans Kubernetes.

## 9. Risques connus

- Monolithe MVP : risque de fusion accidentelle de responsabilités ;
  mitigation : crates séparées + revue des dépendances internes (deny des
  couches basses vers hautes).
- PKI intégrée : doit rester minuscule et testée ; alternative externe
  (smallstep etc.) à évaluer en spike (DEC-07) — NON VÉRIFIÉ jusqu'au spike.
- Le compilateur multi-backends est le point de complexité maximal ;
  mitigation : MVP limité à fapolicyd + déclaration explicite des cibles non
  applicables.
