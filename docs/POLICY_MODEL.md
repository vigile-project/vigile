# MODÈLE DE POLITIQUE

> **Statut** : **Validé** — Phase 0 approuvée par décision humaine le 2026-08-21
> **Version** : 0.1 — 2026-08-21 — schéma `policy/v0` (pré-version : sera figé en `v1` avec JSON Schema complet et tests)
> **Décisions ouvertes** : DEC-12 (JSON vs CBOR pour le format signé), DEC-09 (bornes de validité par défaut)
> **ADR liés** : ADR-0004, ADR-0006, ADR-0007
> **Hypothèses clés** : le format est un **point de départ** (§4 du cahier des charges) ; la version signée est canonique (RFC 8785) ; il est interdit d'ignorer silencieusement un champ non pris en charge.

## 1. Principes

1. **Déclaratif et versionné** : décrit l'intention, jamais des commandes.
2. **Indépendant des distributions** : un modèle intermédiaire (IR) compilé
   en artefacts par backend (fapolicyd, SELinux, AppArmor, nftables,
   USBGuard, systemd, polkit, NixOS, règles d'audit).
3. **Signé** : toute instance distribuée est dans une enveloppe signée
   (Ed25519, à seuil pour l'enforcement production) — voir §7.
4. **Déterministe** : la compilation produit les mêmes octets pour la même
   entrée + version de compilateur (testé, hash publié).
5. **Explicite** : tout ce qui n'est pas déclaré est refusé ; toute
   fonctionnalité non applicable à la cible est **déclarée** dans l'artefact,
   jamais omise.

## 2. Schéma `policy/v0` (structure logique)

```yaml
policy:
  id: "uuid"                    # identifiant stable de la politique
  version: 17                   # monotone par (tenant, flux)
  schema_version: "policy/v0"
  tenant: "tenant-uuid"         # obligatoire dès le MVP (mono-tenant : valeur fixe)
  target:
    groups: ["workstations"]    # groupes de machines ; jamais "all" implicite
  application:
    identity:                   # identité multi-facteurs (jamais le seul chemin)
      package: { name: "firefox", vendor: "distribution" }
      hashes: []                # SHA-256 (vide = toutes versions du paquet signé)
      signer: null              # signataire de paquet attendu, si vérifiable
  execution:
    decision: allow             # allow | deny | audit-only | not-applicable
    interpreters:
      allow: []
      deny: ["/usr/bin/bash"]
  filesystem:
    read:  { allow: ["$HOME/Downloads/**"], deny: ["$HOME/.ssh/**"] }
    write: { allow: ["$HOME/Downloads/**"] }
  network:                      # phase 7 : déclaré mais compilé seulement après prototype
    default: deny
    allow: [ { protocol: tcp, destination: "update-service.example", ports: [443] } ]
  usb:
    decision: not-applicable    # phase 4
  validity:
    not_before: "RFC3339"
    not_after: null             # null = permanent (réservé aux politiques, pas aux exceptions)
  approval:
    required_roles: ["security-approver"]
    references: []              # identifiants de décisions d'approbation
  rollout:
    strategy: canary            # audit-only | simulation | canary | rings | percentage
    rings: []
  safety:
    protected_services: ["vigile-agent.service", "vigile-executor.service"]
```

### 2.1 Sémantique des champs clés

- `execution.decision` : `audit-only` observe et journalise sans bloquer ;
  `deny` prime **toujours** sur `allow` en cas de chevauchement.
- `interpreters.deny` : interdit l'exécution *via* l'interpréteur listé pour
  ce périmètre (anti-contournement TM-021) ; un deny sur un interpréteur
  utilisé par une application approuvée est une **erreur de compilation**
  (contradiction), pas un avertissement.
- `filesystem` : expressions de chemins restreintes (voir §4). Sont **sans
  effet** au MVP (backend fapolicyd seul) → déclarées « non applicable »
  dans l'artefact tant qu'aucun backend MAC n'est actif ; presence du champ
  reste obligatoire pour la cohérence.
- `validity` : évaluée **localement** par l'agent (SEC-303) ; l'expiration
  fonctionne sans serveur.
- `safety.protected_services` : fusionné avec la liste protégée globale
  (§12 du cahier des charges) par le compilateur ; la liste reste minimale.

## 3. Validation (avant signature)

1. **Syntaxique** : JSON Schema strict, champs inconnus rejetés.
2. **Sémantique** : références résolues (groupes existants), cohérence
   `decision`/`rollout` (pas d'enforcement global direct — règle §13),
   `validity` bornée pour les exceptions (jamais permanentes).
3. **Contradictions** (exemples détectés et **bloquants**) :
   - `allow` et `deny` sur la même cible et même champ ;
   - interpréteur `deny` nécessaire à une application `allow` ;
   - exception permanente (must expire) ;
   - politique d'enforcement ciblant un groupe contenant des machines dont
     la capacité requise est `unavailable`/`unsafe-to-enable` ;
   - `target.groups` vide ou « tous » implicite.
4. **Simulation** : évaluation contre un corpus d'événements observés
   (qu'aurait-on bloqué ? qu'aurait-on permis ?) — diff lisible obligatoire
   avant tout déploiement d'une politique bloquante (SEC-802).

## 4. Expressions de chemins

- Base : chemins absolus canoniques uniquement ; variables limitées à
  `$HOME`, `$USER` ; motif unique `**` (suffixe) pour l'arborescence.
- Interdits : chemins relatifs, `..`, liens symboliques non résolus,
  double slashs, caractères de contrôle. La normalisation (et son test)
  est partagée agent/compilateur (SEC-402).
- `$HOME/**` ne matche **pas** les fichiers cachés critiques listés dans
  `deny` (le deny prime).

## 5. Compilation

| Entrée | Sortie (MVP) | Statut |
|---|---|---|
| IR | Règles `fapolicyd.rules` + entrées de confiance | v0 |
| IR | Manifeste d'artefacts : hash de chaque sortie + liste des champs **non applicables** par backend cible | v0 |
| IR | Avertissements/erreurs bloquantes + preuve de correspondance (source ↔ artefacts) | v0 |
| IR | Politique SELinux / profil AppArmor | phase 5-6 |
| IR | Règles nftables (lot transactionnel) | phase 7 |
| IR | Règles USBGuard | phase 4 |
| IR | Fragments systemd / polkit / NixOS / règles d'audit | phases 4-9 |

Determinisme : entrée canonique + version de compilateur ⇒ octets identiques
(test CI obligatoire, SEC-209) ; tout artefact embarque l'identifiant de
politique, sa version et le hash du compilateur.

## 6. Gestion de versions et compatibilité descendante

- `schema_version` dans chaque enveloppe ; l'agent **refuse** un schéma
  supérieur à celui qu'il connaît (jamais de devinette).
- `min_agent_version` : une politique peut exiger un agent plus récent ;
  l'agent la refuse avec un message d'action (mise à jour signée requise).
- Ajouts de champs = nouvelle version mineure avec ré-évaluation complète ;
  retraits = majeure avec période de double publication documentée.

## 7. Enveloppe signée (transport)

```json
{
  "envelope": {
    "id": "…", "tenant": "…",
    "version": 17, "generation": 941,
    "digest": "sha256:…",
    "created": "RFC3339", "not_before": "…", "not_after": "…",
    "audience": "agent", "target_groups": ["workstations"],
    "min_agent_version": "1.2.0", "schema_version": "policy/v0",
    "signer_ids": ["key-op-2", "key-op-5"],
    "approval_refs": ["APR-2026-0142"],
    "payload": "<politique canonique>",
    "signatures": ["ed25519:…", "ed25519:…"]
  }
}
```

Vérifications côté agent (dans l'ordre) : mTLS → signature(s) + seuil →
digest vs canonisation locale → schéma → audience/tenant/groupe →
version/génération monotones → fraîcheur → `min_agent_version` → capacité
locale (matrice) → transaction (`FAILURE_MODES.md`, `AGENT_PROTOCOL.md` §5).

## 8. Exemple complet commenté

(L'exemple §4 du cahier des charges reste la référence canonique v0 ; il est
reproduit dans les tests du compilateur comme cas nominal.)

## 9. Critères d'acceptation du document

- [ ] JSON Schema `policy/v0` publié avec le compilateur (issue dédiée).
- [ ] Les règles de contradiction §3.3 sont jugées suffisantes et complétées
      par la revue.
- [ ] L'interdiction d'ignorer silencieusement un champ est couverte par un
      test négatif.

## 10. Risques connus

- Expressivité v0 volontairement réduite (risque de demandes précoces de
  « tout le modèle §5 du cahier des charges ») : mitigation = roadmap.
- Correspondance IR→fapolicyd : les sémantiques ne sont pas isomorphes ;
  les écarts seront **listés dans le manifeste d'artefacts** (spike phase 2,
  partiellement NON VÉRIFIÉ : capacités exactes de fapolicyd).
