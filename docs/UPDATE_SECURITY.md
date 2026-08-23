# SÉCURITÉ DES MISES À JOUR

> **Statut** : **Validé** — Phase 0 approuvée par décision humaine le 2026-08-21
> **Version** : 0.1 — 2026-08-21
> **Décisions ouvertes** : DEC-05 (dépôts officiels et leur hébergement), DEC-11 (HSM pour la signature de release)
> **ADR liés** : ADR-0005, ADR-0004
> **Hypothèses clés** : adoption de **TUF** (The Update Framework) pour les métadonnées de distribution ; les paquets restent installés par les gestionnaires natifs (dnf/apt/nix) — jamais par un canal propriétaire téléchargeant et exécutant lui-même.

## 1. Modèle de distribution

```mermaid
flowchart LR
  SRC[Sources signées\n(git tag signé)] --> CI[CI éphémère\nbuild reproductible]
  CI --> SBOM[SBOM CycloneDX\n+ provenance SLSA]
  CI --> ART[Artefacts : RPM/DEB/flake]
  H1((Humain\nrelease manager)) -- vérifie + signe --> REL[Release]
  REL --> REPO[Dépôts signés\nGPG + checksums]
  REL --> TUFM[Métadonnées TUF\nroot hors ligne · targets · snapshot · timestamp]
  REPO --> AGENT[Agent : vérifie puis\ndnf/apt/nix installe]
  TUFM --> AGENT
```

- **TUF** fournit : signatures à seuil, anti-rollback (versions dans les
  métadonnées), anti-freeze (timestamp expirant), récupération par racine
  hors ligne. Alternatives (-metadata maison signés-) rejetées : réinventer
  TUF moins bien (justification complète dans ADR-0005).
- Les **politiques** suivent le même canal (métadonnées TUF) avec leur
  **propre signature d'enveloppe** (défense en profondeur : TUF protège le
  canal, la signature Ed25519 protège bout en bout).

## 2. Artefacts publiés

| Artefact | Signature | Vérifié par |
|---|---|---|
| RPM | GPG du dépôt + provenance | dnf/rpm côté machine |
| DEB (ph.5) | GPG du dépôt apt | apt |
| Module/flake Nix (ph.9) | dépôt git signé + hash de fixation | nix |
| Métadonnées TUF | rôles TUF (seuils) | agent avant toute action |
| Enveloppes de politiques | Ed25519 (à seuil pour enforcement) | agent (local) |
| SBOM | incluse dans la provenance | audit/outils clients |

Règles : checksums publiés dans les notes de version ; **jamais** de
`curl | sh` ; jamais de téléchargement-exécution par l'agent lui-même ;
mises à jour de l'agent uniquement via le gestionnaire de paquets, signées.

## 3. Sécurité de la chaîne de build

1. Sources : branches protégées, revue obligatoire, commits et tags signés.
2. CI : runners **éphémères**, permissions minimales, secrets de durée courte,
   séparation des rôles CI/CD, environnement de release isolé du développement.
3. Builds : hermétiques lorsque possible, **reproductibles** (vérifié en CI :
   deux builds ⇒ mêmes hash — SEC-903).
4. Provenance SLSA : cible progressif (L2 au MVP, L3 avant qualification
   production) ; attestations publiées avec les releases.
5. SBOM CycloneDX (ou SPDX — décision mineure au premier build) généré à
   chaque build et publié.
6. La **release est signée par un humain** (release manager), jamais par un
   agent IA ni automatiquement depuis une branche de développement.

## 4. Protections protocolaires (rappel)

- Anti-rollback : versions/générations monotones vérifiées **localement**
  (SEC-203) — la protection vaut même contre un serveur compromis.
- Anti-freeze : expiration des métadonnées (TUF timestamp) ; l'absence de
  fraîcheur dégrade visiblement, jamais silencieusement (TM-019).
- Anti-downgrade agent : `min_agent_version` dans les enveloppes + refus des
  paquets non signés / plus anciens que l'état connu quand applicable.

## 5. Procédure de révocation d'urgence

1. Déclenchement : compromission avérée d'une clé opérationnelle, d'un
   artefact ou du dépôt.
2. Actions : révocation dans les métadonnées TUF (rôle concerné, puis racine
   si nécessaire) ; retrait des artefacts ; publication d'un avis signé.
3. Propagation : fenêtre cible ≤ 24 h (mesurée en test) ; les agents
   refusent les artefacts révoqués et alertent.
4. Communication : SECURITY.md, advisory signé, coordination distributeur si
   impact dépôts tiers.
5. Post-incident : ADR rétrospectif + rotation complète des clés touchées.

## 6. Critères d'acceptation du document

- [ ] TUF (ou équivalent formellement justifié) accepté (ADR-0005).
- [ ] Pipeline de release écrit et testé une fois à blanc avant la phase 1.
- [ ] Test d'installation d'un RPM altéré/non signé → refus (T-UPD-01).

## 7. Risques connus

- Charge de maintenance TUF (rôles, expirations) : mitigation = outillage
  et alertes sur échéances de rôles ; une expiration de timestamp non
  renouvelée **doit** être visible (monitoring §23 du cahier des charges).
- Reproductibilité DEB/Nix différente de RPM : traitée par phase.
- Dépendance aux infrastructures de distribution (miroirs) : vérification
  par signature à chaque étape, jamais confiance au transport.
