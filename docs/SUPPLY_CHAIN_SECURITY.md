# SÉCURITÉ DE LA CHAÎNE LOGISTIQUE

> **Statut** : **Validé** — Phase 0 approuvée par décision humaine le 2026-08-21
> **Version** : 0.1 — 2026-08-21
> **Décisions ouvertes** : DEC-03 (forge), DEC-17 (runners), choix SBOM CycloneDX vs SPDX (mineur, au premier build)
> **ADR liés** : ADR-0005, ADR-0001
> **Hypothèses clés** : un score automatisé n'est **jamais** une preuve suffisante ; la parcimonie en dépendances est la première défense.

## 1. Dépendances

- Minimisation systématique ; toute adoption d'une dépendance passe par une
  check-list documentée (fichée dans le template de PR) : maintenance,
  licence, historique de vulnérabilités, nombre de mainteneurs, politique de
  publication, signatures, dépendances transitives, reproductibilité,
  alternatives standard.
- Lockfiles **verrouillés** ; tout changement de lockfile est une revue
  dédiée visible dans la PR (diff obligatoire).
- Outils CI : audit de vulnérabilités cargo (cargo-audit), analyse de
  licences et de sources (cargo-deny), équivalents npm côté web.
- Interdiction des dépendances « lourdes » non justifiées (framework
  génériques, wrappers superflus) ; justification écrite dans l'ADR ou la PR.

## 2. Builds et artefacts

- Builds **reproductibles** (RPM/DEB/Nix) vérifiés en CI (deux builds ⇒
  mêmes hash — SEC-903).
- Hermétiques lorsque possible (pas d'accès réseau arbitraire pendant le
  build).
- SBOM (CycloneDX ou SPDX) publié à chaque build ; provenance SLSA ciblée
  L2 au MVP, L3 avant qualification production.
- Checksums publiés + notes de version signées.

## 3. Contrôle des sources et CI

- Branches protégées ; revue humaine obligatoire (≠ auteur) ; commits et
  tags signés.
- Runners éphémères ; permissions minimales par job ; secrets à durée courte
  et rotation ; séparation nette développement/publication (environnement de
  release isolé, aucune clé de release sur les runners de PR).
- SAST + analyse de secrets + analyse de conteneurs d'build sur chaque PR ;
  fuzzing nocturne des parseurs.

## 4. Releases

- Séquence : tag signé par humain → build CI → vérification de
  reproductibilité → SBOM + provenance → **signature humaine** des artefacts
  → publication dépôts + métadonnées TUF → annonce signée.
- Les agents IA ne publient, ne signent, ni ne fusionnent (charte §27).
- Rotation des secrets CI planifiée ; revue d'accès trimestrielle.

## 5. Vulnérabilités

- Politique de divulgation et délais : voir `SECURITY.md`.
- Versions supportées publiées (politique de versions) ; correctifs
  d'urgence : procédure accélérée documentée (chaîne de signature conservée).
- Délai de révocation cible ≤ 24 h (UPDATE_SECURITY.md §5).

## 6. Critères d'acceptation du document

- [ ] Check-list d'adoption de dépendance intégrée au template de PR.
- [ ] Pipeline reproductibilité + SBOM opérationnel dès la première release.
- [ ] Audit de licences initial publié (AGPL compatible — DEC-02).

## 7. Risques connus

- Compromission de dépendance transitive (TM-010) : résiduel inhérent ;
  réduit par parcimonie + verrouillage + SBOM (visibilité rapide).
- Mainteneur malveillant (TM-009) : mitigation procédurale (4 yeux) ;
  résiduel accepté et documenté.
- Forge/auto-hébergement : décision DEC-03 influence tout le pipeline.
