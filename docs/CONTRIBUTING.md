# CONTRIBUTER

> **Statut** : **Validé** — Phase 0 approuvée par décision humaine le 2026-08-21
> **Version** : 0.1 — 2026-08-21
> **Décisions ouvertes** : DEC-03 tranchée (GitHub, 2026-08-21) ; DCO adopté par défaut provisoire (DEC-04) ; SAST/outils exacts à installer au sprint 1
> **Langue (DEC-15)** : documentation publique, commits, descriptions de PR et identifiants de code **en anglais** ; notes internes et discussions en français admises.
> **ADR liés** : ADR-0001 (standards Rust), tous pour les contributions touchant une décision
> **Hypothèses clés** : contribution = code + tests + documentation ; le processus reflète la charte (§27-28 du cahier des charges).

## 1. Parcours d'une contribution

1. **Issue d'abord** : toute contribution significative est rattachée à une
   issue décrite (objectif, hypothèses, limites).
2. Branche nommée `ISS-<numéro>-slug` ; commits signés ; messages clairs.
3. PR avec : description, tests ajoutés, impact sécurité évalué (template),
   mentions `Hypothèses`/`Limites` si contribution assistée par IA.
4. Revue humaine obligatoire (revueur ≠ auteur ; pour le code de sécurité :
   revueur avec habilitation sécurité).
5. CI verte (lint, unitaires, intégration VM concernée) avant fusion.
6. Toute contribution touchant une décision d'architecture exige un ADR
   (créé ou mis à jour) dans la même PR.

## 2. Standards de code

### Rust (agent, exécuteur, serveur, CLI)

- `unsafe` **interdit par défaut** ; tout `unsafe` exceptionnel : bloc isolé,
  commentaire d'invariant, revue dédiée, tests spécifiques.
- `clippy` strict (`-D warnings`), `rustfmt`, aucune `panic` attendue sur
  entrée distante (gestion typée des erreurs).
- Dépendances : parcimonie + check-list d'adoption (SUPPLY_CHAIN_SECURITY.md).
- Secrets : types dédiés à effacement lorsque réaliste ; jamais en argument
  de processus ni en URL.

### TypeScript (portail)

- `strict: true`, pas de `any` ; composants petits et testés ; pas de
  dépendance CDN externe.

### Documentation

- Tout changement de comportement documenté dans la même PR.
- Les affirmations de sécurité dans la documentation doivent citer les tests
  ou être retirées.

## 3. Contribution assistée par IA (charte §27)

- **Attribution obligatoire** : la PR mentionne l'usage d'IA et ses limites.
- L'IA ne peut pas : publier/signer une release, modifier des clés, approuver
  une politique de production, déployer globalement, désactiver une
  protection, fusionner sa propre PR, introduire une dépendance non évaluée,
  exécuter de commande destructive.
- Les contributions IA sont testées, revues, rattachées à une issue,
  reproductibles — comme toute contribution.

## 4. Environnement de développement

- Développement en conteneurs rootless ; VM de labo pour tout ce qui touche
  fapolicyd/SELinux/GNOME (jamais sur la machine du développeur).
- Harnais de tests documenté (`TEST_STRATEGY.md`) ; reproduire un échec de
  CI localement avant de pousser.

## 5. Signalement de sécurité

Ne passe **pas** par les issues publiques : voir `SECURITY.md`.

## 6. Critères d'acceptation du document

- [ ] Templates de PR (dont volet sécurité) créés avec la forge (DEC-03).
- [ ] Processus IA jugé applicable et accepté.

## 7. Risques connus

- Friction élevée (gates strictes) ralentissant les contributions :
  arbitrage assumé en faveur de la sécurité ; outillage prévu pour fluidifier.
- Forge non choisie : certaines instructions devront être adaptées (DEC-03).
