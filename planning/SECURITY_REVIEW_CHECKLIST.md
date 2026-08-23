# CHECKLIST DE REVUE DE SÉCURITÉ

> **Statut** : **Validé** — Phase 0 approuvée par décision humaine le 2026-08-21
> **Version** : 0.1 — 2026-08-21
> **Usage** : (a) revue de chaque PR touchant du code sensible ; (b) gate de fin de phase ; (c) revue pré-release. Toute case non applicable doit être justifiée par écrit.

## A. Privilège minimal

- [ ] Aucun nouveau chemin privilégié sans ADR + analyse de menace dédiée.
- [ ] L'exécuteur n'a acquis aucune action générique (catalogue fermé).
- [ ] `unsafe` éventuels : isolés, justifiés, testés, audités.
- [ ] Unités systemd : hardening à jour (NoNewPrivileges, ProtectSystem,
      capabilities, seccomp) et testé en VM.
- [ ] Aucun secret en argument de processus, en URL ou en variable
      d'environnement journalisée.

## B. Cryptographie et identité

- [ ] Toute donnée acceptée de l'extérieur est vérifiée (signature, schéma,
      bornes) avant usage.
- [ ] Canonisation testée (vecteurs + property-based) si format signé touché.
- [ ] Versions/générations monotones respectées (aucun accepté-rétrograde).
- [ ] Rotation/révocation testées pour tout nouveau type de clé.
- [ ] Anti-rejeu couvert pour tout nouveau message.

## C. Protocole et entrées

- [ ] Champs inconnus rejetés sur les messages critiques (test présent).
- [ ] Limites : taille, débit, délais — testées (fuzz/DoS local).
- [ ] Aucune commande shell, aucun chemin non normalisé, aucun suivi de
      symlink (tests négatifs présents).
- [ ] Idempotence et gestion d'erreur typée vérifiées.

## D. Transactions et défaillance

- [ ] Toute écriture locale : temporaire → validation native → rename
      atomique → santé → confirmation/rollback.
- [ ] LKG préservée jusqu'à validation complète (test d'interruption).
- [ ] Classification fail-open/fail-closed mise à jour (FAILURE_MODES §4)
      pour toute nouvelle fonction — aucun fail-open implicite.
- [ ] Scénario chaos correspondant ajouté.

## E. Auto-blocage

- [ ] Simulation passée avant tout déploiement de politique bloquante.
- [ ] Liste protégée non élargie sans ADR.
- [ ] Tests catégorie D passés pour l'anneau visé.

## F. Audit et confidentialité

- [ ] Toute action sensible produit une entrée d'audit complète (avant/
      après, acteur, justification).
- [ ] Aucun secret/contenu utilisateur ajouté aux journaux (règle SEC-703).
- [ ] Données collectées : minimales, documentées publiquement.

## G. Tests

- [ ] Tests négatifs présents pour chaque nouvelle garantie de sécurité.
- [ ] Couverture des modules sécurité au niveau exigé.
- [ ] Tests VM ajoutés si comportement système modifié.
- [ ] Matrice interversions mise à jour si contrat changé.

## H. Chaîne logistique

- [ ] Nouvelle dépendance : check-list d'adoption remplie (maintenance,
      licence, vulnérabilités, transitives…).
- [ ] Lockfile : diff expliqué dans la PR.
- [ ] SBOM/provenance régénérés.
- [ ] Aucun `curl | sh`, aucun téléchargement-exécution.

## I. Documentation

- [ ] Comportements, modes de défaillance et limites documentés.
- [ ] Aucune revendication de sécurité sans test la soutenant.
- [ ] Mentions « NON VÉRIFIÉ » résolues ou converties en issue tracée.

## Gate de fin de phase (en plus des sections ci-dessus)

- [ ] Modèle de menace revu et mis à jour.
- [ ] Matrice de compatibilité revue.
- [ ] Registre des risques revu ; owners nommés.
- [ ] Décisions humaines requises tranchées (DECISIONS_NEEDED).
- [ ] Revue humaine go/no-go documentée (avec dissensus éventuels conservés).

## Revue pré-release (en plus)

- [ ] Reproductibilité des artefacts vérifiée.
- [ ] Rotation/clés : échéances vérifiées, aucune expiration imminente.
- [ ] Procédures d'urgence (révocation, break-glass, PRA) testées récemment.
- [ ] SECURITY.md à jour (versions supportées).
