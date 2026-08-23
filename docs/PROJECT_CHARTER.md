# CHARTE DU PROJET

> **Statut** : **Validé** — Phase 0 approuvée par décision humaine le 2026-08-21
> **Version** : 0.1 — 2026-08-21
> **Décisions ouvertes** : DEC-01/02/03/15 tranchées le 2026-08-21 (nom : Vigile ; AGPL-3.0-or-later ; GitHub ; anglais public / français interne). Reste : DEC-04 (gouvernance formelle — défaut provisoire appliqué).
> **ADR liés** : ADR-0001, ADR-0003, ADR-0005
> **Hypothèses clés** : projet communautaire libre, ressources initiales réduites (équipe « 2 à 4 équivalents temps plein » hypothétiques), laboratoire VM disponible.

## 1. Mission

Fournir une **plateforme libre** d'administration centralisée de la sécurité
applicative des systèmes Linux, inspirée fonctionnellement de la catégorie des
outils de type « application allowlisting / control » du marché, **sans copier
ni code, ni interface, ni marque, ni protocole propriétaire, ni fonctionnalité
brevetée** d'un produit existant.

La plateforme administre progressivement : inventaire des exécutables,
allowlisting avec refus par défaut, contrôle des interpréteurs et scripts,
apprentissage des comportements légitimes, confinement, contrôle réseau par
application, contrôle USB, élévation contrôlée des privilèges, approbations,
déploiement progressif avec retour arrière, télémétrie/audit/SIEM, mode hors
ligne, et vérification cryptographique des politiques et mises à jour.

## 2. Valeurs

1. **Liberté** : licence libre forte ; aucun composant propriétaire requis pour
   fonctionner ; formats documentés.
2. **Refus par défaut** : toute action non explicitement autorisée est refusée ;
   toute politique non vérifiée est rejetée ; aucun fail-open implicite.
3. **Prudence épistémique** : aucune revendication de sécurité sans preuve,
   test, revue indépendante et périmètre défini. Les limites sont affichées,
   jamais masquées.
4. **Moindre privilège et défense en profondeur** : à tous les niveaux
   (composants, protocoles, opérations).
5. **Reproductibilité et traçabilité** : builds déterministes, SBOM, provenance,
   chaîne de signature.
6. **Sécurité des personnes utilisatrices** : messages compréhensibles, workflows
   d'approbation humains, aucun rejet inexpliqué.
7. **Pragmatisme incrémental** : compatibilité progressive par distribution,
   pas d'abstraction universelle fragile.

## 3. Objectifs mesurables (extraits)

Liés aux critères de production (§30 du cahier des charges) et détaillés dans
`ROADMAP.md` :

- Politiques distribuées **signées et vérifiées** par 100 % des agents
  (testé, mesuré).
- **Rollback** automatique effectif sur échec d'application (testé en VM sur
  chaque anneau de déploiement).
- Aucun auto-blocage irrécupérable dans les scénarios testés
  (boot, login, SSH, gestionnaire de paquets, DNS, certificats).
- Mode hors ligne : enforcement maintenu pendant ≥ 72 h sans serveur
  (objectif cible à valider).
- Revue indépendante (audit externe + pentest) avant toute qualification
  « production ».

## 4. Non-objectifs

Voir `NON_GOALS.md` — notamment : pas d'EDR comportemental, pas d'antivirus,
pas de module noyau maison, pas de Windows/macOS, pas de garantie face à un
root/noyau pleinement compromis.

## 5. Gouvernance (proposition)

- **Mainteneurs** : noyau initial de mainteneurs nommés (décision DEC-04) ;
  toute fusion nécessite une revue humaine ≠ auteur.
- **Séparation des rôles sensibles** : signature des releases, gestion des
  clés racines, approbation des politiques de production — réservées à des
  humains identifiés (jamais des agents IA, voir §27 du cahier des charges).
- **Décisions d'architecture** : via ADR versionnés (`adr/`), revus et
  acceptés explicitement.
- **Jalons** : chaque phase du plan (0→11) se termine par une revue humaine
  go/no-go documentée.
- **Communauté** : code de conduite (à adopter — version « Contributor
  Covenant » ou équivalent, décision mineure laissée aux mainteneurs),
  processus de contribution dans `CONTRIBUTING.md`.
- **Transparence** : développement public par défaut ; les éléments sensibles
  (détails d'incidents, clés) restent privés.

## 6. Utilisation de l'IA (charte)

Les contributions assistées par IA sont admises si elles sont : attribuées,
revues par un humain, testées, rattachées à une issue, accompagnées de leurs
hypothèses et limites. Les agents IA ne peuvent jamais : publier ou signer une
release, modifier des clés, approuver une politique de production, déployer
globalement, désactiver une protection, fusionner leur propre code, ni
exécuter une commande destructive. Détail : `CONTRIBUTING.md` § IA.

## 7. Licence (décidée)

**Décision DEC-02 du 2026-08-21 (validation Phase 0)** :

- Code (agent, serveur, CLI, UI) : **AGPL-3.0-or-later** — copyleft fort
  incluant l'usage via réseau (fichier `LICENSE` à la racine).
- Documentation : **CC BY-SA 4.0** (mention `docs/LICENSE-docs.txt`).
- Les dépendances retenues devront être compatibles (audit licence dans
  `SUPPLY_CHAIN_SECURITY.md`, `deny.toml`).

## 8. Critères d'acceptation du document

- [ ] Mission, valeurs et non-objectifs validés par un humain responsable.
- [ ] Licence choisie et validée (DEC-02).
- [ ] Gouvernance et liste initiale de mainteneurs actée (DEC-04).
- [ ] Nom validé après recherche d'antériorité (DEC-01).
- [ ] La charte est référencée dans le README et dans CONTRIBUTING.

## 9. Risques connus

- Gouvernance non formalisée → décisions bloquées ou captées par un acteur ;
  mitigation : DEC-04 traitée avant la fin de la Phase 0.
- Licence en attente → bloque la première contribution externe ; mitigation :
  décision DEC-02 prioritaire.
- Périmètre très large → dispersion ; mitigation : NON_GOALS strictes et MVP
  verrouillé (§26 du cahier des charges).
