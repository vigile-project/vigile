# GLOSSAIRE

> **Statut** : **Validé** — Phase 0 approuvée par décision humaine le 2026-08-21
> **Version** : 0.1 — 2026-08-21
> **Décisions ouvertes** : terminologie FR/EN définitive (DEC-15)
> **ADR liés** : aucun
> **Hypothèses clés** : vocabulaire aligné sur les usages des projets amont (fapolicyd, SELinux, TUF…), non sur un produit commercial.

Convention : les termes marqués **NON VÉRIFIÉ** dans d'autres documents
renvoient à une vérification à faire dans une source primaire ; ce glossaire ne
constitue pas une telle source pour des affirmations de version ou d'API.

## A–C

- **Allowlisting** : mode dans lequel seuls les exécutables explicitement
  approuvés peuvent s'exécuter ; complémentaire du refus par défaut.
- **Anneau (ring)** : sous-ensemble de machines servant un déploiement
  progressif (CI → VM éphémères → labo → dev → canary → 5 % → …).
- **Approbation** : décision humaine signée permettant une exception ou une
  politique ; toujours bornée (durée, machine, utilisateur, groupe,
  empreinte…) et expirant automatiquement.
- **Apprentissage** : phase d'observation (audit-only) visant à proposer des
  règles ; ne produit jamais automatiquement une politique permissive.
- **Break-glass** : procédure d'urgence locale, contrainte, limitée dans le
  temps, auditable et révocable, pour récupérer un système (jamais une porte
  dérobée universelle).
- **Canary** : premier petit ensemble de machines de production recevant une
  politique avant généralisation.
- **Capacité (backend)** : aptitude concrète d'une distribution à héberger un
  mécanisme (fapolicyd, SELinux, AppArmor, nftables, USBGuard…), avec niveau :
  `supported`, `supported-with-limitations`, `experimental`, `unavailable`,
  `unsafe-to-enable`.
- **Cgroups v2 / systemd scope** : mécanismes d'identification et de
  groupement des charges de travail utilisés notamment pour le contrôle
  réseau par application (Phase 7).
- **Clé racine hors ligne** : clé de confiance ultime conservée hors de tout
  serveur en ligne, utilisée rarement et en cérémonie.

## D–F

- **Dégradation (état)** : état nominal alternatif où une fonction non
  critique (ex. télémétrie) est perdue sans perte d'enforcement.
- **Enforcement** : application effective des décisions (par opposition au
  mode audit-only qui observe sans bloquer).
- **Enrôlement** : création de l'identité unique d'un agent auprès du serveur
  (token à usage unique, certificat client unique).
- **Fail-closed / fail-open** : en cas de défaillance, refuser (fermé) ou
  autoriser (ouvert). Le projet est fail-closed pour l'enforcement ; tout
  fail-open est interdit sauf décision explicite documentée (ADR-0010).
- **fapolicyd** : démon d'espace utilisateur qui décide de l'exécution des
  fichiers selon une base de confiance et des règles ; backend principal de
  l'allowlisting sur la famille Red Hat.
- **Flatpak / portails** : système d'application sandboxé ; source
  d'information d'inventaire, pas une frontière de sécurité absolue.
- **Freeze (attaque)** : blocage de la distribution des métadonnées récentes
  pour figer un parc sur un état ancien ; contré par des horodatages et
  fenêtres d'expiration (TUF).
- **fs-verity / IMA-EVM** : mécanismes noyau d'intégrité de fichiers,
  extensions possibles (pas des dépendances du MVP).

## G–P

- **Génération (de politique)** : compteur global monotone protégeant contre
  les réordonnancements/rejeux, distinct du numéro de version par flux.
- **Identité applicative** : combinaison (hash, provenance de paquet,
  signataire, chemin canonique, interpréteur, contexte…) — jamais le seul
  chemin.
- **IPC local étroit** : protocole local versionné entre agent non privilégié
  et exécuteur privilégié, à actions strictement typées.
- **LKG (last known good)** : dernière politique valide appliquée avec succès,
  conservée localement pour l'autonomie hors ligne et le rollback.
- **mTLS** : TLS mutuel : le client ET le serveur présentent un certificat.
- **Prévention d'auto-blocage** : ensemble des listes protégées, seuils et
  simulations évitant qu'une politique ne rende une machine ou le parc
  inutilisables.
- **Politique (policy)** : document déclaratif versionné décrivant décisions
  et exceptions pour un périmètre cible ; compilé en artefacts propres à
  chaque backend.
- **Provenance** : information vérifiable sur l'origine et la façon dont un
  artefact a été produit (build, signataire, dépendances).

## Q–Z

- **RBAC / ABAC** : contrôle d'accès par rôles (éventuellement enrichi
  d'attributs) ; séparation auteur/approbateur obligatoire.
- **Rollback** : retour automatique ou commandé à l'état précédent une
  application échouée ou dangereuse ; testé, jamais théorique.
- **SBOM** : inventaire machine-lisible des composants d'un artefact
  (CycloneDX ou SPDX).
- **SIEM** : plateforme de corrélation de journaux ; Vigile exporte vers elle,
  n'en dépend pas pour l'enforcement local.
- **TOCTOU** : « time-of-check to time-of-use » : écart entre vérification et
  usage exploitable par un attaquant local ; traité explicitement (tests
  dédiés).
- **Transaction** : séquence d'application d'une politique localement
  (vérification → sauvegarde → écriture temporaire → validation native →
  remplacement atomique → santé → confirmation ou rollback).
- **TUF (The Update Framework)** : cadre ouvert de distribution signée de
  métadonnées de mise à jour, protégeant contre rollback, freeze, clés
  compromises.
- **Zero Trust** : posture où aucune confiance implicite n'est dérivée du
  réseau ou de la position ; chaque action est vérifiée explicitement.
  **Ce mot décrit une orientation, jamais une certification.**

## Critères d'acceptation du document

- [ ] Chaque terme utilisé dans les autres documents existe ici ou y renvoie.
- [ ] Les termes trompeurs (« sécurisé », « garanti ») sont proscrits hors
      usage négatif.

## Risques connus

- Glissement sémantique (« approbation » vs « exception » vs « autorisation ») :
  mitigation par revue terminologique lors des revues de PR.
