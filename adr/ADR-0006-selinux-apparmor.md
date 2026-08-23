# ADR-0006 — SELinux / AppArmor

**Statut** : Accepté — validé avec la Phase 0 le 2026-08-21
**Date** : 2026-08-21

## Contexte

Le confinement MAC n'est pas uniforme : SELinux est la référence sur la
famille Red Hat ; AppArmor sur Debian/Ubuntu ; leurs modèles (étiquettes vs
chemins) ne sont pas isomorphes. Le cahier des charges interdit d'ignorer
silencieusement un champ et de générer des politiques excessivement
permissives ; le MVP est Fedora (fapolicyd d'abord, SELinux en phase 6).

## Options étudiées

| Option | Avantages | Inconvénients |
|---|---|---|
| **Un backend MAC par famille de distributions, piloté par l'IR du compilateur** | Respecte les modèles natifs ; n'invente pas une couche d'abstraction trompeuse ; chaque backend déclare son niveau de support | Deux backends à maintenir ; couverture sémantique inégale (documentée champ par champ) |
| Abstraction MAC unifiée unique | Un seul code | Fausse promesse : perte d'information, politiques faibles des deux côtés |
| SELinux partout | Un modèle | `unsafe-to-enable` sur Debian/Ubuntu (matrice) : trompeur |
| Aucun MAC (fapolicyd seul) | Simple MVP | Pas de confinement des applications autorisées (phases 5-6 requises) |

## Décision (recommandée)

1. **SELinux = backend MAC principal sur Fedora/RHEL** ; **AppArmor = backend
   MAC principal sur Debian/Ubuntu** ; jamais activés en substitution
   croisée sur les cibles où la matrice dit `unsafe-to-enable`/`U`.
2. Le compilateur génère des artefacts **par backend** depuis l'IR
   (POLICY_MODEL.md §5) et émet, dans le manifeste d'artefacts, la liste des
   champs IR **non couverts** par ce backend (ex. règles filesystem fines) :
   aucun champ ignoré silencieusement (SEC-603).
3. Approche progressive : modes **complain/permissif ciblés** d'abord,
   analyse des AVC/violations, puis enforcement par anneaux ; **interdiction
   de générer automatiquement une politique permissive à partir de tous les
   événements observés** (phase 6 : assemblage contrôlé de modules, revue
   humaine obligatoire).
4. MVP : aucun backend MAC actif (fapolicyd seul) ; les champs concernés de
   l'IR sont déclarés « non applicable » dans les artefacts.

## Conséquences

- La matrice de compatibilité porte la vérité de terrain par
  (distribution × version × backend) et est signée/chargée par l'agent.
- Effort phase 5 (AppArmor) et phase 6 (SELinux) séparé et séquencé.

## Alternatives rejetées

Abstraction unifiée : réintroduirait exactement l'« abstraction universelle
fragile » proscrite par le cahier des charges.

## Risques et critères de révision

- Écart sémantique IR↔backend mal documenté : mitigé par manifeste + tests.
- Génération SELinux complexe : périmètre volontairement limité (modules
  ciblés, ringfencing minimal documenté), révisé à la phase 6.
