# ADR-0010 — Modes fail-open / fail-closed

**Statut** : Accepté — validé avec la Phase 0 le 2026-08-21
**Date** : 2026-08-21

## Contexte

Chaque composant peut tomber en panne (serveur, DNS, certificats, horloge,
disque, backend local, redémarrage pendant transaction). Il faut décider,
pour chaque fonction, si sa défaillance **ferme** (refuse l'opération) ou
**ouvre** (laisse passer). Cahier des charges §1, §10 : aucun fail-open
implicite ; ne jamais désactiver automatiquement la protection ; distinguer
télémétrie et enforcement.

## Options étudiées

| Option | Avantages | Inconvénients |
|---|---|---|
| **Fail-closed partout** | Sécurité maximale | Peut verrouiller des machines (clavier USB, login) — exactement l'auto-blocage redouté |
| Fail-closed pour l'enforcement, fail-open **explicite et visible** pour la télémétrie uniquement | Réaliste et sûr : la perte de visibilité n'est pas une perte de contrôle | Exige une liste d'exceptions parfaitement tenue |
| Fail-open sur incident | Disponibilité | Inacceptable pour le cœur du produit |

## Décision (recommandée)

1. **Fail-closed par défaut pour toute fonction de sécurité** : décision
   d'exécution, acceptation de politique (signature/monotonicité/fraîcheur/
   audience/capacité), expiration d'exceptions, application transactionnelle.
2. **Fail-open autorisé uniquement pour la télémétrie et la notification**,
   à condition d'être : borné (files/quotas), visible (état dégradé nommé),
   journalisé — et jamais une condition de l'enforcement local.
3. **Aucune désactivation automatique de protection** ; les baisses
   temporaires de garde sont : locales (break-glass), contraintes (TTL),
   justifiées, auditées, bruyantes (ADR du break-glass :
   RECOVERY_AND_BREAK_GLASS.md).
4. Cas sensitif tranché explicitement : le **clavier/périphériques d'entrée
   essentiels** en cas d'indisponibilité USBGuard (FM-12) — décision
   explicitée et testée en phase 4, car un fail-closed matériel peut
   verrouiller physiquement une machine ; toute autre voie reste fermée.
5. Chaque exception à la présente doctrine exige un ADR dédié + validation
   humaine ; registre des exceptions maintenu dans FAILURE_MODES.md §4.

## Conséquences

- Un serveur mort ne change rien à l'enforcement local (LKG).
- Les tests chaos rejouent systématiquement la matrice §4 de
  FAILURE_MODES.md ; toute divergence est un bug bloquant.

## Alternatives rejetées

Fail-open général : contraire au produit. Fail-closed absolu sans exception
clavier : risque physique humain jugé inacceptable — arbitrage documenté.

## Risques et critères de révision

- L'exception « périphériques d'entrée » est le seul fail-open matériel :
  à revoir après tests phase 4 (BadUSB vs clavier) avec données.
- Toute nouvelle fonction doit être classée dans la matrice avant merge
  (gate de revue sécurité).
