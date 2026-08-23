# ADR-0005 — Stratégie TUF pour les mises à jour

**Statut** : Accepté — validé avec la Phase 0 le 2026-08-21
**Date** : 2026-08-21

## Contexte

La distribution (agents, métadonnées, politiques) doit résister à : rejeu
(rollback), gel des métadonnées (freeze), compromission partielle de clés,
miroir ou serveur compromis. Le cahier des charges (§7) demande d'« étudier
et adopter TUF, ou justifier formellement toute alternative ».

## Options étudiées

| Option | Avantages | Inconvénients |
|---|---|---|
| **Adopter TUF** | Conçoit exactement rollback/freeze/compromission ; racine hors ligne, seuils, rôles éprouvés ; implémentations existantes (rust-tuf et autres — maturité à vérifier en spike, NON VÉRIFIÉ) | Charge opérationnelle (rôles, expirations) ; discipline de cérémonie |
| Métadonnées maison signées | Simple au début | Réinventer TUF avec les mêmes bugs historiques, sans les défenses ; rejeté sauf preuve d'impossibilité |
| Uptane (variante automobile) | Défenses accrues pour flottes | Surdimensionné ici |

## Décision (recommandée)

1. **Adopter TUF** pour la distribution des mises à jour de l'agent et des
   **métadonnées de politiques** (targets/snapshot/timestamp ; racine hors
   ligne à seuil k-of-n — KEY_MANAGEMENT.md §1).
2. Les enveloppes de politiques conservent **leur propre signature Ed25519**
   (ADR-0004) : TUF protège le canal et la fraîcheur ; la signature
   bout-en-bout protège contre un serveur/miroir compromis. Défense en
   profondeur volontaire.
3. Paquets (RPM/DEB) : installés par les gestionnaires natifs depuis des
   dépôts **signés GPG** ; TUF référence leurs hash (targets) ; jamais de
   canal propriétaire d'installation ni `curl | sh`.
4. Un spike phase 1 évaluera les implémentations TUF en Rust et leur état
   de maintenance avant engagement (règle : ne pas supposer une API).

## Conséquences

- Expirations de rôles à monitorer (timestamp fréquent) ; alerte obligatoire
  en cas de péremption (observabilité §23).
- Cérémonies de rotation documentées et exercées (phase 10).
- Anti-rollback local (versions/générations monotones agent) reste nécessaire
  (TUF protège la chaîne, l'état local protège contre les rejeux directs).

## Alternatives rejetées

Maison : justification formelle de rejet — refaire TUF moins bien. Uptane :
complexité supplémentaire sans besoin de flotte véhiculaire.

## Risques et critères de révision

- Maturité des implémentations Rust : spike obligatoire ; si aucune n'est
  acceptable, ADR complémentaire (pas de contournement silencieux).
- Charge opérationnelle réelle : à réévaluer après 6 mois d'exploitation.
