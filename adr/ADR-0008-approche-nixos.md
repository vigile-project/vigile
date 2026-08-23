# ADR-0008 — Approche NixOS

**Statut** : Accepté — validé avec la Phase 0 le 2026-08-21
**Date** : 2026-08-21

## Contexte

NixOS est déclaratif et immuable par générations : éditer impérativement des
fichiers gérés par Nix crée une divergence effacée au prochain
`nixos-rebuild`. Le cahier des charges (§14) exige un module NixOS, des
secrets hors Nix store, et une stratégie de coexistence explicite entre
contrôle centralisé et configuration déclarative. Pas de paquet fapolicyd
natif NixOS (matrice — NON VÉRIFIÉ).

## Options étudiées

| Option | Avantages | Inconvénients |
|---|---|---|
| **Module NixOS dédié + état dynamique strictement séparé** (recommandé) | Respecte le modèle déclaratif ; rollback par générations natif ; secrets hors store | Double mécanisme de déploiement à documenter |
| Agent impératif classique sur NixOS | Réutilise le code Fedora | Divergences effacées à chaque rebuild ; anti-pattern |
| Nix sur distributions non-NixOS traité comme NixOS | — | Explicitement exclu par le cahier des charges |

## Décision (recommandée)

1. Fournir un **module NixOS** (phase 9) installant l'agent (paquet
   reproductible construit depuis le flake du projet), déclarant l'URL du
   serveur, activant les backends disponibles, et posant des unités systemd
   durcies identiques aux autres distributions.
2. **Séparation d'état explicite** :
   - **Déclaratif** (dans la config Nix) : présence/composants, URL serveur,
     options de backends, durcissement ;
   - **Dynamique local acceptable** (`/var/lib/vigile`) : cache de
     politiques signées, LKG, files d'événements, état de transactions ;
   - **Identité agent** (`/var/lib/vigile/identity`) : persistante, jamais
     dans le store ;
   - **Secrets** : injectés hors store (intégration aux mécanismes du type
     sops-nix/agenix au choix de l'exploitant — non imposée) ;
   - **Politiques dynamiques** : appliquées localement sous signature, sans
     toucher aux fichiers gérés par Nix.
3. Avant tout `nixos-rebuild` assisté : **vérification de compatibilité**
   (prédicat d'évaluation + tests) ; tests NixOS en VM (`nixosTests`) au
   même niveau que les tests VM Fedora.
4. Fonctionnalités indisponibles sur NixOS (ex. allowlisting fapolicyd)
   sont déclarées `unavailable` et refusées proprement (jamais simulées) ;
   la couverture viendra des mécanismes d'intégrité propres à Nix (étude
   phase 9).

## Conséquences

- Le rollback NixOS (générations) et le rollback politique (LKG)
  coexistent : documentés ensemble dans le guide opérateur phase 9.
- Le module ne « monkey-patche » rien : ce qui est déclaratif reste
  déclaratif.

## Alternatives rejetées

Impératif pur : divergence systémique ; contraire au cahier des charges.

## Risques et critères de révision

- Étude phase 9 (intégrité du store, alternatives d'allowlisting) pourra
  amender cet ADR.
- Couverture fonctionnelle réduite sur NixOS au début : assumée, documentée
  dans la matrice.
