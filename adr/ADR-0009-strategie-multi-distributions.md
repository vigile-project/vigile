# ADR-0009 — Stratégie multi-distributions

**Statut** : Accepté — validé avec la Phase 0 le 2026-08-21
**Date** : 2026-08-21

## Contexte

Cibles nombreuses (famille Red Hat, Debian/Ubuntu, NixOS) mais ressources
limitées ; les mécanismes divergent (SELinux/AppArmor, RPM/DEB, mutable/
déclaratif, GNOME/headless, Wayland/X11, cgroups v1/v2, nftables natif ou
compat, NetworkManager/networkd). Le cahier des charges exige une matrice de
capacités par distribution/version et un refus propre des fonctions
indisponibles.

## Options étudiées

| Option | Avantages | Inconvénients |
|---|---|---|
| **Priorité stricte + matrice de capacités + refus propre** (recommandé) | Qualité de la cible primaire ; vérité documentée ; pas de simulation trompeuse | Les autres familles attendent leur phase |
| Support simultané universel | Couverture immédiate « sur le papier » | Qualité inégale, promesses intenables, tests non tenables |
| Couches de compatibilité masquant les différences | Code partagé | Illusions dangereuses (ex. iptables-compat vs nftables natif) |

## Décision (recommandée)

1. **Ordre** : Fedora (phases 1-3) → Debian/Ubuntu+AppArmor (ph.5) → NixOS
   (ph.9) ; RHEL-compat via packaging/test dès que Fedora est stable.
2. **Matrice de capacités** versionnée (DISTRIBUTION_COMPATIBILITY.md) :
   chaque backend déclare (distribution, version, capacité) →
   `supported / supported-with-limitations / experimental / unavailable /
   unsafe-to-enable`.
3. Chaque backend embarque son manifeste de capacités ; l'agent le charge
   au démarrage (détection locale) et **refuse proprement** toute
   fonctionnalité indisponible avec message exploitable — jamais de
   simulation ni d'ignorance silencieuse (SEC-603).
4. CI : tests d'intégration par distribution suivie (Fedora N et N-1 au
   MVP) ; les cellules `experimental` exigent un opt-in administrateur
   explicite.
5. Toute affirmation de version/API est vérifiée en source primaire avant
   usage (règle §28) ; les NON VÉRIFIÉ deviennent des issues.

## Conséquences

- Le socle commun (synchronisation, signature, transactions, IPC) est
  partagé ; seuls les adaptateurs diffèrent par famille.
- La matrice est un livrable vivant, revu à chaque release.

## Alternatives rejetées

Universalisme immédiat : contradictoire avec le MVP strict et générateur de
fausses garanties de sécurité.

## Risques et critères de révision

- Pression utilisateur pour des familles secondaires : absorbée par la
  feuille de route et les phases, pas par des promesses.
- Rotations rapides des versions Fedora : politique N/N-1 (DEC-05).
