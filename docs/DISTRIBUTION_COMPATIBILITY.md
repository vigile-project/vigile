# COMPATIBILITÉ PAR DISTRIBUTION

> **Statut** : **Validé** — Phase 0 approuvée par décision humaine le 2026-08-21
> **Version** : 0.1 — 2026-08-21
> **Décisions ouvertes** : DEC-05 (liste définitive des versions cibles et de leur politique de support)
> **ADR liés** : ADR-0006, ADR-0008, ADR-0009
> **Hypothèses clés** : données vérifiées le 2026-08-21 à partir de sources publiques (Fedora/Debian/Ubuntu). Tout élément marqué **NON VÉRIFIÉ** devra être confirmé en source primaire avant le début de la phase concernée (issue dédiée `planning/BACKLOG.md`).

## 1. Versions de référence (hypothèses de travail)

| Famille | Cibles proposées | Remarques |
|---|---|---|
| Fedora | 44 (stable, avr. 2026) et 43 | Vérifié : Fedora 44 publié le 2026-04-28 |
| RHEL | 10.x et 9.x | NON VÉRIFIÉ : point releases actuelles |
| CentOS Stream / Rocky / Alma | Stream 10, 9/10 | NON VÉRIFIÉ : correspondances exactes |
| Debian | 13 « trixie » (stable, 13.x) ; 12 en oldstable | Vérifié : stable actuelle |
| Ubuntu | 24.04 LTS ; 26.04 LTS | 26.04 : sortie avr. 2026 NON VÉRIFIÉ |
| NixOS | stable courante (25.05/25.11) | NON VÉRIFIÉ |

MVP : **Fedora Workstation 44/43 + Fedora Server 44/43**, x86_64 ; aarch64
« lorsque les dépendances le permettent » (à valider par build).

## 2. Matrice de capacités

Niveaux : `supported` (S), `supported-with-limitations` (S*),
`experimental` (E), `unavailable` (U), `unsafe-to-enable` (X).

| Capacité | Fedora 43/44 | RHEL 9/10, clones | Debian 12/13 | Ubuntu 24.04/26.04 | NixOS |
|---|---|---|---|---|---|
| fapolicyd | S (paquet officiel — **2.0-1.fc44 vérifié** le 2026-08-21, spike ISS-008 ; NFS client, conteneurs et memfd non couverts par fapolicyd : voir `docs/spikes/ISS-008-fapolicyd.md`) | S (S* sur clones hors dépôts de base — NON VÉRIFIÉ) | S* (présent ; intégration à valider — présent dans sid, inclusion trixie NON VÉRIFIÉ ; backend `debdb` confirmé en amont) | S* (présent depuis 23.04 ; LTS couvertes, qualité à valider) | U (pas de paquet natif — NON VÉRIFIÉ ; rôle dévolu aux mécanismes NixOS) |
| SELinux (cible) | S (targeted par défaut) | S | X (présent mais politiques incomplètes : unsafe-to-enable sans projet dédié) | X (idem) | U |
| AppArmor (cible) | E (paquet présent, pas défaut) | E/U | S* (disponible, activation manuelle) | S (défaut sur LTS) | U |
| nftables | S | S | S | S (via ufw/iptables-nft : S*) | S (module NixOS) |
| cgroups v2 unifiés | S | S (9+) | S (12+) | S | S |
| systemd ≥ 250 | S | S | S | S | S |
| USBGuard | S* (paquet présent ; politique par défaut à construire) | S* | S* | S* | E (packaging à vérifier) |
| polkit | S | S | S | S | S |
| IMA/EVM | E (noyau ok, chaîne de confiance à construire) | E | E | E | E |
| fs-verity | S* (ext4 ; usage à définir) | S* | S* | S* | S* |
| TPM 2.0 (tpm2-tss) | S* (optionnel) | S* | S* | S* | S* |
| Flatpak (info) | S | S* | S* | S* | S* |
| Paquetage agent | RPM | RPM | DEB (ph.5) | DEB (ph.5) | module NixOS (ph.9) |
| GNOME / Wayland | S | S (WS seulement) | S | S | S* |
| aarch64 | S* (à valider par build et tests) | S* | S* | S* | S* |

## 3. Règles de gestion de la matrice

1. Un backend **déclare** son niveau de support par (distribution, version,
   capacité) dans son manifeste ; l'agent lit cette matrice locale (signée)
   au démarrage (détection de capacités, FR-101).
2. Une fonctionnalité `unavailable` ou `unsafe-to-enable` est **refusée
   proprement** avec message explicite — jamais simulée ni ignorée
   silencieusement (SEC-603).
3. `experimental` nécessite un opt-in explicite de l'administrateur avec
   avertissement ; impossible pour les politiques d'enforcement globales.
4. La matrice est versionnée dans le dépôt et vérifiée par CI (tests
   d'intégration par distribution) ; mise à jour à chaque release de
   distribution suivie.
5. Toute cellule passant de S à autre chose dans une version supportée
   déclenche une revue de compatibilité (processus dans
   `planning/SECURITY_REVIEW_CHECKLIST.md`).

## 4. Écarts documentés (MVP → phases ultérieures)

| Écart | Conséquence | Traitement |
|---|---|---|
| Pas de fapolicyd natif NixOS | Allowlisting classique indisponible sur NixOS au MVP | Phase 9 : mécanismes déclaratifs NixOS + étude des alternatives d'intégrité du store |
| SELinux Debian/Ubuntu `unsafe-to-enable` | Pas de confinement MAC sur ces cibles avant la phase 5 | Phase 5 = AppArmor ; SELinux hors périmètre sur Debian-like |
| Ubuntu via couches ufw/iptables-nft | Comportement nftables différent (phase 7) | Tests dédiés phase 7 |
| Clones RHEL : dépôts/EPEL variables | fapolicyd parfois hors dépôts de base | Packaging propre + documentation |

## 5. Critères d'acceptation du document

- [ ] Toutes les cellules NON VÉRIFIÉ sont converties en issues de
      vérification avec échéance = début de la phase concernée.
- [ ] Les niveaux de support sont acceptés par le valideur humain.
- [ ] La règle « refuser proprement, ne jamais simuler » est jugée
      implémentable (issue de test dédiée).

## 6. Risques connus

- Dérive des versions pendant le développement (cycles 6 mois Fedora) :
  mitigation = politique DEC-05 (N et N-1) + CI sur les deux.
- Qualité variable de fapolicyd hors écosystème Red Hat : mitigation = ne
  jamais promettre l'allowlisting identique partout ; AppArmor/SELinux
  portent le confinement sur Debian-like.
- NixOS : divergence fondamentale (store immuable, déclaratif) : ADR-0008.
