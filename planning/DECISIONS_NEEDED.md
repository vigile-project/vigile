# DÉCISIONS HUMAINES NÉCESSAIRES

> **Statut** : **Actif** — ces décisions appartiennent **exclusivement à des humains** (charte §27) ; le tronc commun du document a été validé avec la Phase 0 le 2026-08-21

## Journal des décisions

| ID | Décision | Résultat | Date |
|---|---|---|---|
| DEC-01 | Nom du projet | **Vigile** (confirmé). Login GitHub : **vigile-project** (amendé le 2026-08-22 : le login « vigile » appartient à un compte personnel inactif sans lien avec la sécurité ; crates `vigile*` toutes **libres** sur crates.io — vérifié ; domaines `vigile.io/.dev/.net/.app/.org` tous pris — non bloquant, pas de site au MVP). **Reste avant médiatisation : recherche de marques (INPI/EUIPO)** | 2026-08-21, amendée le 2026-08-22 |
| DEC-02 | Licence | **AGPL-3.0-or-later** (code, `LICENSE`) + **CC BY-SA 4.0** (documentation) | 2026-08-21 |
| DEC-03 | Forge / hébergement | **GitHub** (CI GitHub Actions avec runners éphémères ; organisation à créer) | 2026-08-21 |
| DEC-15 | Langue de référence | **Anglais public + français interne** — traduction progressive des documents Phase 0 | 2026-08-21 |
| DEC-04 | Gouvernance | *Défaut provisoire appliqué* : fondateur = mainteneur initial, DCO sans CLA — formalisation attendue avant l'arrivée de contributeurs | en attente |
| DEC-05 | Versions cibles | *Défaut provisoire appliqué* : Fedora 44 + 43 (politique N/N-1) — à confirmer | en attente |
| DEC-07 | Bibliothèques PKI/TLS | **Tranchée (GO)** : rustls 0.23 (ring) + rcgen 0.14 (+x509-parser) + x509-cert 0.3 (CRL) + signature 3 + adaptateurs Ed25519 ; éprouvée par prototype 6/6 (`docs/spikes/ISS-011-prototype-pki.md`) | **2026-08-22 (feu vert humain)** |
> **Version** : 0.1 — 2026-08-21
> **ADR liés** : tous
> **Hypothèses clés** : chaque décision a une recommandation argumentée ; l'absence de décision bloque les issues indiquées.

| ID | Décision | Options | Recommandation | Bloque | Échéance |
|---|---|---|---|---|---|
| DEC-01 | Nom du projet (recherche d'antériorité incluse) | « Vigile » (nom de travail) / autre | Vérification de disponibilité (forge, marques, domaines) puis acter | Publication, packaging | Fin phase 0 |
| DEC-02 | Licence | AGPL-3.0+ / GPLv3 / autre | **AGPL-3.0+** (code) + CC BY-SA 4.0 (doc) | ISS-001, toute release | Fin phase 0 |
| DEC-03 | Forge et hébergement (git, CI, artefacts, dépôts) | GitHub / GitLab / Forgejo auto-hébergé / Codeberg | Auto-hébergement léger ou Codeberg selon posture ; CI éphémère dans tous les cas | ISS-001..004, dépôts signés | Fin phase 0 |
| DEC-04 | Gouvernance : mainteneurs initiaux, code de conduite, DCO/CLA | Liste de 3-5 mainteneurs ; DCO recommandé | DCO (pas de CLA) ; rôles signataires listés nommément | RISK-02, clés | Fin phase 0 |
| DEC-05 | Versions cibles et politique de support (Fedora N/N-1 ? clones ? dépôts officiels) | N+N-1 (recommandé) / N seul ; EPEL pour clones | Fedora 44+43 au MVP ; N/N-1 ensuite | Packaging, matrice | Fin phase 0 |
| DEC-06 | Framework du portail | React+Vite / SvelteKit / autre (TS strict imposé) | React+Vite+TS strict (écosystème, recrutement) | ISS-032 | Début phase 1 |
| DEC-07 | Bibliothèques TLS/PKI (au regard du spike ISS-006) | rustls+ACME interne / smallstep intégré / autre | Trancher **après** le spike ; aucune API supposée exister | ISS-011 | Fin sprint 1 |
| DEC-08 | Garde des clés racines (dépositaires, lieu, cérémonie) | 3 personnes séparées / 5 ; coffre + offsite | 3 dépositaires géographiquement séparés, procédure écrite | Cérémonie racine | Avant première signature |
| DEC-09 | Paramètres chiffrés : durées certificats, seuils, TTL break-glass, dérive horloge, fenêtre fraîcheur | Propositions de KEY_MANAGEMENT/FAILURE_MODES | 90 j agents ; 2/3 politiques prod ; 4 h break-glass ; ±10 min horloge — à valider | SEC concernées | Début phase 1 |
| DEC-10 | Monolithe modulaire vs microservices au MVP | Monolithe en crates (recommandé) / services séparés | Monolithe en crates aux frontières internes strictes | ISS-030 | Début phase 1 |
| DEC-11 | HSM au MVP ou plus tard ; emplacement du service de signature | Sans HSM au MVP (isolation+seuils) / HSM dès le départ | Sans HSM au MVP, obligatoire avant qualification production | ISS-028 | Début phase 1 |
| DEC-12 | Format signé : JSON canonique (recommandé) vs CBOR/COSE | ADR-0004 | JSON canonique + Ed25519 détachée | ISS-027 | Début phase 1 |
| DEC-13 | Paramètres de polling adaptatif | 60 s nominal / 5 s post-action (proposition) | À calibrer par tests de charge | ISS-030 | Phase 1 |
| DEC-14 | Politique de double publication des versions de protocole | N et N-1 pendant M releases | N et N-1 pendant 3 releases | Contrats | Phase 1 |
| DEC-15 | Langue de référence (FR vs EN vs bilingue) | FR interne / EN publique / bilingue | EN pour la documentation publique, FR acceptable en interne — à trancher tôt (coût de traduction) | Docs | Fin phase 0 |
| DEC-16 | Portées d'approbation exposées au MVP (9 prévues) | 3 au MVP (une fois, durée, machine) puis élargir | 3 portées au MVP | ISS-044 | Début phase 3 |
| DEC-17 | Infrastructure CI/VM | Testing Farm / self-hosted libvirt / cloud éphémère | Self-hosted libvirt (maîtrise) + étude Testing Farm pour Fedora | ISS-005 | Fin sprint 1 |
| DEC-18 | Budgets de performance définitifs | Propositions TEST_STRATEGY §6 | Valider les seuils proposés avant optimisation | Tests perf | Début phase 1 |

## Processus de décision

1. Chaque DEC est tranchée par un humain habilité (gouvernance DEC-04).
2. Les décisions techniques sont consignées dans l'ADR concerné (statut
   « Accepté » + date + décideur) ; les décisions de gouvernance dans la
   charte.
3. Aucun agent IA ne tranche, ne publie, ne signe (charte §27) ; les
   recommandations ci-dessus sont des propositions à valider.

## Critères d'acceptation

- [ ] DEC-01..05 et DEC-15 tranchées avant la fin de la phase 0.
- [ ] Chaque DEC a un décideur nommé et une date de décision.
