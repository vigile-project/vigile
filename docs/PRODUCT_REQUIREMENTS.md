# EXIGENCES FONCTIONNELLES (PRODUIT)

> **Statut** : **Validé** — Phase 0 approuvée par décision humaine le 2026-08-21
> **Version** : 0.1 — 2026-08-21
> **Décisions ouvertes** : DEC-06 (framework web), DEC-05 (versions cibles exactes), DEC-16 (détail des choix d'approbation exposés à l'utilisateur)
> **ADR liés** : ADR-0001, ADR-0002, ADR-0003, ADR-0004, ADR-0009
> **Hypothèses clés** : les priorités MoSCoW (Must/Should/Could/Won't) se rapportent au MVP défini en §26 du cahier des charges ; toute exigence « Won't » du MVP est re-planifiée par `ROADMAP.md`.

## 1. Personas

| Persona | Description | Besoins clés |
|---|---|---|
| Admin sécurité | Responsable des politiques du parc | Écrire/simuler/diffuser des politiques, voir l'impact, rollback |
| Approbateur (security-approver) | Valide les demandes | File de demandes, contexte de provenance, décision bornée, piste d'audit |
| Opérateur déploiement | Gère anneaux/canaris | État par machine, pause/reprise/annulation, historique |
| Auditeur | Contrôle a posteriori | Journal d'audit complet, export, non-modifiabilité |
| Helpdesk | Support niveau 1 | Statut machine, diagnostic limité, création de demandes |
| Utilisateur final (dev/employé) | Subit le refus par défaut | Message clair, demande d'approbation en 1 clic, statut local |
| Équipe SI/SIEM | Consomme la télémétrie | Export structuré, quotas, latence connue |

## 2. Exigences par domaine

Identifiants `FR-<domaine><numéro>`. Priorité : M = Must (MVP), S = Should (MVP si possible), C = Could (phases suivantes), W = Won't (MVP).

### 2.1 Inventaire (domaine 1)

- FR-101 (M) : détection de la distribution, de la version et des capacités locales (backends disponibles + niveau de support).
- FR-102 (M) : inventaire des paquets (dnf/rpm sur MVP) avec provenance (dépôt, signataire du paquet).
- FR-103 (M) : inventaire des exécutables hors paquets (chemins utilisateurs, /usr/local, AppImage…) avec hash SHA-256.
- FR-104 (M) : détection des interpréteurs et scripts avec shebang ; exécutions indirectes (python/bash/perl/node/java).
- FR-105 (S) : détection Flatpak (applications + permissions) comme information d'inventaire.
- FR-106 (S) : détection Snap si présent (information seulement, MVP Fedora : non applicable).
- FR-107 (C) : détection conteneurs, montages NFS/amovibles, fichiers Nix store (phases ultérieures).
- FR-108 (M) : mise à jour incrémentale de l'inventaire + envoi différé/limité (bande passante maîtrisée).

### 2.2 Allowlisting / fapolicyd (domaine 2)

- FR-201 (M) : génération (compilation) de règles fapolicyd depuis le modèle de politique intermédiaire.
- FR-202 (M) : mode **audit-only** d'abord : aucune action bloquante, collecte des refus simulés.
- FR-203 (M) : mode enforcement activable **par groupe et par anneau uniquement**, jamais globalement à la création.
- FR-204 (M) : comparaison comportement attendu / observé et recommandations (apprentissage assisté, jamais d'activation automatique).
- FR-205 (M) : conservation de la dernière politique valide (LKG) et refus de toute politique non signée/invalide.

### 2.3 Approbations et exceptions (domaine 3)

- FR-301 (M) : workflow « application bloquée » complet : notification GNOME non technique → demande facultative → transmission serveur → analyse de provenance → décision → distribution signée.
- FR-302 (M) : choix d'approbation bornés : une fois ; durée ; cette machine ; cet utilisateur ; ce groupe ; cette empreinte ; ce paquet signé ; provenance définie pour versions futures ; refus ; quarantaine.
- FR-303 (M) : expiration automatique de toute exception, **même si le serveur tombe** (validité portée par la politique signée, vérifiée localement).
- FR-304 (M) : justification et référence de ticket obligatoires pour toute approbation.
- FR-305 (S) : élévation contrôlée (phase 8) : action structurée précise, jamais de shell root générique par défaut ; jeton à usage limité et expiration.

### 2.4 Déploiement progressif (domaine 4)

- FR-401 (M) : anneaux : CI → VM éphémères → labo → dev → canary → 5 % → 20 % → 50 % → généralisation.
- FR-402 (M) : pause, reprise, annulation, rollback commandé, exclusion temporaire d'une machine.
- FR-403 (M) : état détaillé par machine (version appliquée, retard, échecs, rollbacks).
- FR-404 (M) : simulation/analyse d'impact avant diffusion (diff lisible, contradiction, non-applicables déclarés).
- FR-405 (M) : seuils d'arrêt automatique (hausse anormale de refus, perte de contact multiple, échecs de login, rollbacks…).

### 2.5 Administration / portail / CLI (domaine 5)

- FR-501 (M) : portail web (TypeScript strict) : groupes de machines, inventaire, politiques, approbations, déploiements, audit.
- FR-502 (M) : RBAC avec rôles §8 du cahier des charges (viewer, helpdesk, policy-author, policy-reviewer, security-approver, deployment-operator, auditor, tenant-admin, platform-admin, break-glass-operator).
- FR-503 (M) : séparation auteur/approbateur (quatre yeux) pour toute politique d'enforcement.
- FR-504 (S) : MFA (WebAuthn/passkeys recommandé), OIDC.
- FR-505 (M) : CLI d'administration (même API que le portail).
- FR-506 (M) : journal d'audit consultable et exportable, non modifiable depuis l'application.

### 2.6 Télémétrie / SIEM (domaine 6)

- FR-601 (M) : collecte des refus fapolicyd, événements d'application de politiques, santé des backends, rollbacks.
- FR-602 (M) : files locales bornées avec priorité (jamais la télémétrie ne doit dégrader l'enforcement ni remplir le disque).
- FR-603 (S) : export journald/auditd ; intégration SIEM documentée (format stable).
- FR-604 (C) : OpenTelemetry complet (métriques, traces).

### 2.7 USB (domaine 7 — phase 4, hors MVP)

- FR-701..709 (C) : identification périphérique, affichage fabricant/modèle/interfaces, détection composite suspecte, autorisation temporaire/permanente, blocage par défaut avec préservation des périphériques d'entrée, procédure hors ligne. Tests BadUSB obligatoires avant tout enforcement.

### 2.8 Confinement / réseau / autres (phases 6–8, hors MVP)

- FR-801..899 (C) : AppArmor (phase 5), SELinux ciblé (phase 6), réseau par application (phase 7), élévation (phase 8) — spécifiés dans leurs phases respectives après prototypes.

## 3. Exigences transverses d'expérience

- FR-T01 (M) : tout refus visible par l'utilisateur final comporte : cause en langage courant, action possible (« demander l'autorisation »), identifiant de traçabilité.
- FR-T02 (M) : tout composant expose son état (sain/dégradé/hors ligne) ; aucun état dégradé silencieux.
- FR-T03 (M) : aucune donnée personnelle superflue dans l'inventaire (pas de contenu de fichiers).
- FR-T04 (M) : le portail fonctionne sans JavaScript tiers (pas de CDN externe).

## 4. MVP (rappel borné)

Fedora Workstation/Server (x86_64, aarch64 si dépendances le permettent) ; agent Rust ; serveur central ; interface web ; PostgreSQL ; enrôlement+mTLS ; inventaire ; fapolicyd audit puis enforcement ; approbations ; politiques signées ; exceptions temporaires ; groupes ; canary ; rollback ; journal d'audit ; RPM ; notification GNOME ; tests VM. Tout le reste est hors MVP (`NON_GOALS.md`).

## 5. Critères d'acceptation du document

- [ ] Chaque FR a un identifiant stable, une priorité et une phase.
- [ ] Chaque FR « Must » est traçable vers au moins un test dans `TEST_STRATEGY.md` et une issue dans `planning/BACKLOG.md`.
- [ ] Aucune FR n'est en contradiction avec `NON_GOALS.md`.

## 6. Risques connus

- Périmètre des approbations (FR-302) sous-estimé (9 variantes de portée) ;
  mitigation : implémentation initiale limitée à 3 portées (une fois, durée,
  machine), les autres en phases ultérieures.
- Notifications GNOME : dépendance aux portails freedesktop ; à valider par
  prototype (issue dédiée, NON VÉRIFIÉ jusqu'au test).
