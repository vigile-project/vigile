# MODÈLE DE MENACE

> **Statut** : **Validé** — Phase 0 approuvée par décision humaine le 2026-08-21
> **Version** : 0.1 — 2026-08-21
> **Décisions ouvertes** : calibration des probabilités (revue humaine requise), périmètre exact du pentest phase 10
> **ADR liés** : ADR-0002, ADR-0004, ADR-0005, ADR-0010
> **Hypothèses clés** : menaces énumérées conformément à §19 du cahier des charges ; les probabilités sont des estimations initiales qualitatives (Faible/Moyenne/Élevée) à revoir à chaque phase.

## 1. Périmètre et conventions

- Actifs : politiques et leurs clés de signature, identités agents, serveur
  central et sa base, agent/exécuteur sur les machines, journaux d'audit,
  paquets et chaîne CI/CD, disponibilité du parc.
- Exclusions assumées : voir `NON_GOALS.md` (NG-02, NG-03, NG-04…).
- Chaque menace reçoit : prérequis, impact, probabilité, détection,
  prévention, récupération, **risque résiduel** (ce qui reste après
  prévention), tests associés.

## 2. Analyse STRIDE par composant

| Composant | Usurpation (S) | Falsification (T) | Répudiation (R) | Divulgation (I) | DoS (D) | Élévation (E) |
|---|---|---|---|---|---|---|
| Serveur / API | Agent ou admin imposteur (mTLS, OIDC+MFA) | Politiques/base altérées (signatures, audit append-only) | Actions niées (journal signé) | Tenants, inventaire (chiffrement, RBAC) | Épuisement ressources (limites, quotas) | RBAC contourné (tests) |
| Agent | Certificat volé/cloné (rotation, révocation, quarantaine) | Cache local altéré (vérif. signatures, perms fichiers) | Événements falsifiés (horodatage, chaînage) | Clé agent (perms, TPM option) | Crash agent (watchdog systemd) | Agent→exécuteur (IPC étroit TB-2) |
| Exécuteur | Requêtes forgées (SO_PEERCRED, schéma) | Artefacts altérés (hash re-vérifié, O_NOFOLLOW) | Actions non journalisées (audit local) | — (pas de secret) | Saturation (limites) | Actions non typées (refus par construction) |
| Politique/compilateur | Signataire imposteur (seuils, rôles) | Règles falsifiées (signatures, hash, recompilation) | Règle niée (audit de compilation) | — | Erreur compilation bloquante (fail-closed) | Politique permissive (contradictions, simulation) |
| Chaîne CI/CD | Mainteneur/committer imposteur (commits signés, revue) | Artefacts altérés (releases signées, SBOM) | Release niée (journal de release) | Secrets CI (runners éphémères) | Pipeline bloqué (doublon des étapes) | Runner compromis (permissions min.) |
| Poste utilisateur | Fausse notification (portails de bureau) | — | — | Statut trop bavard (données non sensibles) | Spam de notifications (limites) | UI écrivant des politiques (interdit par conception) |

## 3. Arbres d'attaque (extraits critiques)

### 3.1 Exécuter un programme non approuvé (cœur du produit)

```
Exécution non autorisée
├── Contourner fapolicyd
│   ├── Via interpréteur connu (TM-021)  → règles interpréteurs, deny explicites
│   ├── Via binaire modifié après hash  (TM-022 TOCTOU) → re-hash à l'usage, confiance liée au contenu
│   ├── Via montage exotique (bind/nfs/overlay) (TM-024/026) → politique de montages
│   ├── Via memfd / binaire supprimé (TM-027) → couverture fapolicyd à vérifier par test
│   └── Via LD_PRELOAD / biblio injectée dans un process autorisé (TM-028/030) → env filtrée, SELinux ph.6
├── Agir en tant qu'un process autorisé (détournement)
│   ├── ptrace d'un process autorisé (TM-029) → durcissement (Yama), SELinux ph.6
│   └── Script d'une app autorisée exécutant du contenu arbitraire (TM-021) → identité de script, deny interpréteurs
├── Désactiver l'enforcement
│   ├── Tuer/stopper fapolicyd ou l'agent (TM-006) → détection d'arrêt, alerte, fail-closed
│   └── Faire signer une politique permissive (TM-001/003) → seuils, 4 yeux, simulation, listes protégées
└── Attaquer l'hôte (root/noyau) (TM-005/031/032) → HORS PÉRIMÈTRE de garantie (limite assumée)
```

### 3.2 Faire accepter une politique malveillante

```
Politique malveillante appliquée
├── Compromettre le serveur (TM-001) → mais signature à seuil hors serveur (TB-5), agent vérifie
├── Voler des clés de signature (TM-011) → clés op. à seuil, rotation, révocation ; racine hors ligne
├── Rejouer une ancienne politique signée (TM-016/018) → versions/générations monotones locales
├── Forcer un downgrade d'agent (TM-017) → version minimale d'agent dans l'enveloppe + mises à jour signées
└── Abuser du workflow d'approbation (TM-003) → 4 yeux, MFA step-up, justification+ticket, audit
```

### 3.3 Rendre le parc inutilisable (sabotage par auto-blocage)

```
Auto-blocage du parc (TM-041)
├── Politique bloquant un composant vital → listes protégées + simulation + anneaux + seuils d'arrêt
├── Règles fapolicyd invalides sur une version donnée → validation native avant activation + LKG
├── Perte du serveur prolongée + expiration abusive → validité locale portée par la politique signée
└── Rollback impossible (TM-040) → LKG jamais détruit, tests d'interruption à chaque étape
```

## 4. Registre des menaces (TM-001 → TM-041)

Colonnes : Prérequis (P), Impact (I), Probabilité (Pr), Détection (D),
Prévention/Récupération (PR), Risque résiduel (RR). Tests : voir
`TEST_STRATEGY.md` §C (noms T-xxx).

### 4.1 Plan de contrôle

| ID | Menace | P | I | Pr | D | PR | RR |
|---|---|---|---|---|---|---|---|
| TM-001 | Serveur central compromis | Accès serveur/app | Total sur distribution ; enforcement local tenu | M | Anomalies API, audit, SIEM | Signature à seuil **hors serveur** ; agents vérifient tout ; reconstruction depuis sauvegardes signées ; révocation clés | Le serveur peut refuser de servir / mentir sur l'état ; agents restent en enforcement LKG |
| TM-002 | Base de données compromise | Accès SQL/OS DB | Inventaire, politiques, audit altérables | M | Audit chaîné, contrôle d'intégrité | Comptes minimaux, chiffrement, audit append-only, restauration | Perte d'historique si sauvegardes aussi touchées |
| TM-003 | Compte admin compromis | Vol de session/MFA | Politiques/approbations malveillantes | M | Journal d'audit, alertes usage anormal | MFA step-up, 4 yeux, sessions courtes, justification, RBAC étroit | Un couple auteur+approbateur compromis peut faire approuver ; détection a posteriori |
| TM-011 | Vol de clé | Accès machine à clés | Signature d'artefacts malveillants | M | Journal de signature, anomalie | Clés op. à seuil, rotation, révocation rapide, HSM/TPM en prod critique, racine hors ligne | Fenêtre entre vol et révocation |

### 4.2 Agent et hôte local

| ID | Menace | P | I | Pr | D | PR | RR |
|---|---|---|---|---|---|---|---|
| TM-004 | Agent compromis | Root local ou faille agent | Désync, fausses données, tentatives d'élévation via exécuteur | M | Incohérences, événements de sécurité | IPC étroit TB-2, exécuteur vérifie tout, quarantaine, redéploiement signé | Fausse télémétrie possible ; enforcement non contournable par le seul agent |
| TM-005 | Root local hostile | Root sur la machine | Neutralisation locale de l'agent (kill, fichiers) | Élevée (poste dev) | Perte de heartbeat, événements de santé | Détection+alerte, comparaison au redémarrage, SELinux ph.6 | **Limite assumée** : un root peut localement casser l'agent ; la plateforme le voit et le signale (NG-02) |
| TM-006 | Utilisateur local non privilégié hostile | Compte utilisateur | Tentatives de contournement, flood de demandes | Élevée | Refus journalisés, quotas | Refus par défaut, quotas demandes, aucun secret en zone lisible | Nuisance (demandes) contenue par quotas |
| TM-022 | TOCTOU | Local non root | Exécuter un fichier changé entre hash et exécution | M | Écart hash/journal | Confiance liée au contenu (re-hash à l'usage par fapolicyd), fs-verity plus tard | Fenêtres résiduelles documentées par backend |
| TM-023 | Liens symboliques | Local non root | Écriture via chemin contrôlé par attaquant | M | Audit local | O_NOFOLLOW, chemins normalisés, répertoires parents root-owned | Très faible si règles respectées (tests dédiés) |
| TM-024 | Bind mounts | Local root | Masquer des chemins de confiance | F | Incohérence montages/inventaire | Inventaire des montages, alertes | Couvert par la limite root (TM-005) |
| TM-025 | Namespaces | Local non root (user ns) | Vue alternative du système de fichiers | M | Détection ns dans les événements | Règles par chemin réel ; traitement explicite des namespaces | À qualifier par tests ; documenté |
| TM-026 | Conteneurs | Runtime présent | Exécuter dans un conteneur | M | Inventaire des runtimes | Politique sur runtimes (allowlist des images à terme), refus par défaut des binaires non approuvés y compris dans conteneurs privilégiés | Conteneurs rootless non couverts finement au MVP (documenté) |
| TM-027 | memfd / binaire supprimé | Local non root | Exécution sans chemin stable | M | Journaux kernel | Prise en compte par fapolicyd à **vérifier par test (NON VÉRIFIÉ)** ; sinon déni documenté | Moyen jusqu'à validation |
| TM-028 | LD_PRELOAD / variables similaires | Local non root | Injecter du code dans un process autorisé | M | Journalisation env suspecte | Filtrage d'env par wrapper pour apps gérées, SELinux ph.6 | Résiduel sur apps non gérées |
| TM-029 | ptrace | Local même UID | Détourner un process autorisé | M | Journal kernel (ptrace) | Yama/SELinux ph.6, alertes | Résiduel MVP |
| TM-030 | Injection de bibliothèque | Écriture dans chemin de biblio + exec | Code exécuté au chargement | M | Hash des bibliotheques | Répertoires de bibliotheques non inscriptibles par l'utilisateur ; inventaire | Résiduel sur répertoires inscriptibles (ex. ~/.local) → deny |
| TM-031 | eBPF hostile | root + bpf non restreint | Espionnage/altération noyau | F | Audit kernel | Désactivation/bpf durci recommandé côté durcissement hôte | Hors garantie agent |
| TM-032 | Module noyau hostile | root | Contrôle total | F | Audit module load | Allowlist modules hors périmètre MVP (durcissement hôte doc) | Hors garantie (NG-02) |

### 4.3 Chaîne logistique

| ID | Menace | P | I | Pr | D | PR | RR |
|---|---|---|---|---|---|---|---|
| TM-007 | Paquet de mise à jour compromis | Dépôt ou clés de dépôt | Code arbitraire sur le parc | F–M | Signature du dépôt, SBOM, provenance | Dépôts signés, vérification GPG, mises à jour via gestionnaire de paquets uniquement | Standard du dépôt mère |
| TM-008 | Pipeline CI compromis | Accès forge/secrets | Artefacts malveillants « officiels » | M | Provenance SLSA, écarts reproductibilité | Runners éphémères, permissions min, releases signées **par humain**, environnements séparés | Fenêtre si release signing automatisée par erreur |
| TM-009 | Mainteneur malveillant | Statut mainteneur | Backdoor dans le code | F–M | Revue obligatoire, analyse | 4 yeux sur code, commits signés, attribution IA | Un duo complice reste possible (communauté/audit) |
| TM-010 | Dépendance compromise | Supply chain écosystème | Backdoor transitive | M | Audit deps, SBOM, alerts | Dépendances minimales, verrouillées, revues (§20 cahier des charges) | Résiduel inhérent ; réduction par parcimonie |
| TM-012 | Miroir de dépôt compromis | Miroir tiers | Paquets altérés | F | Signature paquets | Vérif signatures partout ; miroirs non officiels non supportés | Très faible |

### 4.4 Réseau, protocole, temps

| ID | Menace | P | I | Pr | D | PR | RR |
|---|---|---|---|---|---|---|---|
| TM-013 | Réseau hostile (MITM) | Position réseau | Falsifier le trafic | Élevée | Échec TLS | mTLS, pinning de l'ancre locale, TLS moderne | Quasi nul sur le canal |
| TM-014 | DNS hostile | Contrôle résolveur | Rediriger l'agent | Élevée | Certificat attendu mismatch | Ancre locale ≠ DNS ; mTLS ; URL configurée | Agent refuse le mauvais serveur |
| TM-015 | Proxy TLS hostile | Proxy imposé | Idem MITM | M | Idem | Idem + refus des autorités injectées non configurées | Quasi nul si ancre locale |
| TM-016 | Rejeu de messages | Capture de trafic | Réappliquer un vieil état | M | Compteurs/nonce | Anti-rejeu SEC-106, idempotence | Nul après tests |
| TM-017 | Downgrade d'agent | Distribution d'anciens paquets | Exploiter failles corrigées | M | Version minimale refusée | Enveloppe avec version minimale d'agent, anti-rollback | Nul si appliqué partout |
| TM-018 | Rollback de politique | Rejeu d'une politique signée ancienne | Réappliquer un état ancien | M | Compteur local | Versions/générations monotones **locales** (SEC-203) | Nul si LKG+compteurs intacts (TM-022/005 en prérequis) |
| TM-019 | Freeze des métadonnées | Blocage distribution | Paralysie en état ancien | M | Fenêtre de fraîcheur expirée | Expiration des métadonnées, alerte admin | Dégradation visible, pas silencieuse |
| TM-036 | Sabotage de l'horloge | Contrôle heure locale | Faux expirés/jamais expirés | M | Dérive détectée | Bornes de dérive, monotonicité locale, dates de validité prudentes | Fenêtres de dérive assumées (documentées) |

### 4.5 Tenancité, périphériques, opérations

| ID | Menace | P | I | Pr | D | PR | RR |
|---|---|---|---|---|---|---|---|
| TM-020 | Confusion de tenant | Multi-tenant + bug | Fuite inter-tenants | F (MVP mono) | Tests IDOR | tenant_id serveur, tests anti-fuite (§C) | Actif en phase 11 |
| TM-033 | BadUSB | Accès physique | Frappe/USB malveillant | M (selon contexte) | USBGuard événements | USBGuard blocage par défaut (ph.4), préservation clavier/souris | Fenêtre avant activation ph.4 |
| TM-034 | Épuisement disque/mé/CPU | Flood local ou bug | Perte de fonctions | M | Alertes ressources | Quotas, files bornées, élagage télémétrie en dernier (SEC-604) | Perte de télémétrie possible, enforcement tenu |
| TM-035 | Tempête d'événements | Incident de masse | Saturation serveur | M | Métriques files | Limites côté agent, agrégation, backoff+jitter | Retard de télémétrie |
| TM-037 | Restauration d'un snapshot ancien | Contrôle hyperviseur/sauvegarde | État politique ancien réapparu | F | Compteur régressé détecté | Anti-rollback local + resynchronisation forcée | Résiduel si snapshot inclut clés → rotation |
| TM-038 | Clonage de VM | Accès image | Deux agents même identité | M | Doublon détecté à la sync | Token unique, quarantaine du clone (SEC-107) | Avant première sync : couvert par rotation |
| TM-039 | Attaque sur break-glass | Accès physique/local + connaissance procédure | Contournement local temporaire | F | Journal local inaltérable + alerte serveur | TTL court, justification obligatoire, bruyant, révocable, testé | Fenêtre hors ligne = TTL |
| TM-040 | Attaque sur rollback | Forcer un rollback vers état plus faible | Retour à une politique permissive | M | Journal des rollbacks | LKG signée et monotone ; rollback ≠ régression de version sans signature | Nul si LKG intègre |
| TM-041 | Auto-blocage du parc | Erreur humaine ou bug | Parc inutilisable | M | Seuils automatiques | Listes protégées, simulation, anneaux, seuils d'arrêt, break-glass | Impact borné aux anneaux déjà déployés |

## 5. Menaces critiques — fiches détaillées

### TM-001 Serveur central compromis
- **Prérequis** : RCE ou accès admin sur `vigile-server`.
- **Impact** : contrôle de la distribution ; fausse vision du parc ; refus de
  service du plan de contrôle. **L'enforcement local ne dépend pas du serveur.**
- **Probabilité** : Moyenne (cible de valeur).
- **Détection** : audit chaîné exporté, anomalies de signature, somme de
  contrôle des métadonnées TUF, agents signalant des incohérences.
- **Prévention** : surface d'attaque minime, durcissement, signatures **à seuil
  émises hors du serveur** (TB-5), agents vérifient tout localement.
- **Récupération** : reconstruction depuis sauvegardes, révocation des clés
  opérationnelles via racine, ré-enrôlement si nécessaire.
- **Risque résiduel** : période de « mensonge d'état » (le serveur peut
  raconter n'importe quoi) tant qu'il n'est pas reconstruit ; les agents
  restent en enforcement local et alertent sur anomalies.
- **Tests** : T-SRV-01 serveur hostile injectant politiques non signées /
  mal signées / anciennes ; T-AGENT-14..20.

### TM-005 Root local hostile (limite fondamentale)
- **Prérequis** : obtention de root sur une machine administrée.
- **Impact** : l'attaquant peut tuer/altérer localement l'agent et l'exécuteur,
  falsifier des fichiers locaux (pas la cryptographie des politiques).
- **Probabilité** : Élevée sur les postes de développement (par conception).
- **Détection** : perte de heartbeat, échecs de vérification d'intégrité de
  l'agent (hash des binaires au démarrage), incohérence au retour en ligne.
- **Prévention** : réduction de la surface (pas de shell dans l'exécuteur),
  alertes, SELinux en phase 6 pour compliquer la neutralisation.
- **Récupération** : redéploiement signé de l'agent, investigation.
- **Risque résiduel** : **un root local peut toujours casser l'agent sur SA
  machine** — la plateforme garantit la détection/le signalement, pas la
  survie. C'est une limite publique assumée (NG-02), jamais masquée.
- **Tests** : T-LOCAL-01..05 (kill, remplacement binaire, falsification cache).

### TM-011 Vol de clé de signature
- Voir fiche tableau §4.1. Point clé : la racine est hors ligne ; les clés
  opérationnelles sont à seuil ; la révocation est testée (exercice complet
  requis avant qualification production).

### TM-021 Contournement via interpréteur
- **Prérequis** : interpréteur approuvé présent (bash, python…).
- **Impact** : exécution de contenu arbitraire (script inline, `-c`, fichier
  non approuvé) sous couvert d'un binaire de confiance.
- **Probabilité** : Élevée (vecteur classique).
- **Détection** : événements fapolicyd sur scripts, journalisation des
  invocations d'interpréteurs avec arguments (réduction des secrets).
- **Prévention** : politique des interpréteurs (deny par défaut de
  `/usr/bin/bash` en usage interactif non approuvé là où cible), identification
  des scripts par hash et non par seule extension, règles sur `-c` et stdin
  (dans la mesure des capacités de fapolicyd — **partiellement NON VÉRIFIÉ**,
  spike phase 2 requis).
- **Récupération** : règle d'exception ciblée signée.
- **Risque résiduel** : les interpréteurs intégrés (app embarquant un moteur
  de script) restent une zone grise documentée.
- **Tests** : T-BYPASS-01..10 (bash -c, python -, env python, stdin, etc.).

### TM-038 Clonage de VM
- Double vie de la même identité → quarantaine automatique au premier contact
  simultané ; avant contact, la rotation des certificats et le compteur
  monotone tranchent. Tests : T-CLONE-01..03.

### TM-041 Auto-blocage du parc
- C'est la menace que l'opérateur se pose à lui-même. Toutes les défenses des
  §12/§13 du cahier des charges (listes protégées, simulation, anneaux,
  seuils, break-glass, LKG) convergent ici. Tests catégorie D entière.

## 6. Limites explicites du modèle

1. **Root/noyau compromis** : aucune garantie de survie de l'agent (NG-02) ;
   la promesse se limite à détection/signalement.
2. **Snapshot/rollback hyperviseur** : hors de contrôle de l'agent ; atténué
   par compteur + rotation (TM-037).
3. **Canal de décision humain** : un duo auteur+approbateur compromis peut
   faire approuver une politique ; la défense est procédurale (MFA, tickets,
   audit) et statistique (seuils, simulation), pas cryptographique.
4. **Zéro jour des dépendances** : parcimonie + SBOM + mise à jour rapide ;
   pas de garantie d'immunité.
5. **Couverture fapolicyd de cas exotiques (memfd, namespaces)** : à valider
   empiriquement phase 2 (spikes + tests) avant toute revendication.

## 7. Critères d'acceptation du document

- [ ] Les 41 menaces de §19 du cahier des charges sont couvertes et reliées
      à des exigences SEC et des tests.
- [ ] Les limites §6 sont reprises telles quelles dans la documentation
      publique.
- [ ] Probabilités revues par un humain (validation Phase 0).

## 8. Risques connus

- Modèle statique : doit être révisé à chaque phase (gate de revue du modèle
  de menace dans `planning/SECURITY_REVIEW_CHECKLIST.md`).
- Arbres d'attaque non exhaustifs : complétés par le pentest (phase 10).
