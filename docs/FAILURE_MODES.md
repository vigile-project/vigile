# MODES DE DÉFAILLANCE

> **Statut** : **Validé** — Phase 0 approuvée par décision humaine le 2026-08-21
> **Version** : 0.1 — 2026-08-21
> **Décisions ouvertes** : DEC-09 (bornes : dérive horloge, fenêtre de fraîcheur, délais de quarantaine)
> **ADR liés** : ADR-0010, ADR-0005
> **Hypothèses clés** : doctrine **fail-closed pour l'enforcement** ; un état dégradé est toujours nommé, exposé et audité ; la télémétrie peut être sacrifiée, jamais l'enforcement ni la capacité de rollback.

## 1. Principes

1. Conserver la **dernière politique valide** (LKG) ; ne jamais accepter une
   politique non vérifiée ; ne jamais supprimer une politique valide avant
   validation de la suivante.
2. Distinguer : perte de **télémétrie** (acceptable, dégradé) vs perte
   d'**enforcement** (critique, alerter) vs perte de **contrôlabilité**
   (critique, breaker + break-glass).
3. Pas de désactivation automatique de la protection. Pas de fail-open.
4. Toute défaillance produit : un état nommé + un journal + (si possible)
   une remontée serveur.

## 2. États nommés

| État | Signification | Enforcement | Télémétrie |
|---|---|---|---|
| `NOMINAL` | Tout va bien | actif | active |
| `DEGRADED_TELEMETRY` | Files pleines/perte réseau sortant | actif | différée/bornée |
| `DEGRADED_SERVER` | Serveur injoignable > seuil | actif (LKG) | locale (spool) |
| `ENFORCING_STALE` | Politique ancienne (au-delà de la fraîcheur attendue) | actif + avertissement admin | selon canal |
| `RECOVERY_MODE` | Transaction interrompue / redémarrage en cours | LKG dès que vérifiée | locale |
| `QUARANTINE` | Identité incohérente / clone / agent compromis | refus de synchronisation ; enforcement local maintenu | bloquée |
| `BREAK_GLASS` | Récupération locale activée (TTL) | réduit explicitement et temporairement | locale inaltérable + alerte différée |

## 3. Registre des défaillances (§10 du cahier des charges)

| ID | Défaillance | Détection | Comportement attendu | Récupération |
|---|---|---|---|---|
| FM-01 | Serveur central indisponible | Échecs successifs (backoff+jitter) | `DEGRADED_SERVER` ; enforcement LKG ; spool local borné ; retry continu | Retour auto ; rien à faire |
| FM-02 | DNS défaillant/hostile | Échec résolution ; échec validation TLS | Idem FM-01 ; jamais de contournement de la validation | DNS réparé ; serveur joignable par IP configurée si besoin |
| FM-03 | Certificat serveur expiré | Échec TLS | Idem FM-01 (l'agent **refuse**, n'ignore pas) | Renouvellement serveur |
| FM-04 | Certificat agent expiré | Avertissement T-30 j ; puis échec mTLS | Enforcement tenu ; `DEGRADED_SERVER` + alerte locale | Renouvellement assisté ; procédure de secours documentée (ré-enrôlement contrôlé) |
| FM-05 | Heure locale incorrecte | Dérive > bornes | Rejet des messages horodatés ; enforcement tenu (validité locale calculée sur horloge monotonic autant que possible) | Correction NTP ; horloge matérielle |
| FM-06 | Base locale corrompue (cache) | Hash/contrôle d'intégrité au démarrage | Re-téléchargement signé ; si politique illisible → LKG précédente ; si aucune → **refus par défaut maintenu** + urgence admin | Resynchronisation |
| FM-07 | Politique invalide reçue | Validation avant application | Refus avec raison explicite ; conservation LKG ; événement serveur | Nouvelle version corrigée |
| FM-08 | Disque plein | Alertes seuils 80/95 % | Télémétrie élaguée en dernier ; enforcement continue ; journaux de sécurité priorisés ; refus d'événements non critiques avec compteur | Purge documentée + alerte admin |
| FM-09 | fapolicyd arrêté | Watchdog systemd + health check | Redémarrage automatique ; si impossible : état critique visible, alerte, **jamais** de bascule permissive | Investiguation ; redéploiement |
| FM-10 | SELinux/AppArmor refuse une action de l'agent | AVC/denial dans les journaux | Transaction échoue → rollback ; alerte ; pas de contournement | Politique MAC de l'agent corrigée (package fourni) |
| FM-11 | nftables refuse le nouveau ruleset (ph.7) | Échec de la transaction de lot | Rollback atomique du lot ; conservation des règles précédentes | Correction puis nouvelle tentative |
| FM-12 | USBGuard indisponible (ph.4) | Health check | Dépend de la config : sur poste critique → échec **fermant** (périphériques non approuvés refusés, clavier préservé par politique matériel le permettant — à valider, NON VÉRIFIÉ) | Redémarrage/repair |
| FM-13 | Mise à jour de distribution change les chemins | Inventaire post-update ; règles invalides | Détection d'incohérence ; recompilation depuis l'IR (chemins recalculés) ; si échec → LKG + alerte | Nouvelle politique adaptée |
| FM-14 | Backend disparaît | Capacités re-détectées | Déclaration « non applicable » propre (jamais de simulation) ; alerte admin | Retrait du backend du périmètre concerné |
| FM-15 | Redémarrage pendant transaction | Journal de transaction au démarrage | `RECOVERY_MODE` : reprise du journal ou retour LKG ; jamais d'état moitié-appliqué | Vérification d'intégrité puis resynchronisation |
| FM-16 | Rollback impossible (LKG corrompue) | Vérification d'intégrité de la sauvegarde | **Refus de la nouvelle politique** (la transaction exige un LKG sain) ; état critique | Resynchronisation depuis serveur ; break-glass si serveur inaccessible |
| FM-17 | Tempête d'événements | Files/profondeurs | Agrégation, priorisation, élagage ; limitation en amont (agent) | Le taux redescend ; rapports |
| FM-18 | Snapshot ancien restauré (VM) | Compteur/génération régressée à la sync | Quarantaine jusqu'à validation ; anti-rollback refusant l'état ancien | Intervention admin ; rotation clés si suspicion |

## 4. Matrice « fail-open / fail-closed » (décision ADR-0010)

| Fonction | Défaillance | Comportement | Justification |
|---|---|---|---|
| Décision d'exécution (allowlist) | Backend absent/arrêté | **fail-closed** (refus), sauf périphériques d'entrée essentiels documentés (clavier : voir FM-12, décision explicite) | Cœur du produit |
| Synchronisation politique | Serveur injoignable / signature invalide | **fail-closed** (garde LKG) | Anti-TM-001/018 |
| Télémétrie | files pleines/réseau coupé | **fail-open autorisé mais visible** (perte de visibilité seulement) | La télémétrie ne doit jamais conditionner l'enforcement |
| Notifications utilisateur | session absente (headless) | silencieux, événement journalisé | Pas de sécurité en jeu |
| Approbations temporaires | expiration atteinte hors ligne | **fail-closed** (l'exception expire) | SEC-303 |

## 5. Visibilité

- Chaque état dégradé est exposé : localement (`GetState`, portail de statut
  utilisateur), côté admin (portail, métriques), dans l'audit.
- Le heartbeat transporte l'état nominal/dégradé ; en cas de perte du canal,
  l'**absence** de heartbeat est elle-même une alerte (défaut de contact).

## 6. Critères d'acceptation du document

- [ ] Chaque FM est couvert par au moins un test chaos (§22-E) nommé.
- [ ] Les états §2 sont repris tels quels dans l'implémentation (noms stables).
- [ ] La matrice §4 validée par la revue (notamment le cas clavier FM-12,
      seul fail-open partiel envisagé, et encore : à décision explicite).

## 7. Risques connus

- FM-12 (USBGuard + clavier) : risque de verrouillage physique ; le choix
  final exige des tests matériels (phase 4) avant tout enforcement.
- FM-05 : horloges dérivantes restent un angle mort partiel ; mitigation par
  fenêtres de validité larges + compteur monotone local.
- Le comportement « LKG » suppose un stockage local fiable ; corruption
    multi-niveaux traitée en FM-06/16 mais testée explicitement.
