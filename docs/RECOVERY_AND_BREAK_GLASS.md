# RÉCUPÉRATION ET BREAK-GLASS

> **Statut** : **Validé** — Phase 0 approuvée par décision humaine le 2026-08-21
> **Version** : 0.1 — 2026-08-21
> **Décisions ouvertes** : DEC-09 (TTL break-glass, conditions exactes), DEC-05 (support du kit de récupération)
> **ADR liés** : ADR-0010, ADR-0005
> **Hypothèses clés** : le break-glass est une procédure **locale, contrainte, bruyante et révocable** ; ce n'est jamais une porte dérobée universelle ni une désactivation à distance.

## 1. Exigences (§10 du cahier des charges)

Documenté ; physiquement ou localement contraint ; limité dans le temps ;
audité ; difficile à utiliser discrètement ; sans porte dérobée universelle ;
révocable ; testé régulièrement.

## 2. Conception proposée

### 2.1 Déclencheur (local uniquement)

```
# Console physique (ou SSH déclaré critique) — jamais à distance via le serveur
sudo vigile-breakglass --reason "..." --ticket INC-1234 --code <code local>
```

- Nécessite **root local + présence physique** (TTTY console par défaut,
  configurable) : par conception, le fait d'être root suffit déjà à casser
  l'agent (TM-005) ; l'intérêt du break-glass est de le faire **proprement,
  de façon tracée et réversible**.
- **Code local** : scellé à l'installation (dérivé d'un secret généré
  localement, stocké root-only, jamais transmis au serveur) OU token
  d'urgence émis par le serveur quand il est joignable (double option).
- Justification + ticket **obligatoires** (SEC-304).

### 2.2 Effet (borné)

1. Retour immédiat à la **last known good** (jamais désactivation totale).
2. Bascule **temporaire et ciblée** en mode audit-only pour les backends
   d'exécution uniquement, TTL maximal (proposition : 4 h — DEC-09) ;
   l'agent, l'exécuteur, le rollback et les services protégés restent
   intacts.
3. Journal local **inaltérable** (append-only, hash chaîné) + file
   d'alerte vers le serveur (envoyée dès que possible).
4. Fin : TTL expiré ou annulation explicite → retour automatique en
   enforcement LKG.

### 2.3 Propriétés vérifiées par tests

| Propriété | Test |
|---|---|
| Auditable localement même hors ligne | Journal consultable sans serveur |
| Bruyant | Alerte admin automatique à la prochaine sync + métrique dédiée |
| Limité dans le temps | TTL non contournable sans root (et root = TM-005, détection) |
| Révocable | Admin peut révoquer les codes d'urgence distants |
| Pas de porte dérobée | Aucun secret universel ; le code est local à la machine |
| Testé | Exercice trimestriel planifié + test CI T-BG-01..05 |

## 3. Récupération hors ligne (auto-blocage d'une machine)

Procédure documentée opérateur (poster runbook) :

1. Diagnostic : état affiché (`GetState`), journaux de transaction.
2. Si transaction échouée : rollback automatique déjà tenté ; sinon
   `vigile-breakglass --rollback-only` (retour LKG sans mode audit).
3. Si LKG corrompue : kit de récupération — média signé (RPM de secours +
   ancre de confiance) préparé par l'opérateur, vérification de signature
   obligatoire à l'usage.
4. Dernier recours : désinstallation propre documentée (elle-même journalisée
   et signalée au serveur dès que possible — jamais silencieuse).

## 4. Récupération du serveur (PRA)

1. **Sauvegardes** : PostgreSQL chiffré + artefacts signés + métadonnées TUF ;
   tests de restauration périodiques obligatoires (« une sauvegarde non
   restaurée n'existe pas »).
2. **Reconstruction** : les agents restent en enforcement LKG pendant
   l'indisponibilité (FM-01) ; au retour : vérification des métadonnées
   (fraîcheur, versions) avant reprise.
3. **Perte totale (clés comprises)** : cérémonie de re-racage TUF (ADR-0005,
   KEY_MANAGEMENT.md §4) + ré-enrôlement planifié du parc.
4. **DR testé** avant qualification production (critère §30).

## 5. Rôles et responsabilités

| Acteur | Responsabilité |
|---|---|
| Opérateur site | Exécution du runbook local, break-glass justifié |
| Admin sécurité | Analyse des alertes break-glass, révocation des codes d'urgence |
| Équipe plateforme | Exercices trimestriels, maintien des kits, PRA serveur |
| Auditeur | Revue systématique de tous les événements break-glass |

## 6. Critères d'acceptation du document

- [ ] Conception validée (notamment TTL, mode « rollback-only », double
      option code local/token serveur).
- [ ] Runbook « machine bloquée » rédigé en une page et testé en labo.
- [ ] Exercice trimestriel inscrit au calendrier d'exploitation.

## 7. Risques connus

- Abus du break-glass comme routine : mitigation par alertes, revue
  auditeur, TTL court.
- Code local volé avec root : équivalent TM-005 (détection au retour en
  ligne) ; le code seul sans root ne suffit pas.
- Kits de récupération périmés : checklist de péremption + re-signature à
  chaque rotation de clés (lien KEY_MANAGEMENT.md).
