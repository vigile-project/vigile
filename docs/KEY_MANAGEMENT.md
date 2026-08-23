# GESTION DES CLÉS

> **Statut** : **Validé** — Phase 0 approuvée par décision humaine le 2026-08-21
> **Version** : 0.1 — 2026-08-21
> **Décisions ouvertes** : DEC-08 (garde des clés racines : personnes, lieu, procédure), DEC-09 (paramètres chiffrés : durées, seuils), DEC-11 (HSM au MVP ou plus tard)
> **ADR liés** : ADR-0004, ADR-0005
> **Hypothèses clés** : Ed25519 pour les signatures d'artefacts ; X.509/P-256 ou Ed25519 pour TLS (aujourd'hui standard) ; RSA possible pour compatibilité HSM — décision d'implémentation (NON VÉRIFIÉ jusqu'au spike matériel).

## 1. Hiérarchie

| Rôle | Emplacement | Usage | Seuil | Rotation proposée |
|---|---|---|---|---|
| Clé racine **TUF** | Hors ligne (supports physiques, 3+ dépositaires) | Signer les rôles racine ; révoquer/renouveler les rôles opérationnels ; récupération | k-of-n (proposition 2/3 — DEC-09) | 2–5 ans + à chaque compromission |
| Rôle **targets** TUF | Service de signature (machine isolée TB-5) | Référencer les artefacts de mise à jour | 1/1 (ou 2/2 prod) | 90 j |
| Rôles **snapshot/timestamp** TUF | Serveur de mise à jour | Fraîcheur anti-freeze | 1/1 | automatique (timestamp : horaire) |
| Clé **politiques** | Service de signature | Signer les enveloppes de politiques | 1/2 labo ; **2/3 enforcement production** | 90 j |
| **CA agents** (racine) | Hors ligne | Émettre l'intermédiaire | k-of-n | 5 ans |
| **CA agents** (intermédiaire) | Serveur identité | Certificats clients agents | 1/1 + journalisation | 1 an |
| Clé **agent** | Machine locale (option TPM) | mTLS client | — | certificat 90 j, clé à rotation sur événement |
| Clé du **site web** | Serveur | TLS portail/API | — | automatique |

## 2. Règles impératives

1. **Aucune clé privée globale dans les images/paquets d'installation**
   (SEC-108) ; l'agent n'embarque que l'ancre de confiance (certificats
   publics).
2. La racine signe peu : rôles TUF, intermédiaires CA, révocations.
   Tout le reste est opérationnel et révocable.
3. Les seuils rendent une compromise isolée insuffisante pour distribuer une
   politique d'enforcement (TM-001/TM-011).
4. Toute signature est journalisée (quoi, qui, quand, référence
   d'approbation) — y compris les signatures **refusées**.
5. Les clés racines ne sont **jamais** présentes sur les serveurs en ligne,
   ni dans la CI, ni accessibles aux agents IA (charte §27).

## 3. Enrôlement et certificats agents

- Émission : intermédiaire CA en ligne, profil contraint (EKU clientAuth,
  SAN=agent_id, durée 90 j) ; journaux d'émission consultables.
- Rotation : automatique à T-30 j (SEC-104), chevauchement de validité pour
  tolérer les dérives d'horloge bornées.
- Révocation : liste de révocation signée publiée via le canal TUF + vérification
  à chaque connexion ; test « certificat révoqué refuse sous délai » (SEC-105).
- Option TPM : clé non extractible ; l'EK/le certificat AI attestent la
  machine (lien inventaire) — jamais obligatoire au MVP.

## 4. Compromission et récupération (playbooks)

| Clé compromise | Action immédiate | Coût/conséquence |
|---|---|---|
| Clé agent | Révocation (l'agent est refusé) ; ré-enrôlement contrôlé | Machine isolée jusqu'à intervention |
| CA intermédiaire | CRL totale ; ré-émission par nouvel intermédiaire signé racine | Perte de connectivité temporaire ; enforcement local tenu |
| Clé politiques (op.) | Révocation via rôles TUF ; seuil → compromis simple insuffisant | Fenêtre = délai de propagation de la révocation (testé) |
| Rôle targets/snapshot | Rotation par racine (cérémonie hors ligne) | Déploiement de nouvelles métadonnées ; agents refusent les anciennes après fenêtre |
| Racine TUF | Cérémonie de replacement complète (k-of-n des dépositaires) | Chantier lourd, plan de continuité requis (exercice avant production) |

Chaque playbook est un **exercice testé** (phase 10, `TEST_STRATEGY.md`),
pas un document théorique.

## 5. Cérémonies

- Création/rotation racine : procédure documentée, 2+ témoins, supports
  vérifiés (hash croisés), journal signé, matériel dédié hors ligne.
- Journal des cérémonies conservé avec l'audit, exportable.

## 6. HSM / TPM

- Production critique : clés opérationnelles et intermédiaires dans un HSM
  (PKCS#11 ou équivalent) — **décision DEC-11** (coût vs risque au MVP).
- TPM agent : option documentée ; l'absence de TPM ne doit jamais empêcher
  l'enrôlement (MVP).

## 7. Critères d'acceptation du document

- [ ] Hiérarchie, seuils et durées validés (humain, DEC-09).
- [ ] Les 5 playbooks de compromission convertis en exercices planifiés
      (phase 10) avec critères de réussite.
- [ ] Vérifié qu'aucune procédure n'exige de `curl | sh` ni de secret en
      ligne de commande.

## 8. Risques connus

- Perte des supports racines = perte de capacité de récupération :
  mitigation = n dépositaires géographiquement séparés + copies testées.
- HSM au MVP : surcoût ; sans HSM, la sécurité repose sur l'isolation du
  service de signature + seuils (risque accepté explicitement, DEC-11).
- Rotation à 90 j non testée en conditions réelles avant la phase 10 :
  exercice requis avant qualification.
