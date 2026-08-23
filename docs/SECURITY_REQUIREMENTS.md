# EXIGENCES DE SÉCURITÉ

> **Statut** : **Validé** — Phase 0 approuvée par décision humaine le 2026-08-21
> **Version** : 0.1 — 2026-08-21
> **Décisions ouvertes** : DEC-07 (bibliothèques de signature/CA exactes), DEC-08 (politique de conservation des clés racines), DEC-09 (seuils chiffrés exacts)
> **ADR liés** : ADR-0001, ADR-0002, ADR-0003, ADR-0004, ADR-0005, ADR-0010
> **Hypothèses clés** : chaque exigence est **vérifiable** ; la colonne « Vérification » indique le moyen de preuve exigé avant toute qualification.

Règle transverse : toute exigence SEC doit posséder au moins un **test
négatif** (démonstration que le système refuse/détecte le cas contraire)
avant d'être déclarée implémentée.

## 1. Identités et authentification

| ID | Exigence | Vérification |
|---|---|---|
| SEC-101 | Chaque agent possède une identité unique (certificat client X.509 émis par la PKI du projet) ; aucun secret partagé entre agents | Test : deux agents avec même identité → second refusé + quarantaine |
| SEC-102 | L'enrôlement utilise un **token à usage unique**, à durée de vie bornée, signé, lié au tenant | Tests : rejeu de token refusé ; token expiré refusé ; token non signé refusé |
| SEC-103 | mTLS obligatoire agent↔serveur ; TLS 1.3 (1.2 minimum avec suites actuelles) ; validation stricte des certificats (chaîne, SAN, EKU, expiration) | Test : connexion sans certificat client refusée ; certificat expiré/révoqué refusé |
| SEC-104 | Rotation automatique des certificats agent avant expiration, sans intervention | Test : rotation forcée à T-Δ ; agent sans perte de fonction |
| SEC-105 | Révocation effective : un certificat révoqué ne peut plus synchroniser de politique | Test : révocation → échec de connexion sous délai défini |
| SEC-106 | Anti-rejeu : chaque message contient nonce serveur + compteur monotone agent ; horodatage avec dérive tolérée bornée | Tests : rejeu détecté ; compteur régressé détecté ; horloge falsifiée détectée selon bornes |
| SEC-107 | Protection du clonage : image machine clonée (même machine-id/certificat) détectée et mise en quarantaine | Test : clone de VM → quarantaine à la première synchronisation |
| SEC-108 | Aucune clé privée globale dans les images ou paquets d'installation | Revue de packaging + test d'absence en environnement propre |
| SEC-109 | Option : clé agent protégée par TPM 2.0 (non extractible) — optionnel, jamais requis par le MVP | Test de plateforme TPM si activé |
| SEC-110 | Administration : MFA obligatoire (WebAuthn/passkeys recommandé) pour tous les rôles sauf viewer local ; réauthentification avant opérations critiques | Tests : accès sans MFA refusé ; step-up exigé |

## 2. Signatures et intégrité

| ID | Exigence | Vérification |
|---|---|---|
| SEC-201 | Toute politique distribuée est **signée** (Ed25519) dans une enveloppe contenant les métadonnées §7 du cahier des charges (id, tenant, version monotone, génération, digest, dates, audience, groupe cible, version minimale d'agent, version de schéma, signataire, approbations) | Tests : signature invalide refusée ; champ manquant refusé ; signataire non autorisé refusé |
| SEC-202 | Canonisation déterministe du contenu signé (JSON canonique RFC 8785) | Test : deux encodages équivalents → même digest |
| SEC-203 | Anti-rollback : version et génération monotones refusent toute politique plus ancienne ou déjà vue, même signée | Tests : rejeu d'une version N-1 refusé ; rejeu d'une génération ancienne refusé |
| SEC-204 | Anti-freeze : métadonnées horodatées avec fenêtre de fraîcheur maximale ; expiration des métadonnées | Test : distribution de métadonnées périmées refusée |
| SEC-205 | Seuil de signatures (k-of-n) pour les politiques d'enforcement de production | Test : politique à seuil insuffisant refusée |
| SEC-206 | Distribution des mises à jour conforme TUF (ou alternative formellement justifiée) | Audit de conformité + tests rollback/freeze TUF |
| SEC-207 | Vérification de l'audience : une politique destinée à un groupe/tenant ne s'applique pas ailleurs | Tests : mauvais tenant refusé ; mauvais groupe refusé |
| SEC-208 | L'agent vérifie la signature et le schéma **avant** toute écriture locale ; refus des champs inconnus pour les messages critiques | Tests : champ inconnu rejeté ; schéma invalide rejeté |
| SEC-209 | Artefacts compilés déterministes, hashés et rattachés à la politique source (preuve de correspondance) | Test de reproductibilité : deux compilations → octets identiques |

## 3. Autorisation

| ID | Exigence | Vérification |
|---|---|---|
| SEC-301 | RBAC strict avec les rôles §8 ; moindre privilège par défaut | Tests par rôle : action interdite → 403 + audit |
| SEC-302 | Séparation auteur/approbateur ; quatre yeux pour enforcement, signatures critiques, break-glass | Test : même acteur ne peut pas auto-approuver |
| SEC-303 | Toute autorisation temporaire **expire automatiquement**, y compris serveur indisponible (validité locale portée par la politique signée) | Test : serveur coupé, exception expirée → non honorée |
| SEC-304 | Justification + référence de ticket obligatoires pour approbations et break-glass | Test : soumission sans justification refusée |
| SEC-305 | Journal d'audit append-only côté application ; impossible à effacer via l'API, même platform-admin | Test : tentative de suppression/modification → refus + audit |
| SEC-306 | Alertes automatiques lors des usages break-glass et des rôles sensibles | Test : déclenchement vérifié |
| SEC-307 | Prévention IDOR et confusion de tenant : filtrage serveur systématique, `tenant_id` jamais issu du client | Tests IDOR/tenant (suite dédiée) |

## 4. Exécution privilégiée minimale

| ID | Exigence | Vérification |
|---|---|---|
| SEC-401 | L'exécuteur privilégié n'interprète **aucun shell** ; actions strictement typées via IPC local versionné | Revue de code + test : toute action non typée rejetée |
| SEC-402 | Chemins normalisés (rejet des chemins relatifs, `..`, doubles slashs) ; rejet des symlinks (O_NOFOLLOW) ; répertoires parents contrôlés | Tests : path traversal, symlink attack, TOCTOU |
| SEC-403 | Aucune configuration non signée acceptée ; aucun plugin distant chargé | Tests : config non signée rejetée |
| SEC-404 | Limites : tailles de messages, délais, nombre d'actions, ressources mémoire/CPU ; comportement borné sous tempête | Tests de saturation/DoS local |
| SEC-405 | Unités systemd restrictives : `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, capabilities minimales, `SystemCallFilter` (seccomp) justifié et testé | Revue des unités + test de survie des fonctions critiques |
| SEC-406 | Abandon de toutes les capacités Linux inutiles ; pas de `CAP_SYS_ADMIN` résiduel | Audit runtime (capsh/proc) |
| SEC-407 | Journalisation locale de toute modification privilégiée (avant/après, hash) | Test : chaque action produit une entrée |
| SEC-408 | Aucun secret dans les arguments de processus ni les URLs | Revue + test (inspection /proc, logs) |

## 5. Transactions et rollback

| ID | Exigence | Vérification |
|---|---|---|
| SEC-501 | Toute application locale suit la séquence transactionnelle §11 (vérification → sauvegarde → écriture temporaire → validation native → remplacement atomique → rechargement → santé → confirmation/rollback) | Tests d'interruption à chaque étape (kill -9, coupure secteur simulée) |
| SEC-502 | fsync des fichiers et répertoires avant remplacement atomique (rename) | Test de coupure pendant écriture |
| SEC-503 | Rollback automatique si le test de santé échoue ; l'état précédent n'est jamais détruit avant validation du nouvel état | Tests : santé défaillante → rollback ; vérification LKG intact |
| SEC-504 | Règles nftables appliquées en lot transactionnel (`atomic` operations) le cas échéant (phase 7) | Test phase 7 |
| SEC-505 | Fichiers créés : permissions minimales, propriétaire explicite, étiquetage SELinux correct | Tests en VM enforcing |

## 6. Modes de défaillance

| ID | Exigence | Vérification |
|---|---|---|
| SEC-601 | Fail-closed pour l'enforcement : perte serveur/DNS/certificat → **maintien** de la dernière politique valide ; jamais de désactivation automatique de la protection | Tests chaos (§22-E) |
| SEC-602 | Distinction explicite perte de télémétrie / perte d'enforcement ; états dégradés nommés et exposés | Test d'observation des états |
| SEC-603 | Une politique invalide ou non applicable est refusée proprement avec raison explicite ; jamais de champ ignoré silencieusement | Tests : politique avec champ non supporté → erreur, pas un avertissement muet |
| SEC-604 | Disque plein : l'enforcement continue ; la télémétrie est élaguée en dernier recours selon une politique documentée | Test disque plein simulé |
| SEC-605 | Redémarrage pendant transaction : reprise cohérente (journal) ou retour LKG | Test reboot pendant application |

## 7. Journalisation et audit

| ID | Exigence | Vérification |
|---|---|---|
| SEC-701 | Journal d'audit conforme §17 : acteur, action, cible, avant/après, horodatage, session, origine, tenant, justification, ticket, résultat, approbateurs, version, hash d'artefacts | Revue de couverture + tests |
| SEC-702 | Chaînage cryptographique ou signature périodique du journal ; export WORM possible | Test de détection d'altération |
| SEC-703 | Interdits dans les journaux : mots de passe, tokens complets, clés privées, variables d'environnement sensibles, lignes de commande avec secrets (sauf rédaction robuste testée) | Tests de rédaction + revue |
| SEC-704 | Rétention configurable ; tests d'intégrité du journal après rotation | Test de rotation |

## 8. Protection contre l'auto-blocage

| ID | Exigence | Vérification |
|---|---|---|
| SEC-801 | Liste protégée minimale (§12) appliquée par le compilateur : agent, exécuteur, rollback, sshd si déclaré critique, gestionnaire de paquets, composants de session GNOME requis, outils SELinux/fapolicyd | Tests D (§22) : boot, login GNOME, SSH, mises à jour, DNS, certificats |
| SEC-802 | Simulation obligatoire avant déploiement d'une politique bloquante (redémarrage, login, refresh, rollback, mise à jour agent, récupération locale, connectivité, DNS, renouvellement) | Gate CI : déploiement impossible sans simulation passée |
| SEC-803 | Seuils automatiques d'arrêt (refus anormaux, pertes de contact, échecs login, rollbacks répétés) avec pause automatique du déploiement | Tests de seuil en labo |
| SEC-804 | La liste protégée reste minimale ; toute extension exige un ADR | Revue périodique |

## 9. Chaîne logistique

| ID | Exigence | Vérification |
|---|---|---|
| SEC-901 | Dépendances verrouillées ; revue de tout changement de lockfile en PR | Gate CI |
| SEC-902 | SBOM (CycloneDX ou SPDX) publié par build ; provenance de build (SLSA, cible progressif) | Test d'artefact de release |
| SEC-903 | Builds reproductibles vérifiés en CI pour RPM/DEB/Nix | Test : deux builds → mêmes hash |
| SEC-904 | Paquets et dépôts signés ; aucune exécution `curl \| sh` nulle part | Revue + scan |
| SEC-905 | Clés racines hors ligne ; seuils ; cérémonies documentées ; rotation testée | Exercice de rotation documenté |
| SEC-906 | SAST, analyse de secrets, analyse de licences, fuzzing des parseurs en CI | Rapports CI |

## 10. Confidentialité

| ID | Exigence | Vérification |
|---|---|---|
| SEC-1001 | Collecte limitée aux métadonnées indispensables ; aucun contenu de fichier utilisateur | Revue des schémas de télémétrie |
| SEC-1002 | Effacement des secrets en mémoire lorsque réaliste (types dédiés) | Revue de code |
| SEC-1003 | Documentation publique de la nature exacte des données collectées | Doc publiée et relue |

## 11. Critères d'acceptation du document

- [ ] Chaque SEC est traçable vers : un test (TEST_STRATEGY.md), une menace
      (THREAT_MODEL.md) lorsque pertinent, et une issue (BACKLOG.md).
- [ ] Aucune exigence ne repose sur une information NON VÉRIFIÉE.
- [ ] La règle « test négatif obligatoire » est acceptée comme gate de revue.

## 12. Risques connus

- Certaines bibliothèques précises (signature, CA, TPM) restent à choisir
  (DEC-07) ; les exigences restent au niveau des propriétés attendues.
- Les seuils chiffrés (dérive horloge, fenêtre de fraîcheur, quotas) sont
  des propositions à calibrer (DEC-09) par des tests.
