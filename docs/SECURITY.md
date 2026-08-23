# POLITIQUE DE SÉCURITÉ (SECURITY.md)

> **Statut** : **Validé** — Phase 0 approuvée par décision humaine le 2026-08-21
> **Version** : 0.1 — 2026-08-21
> **Décisions ouvertes** : délais à valider par la gouvernance (DEC-04)
> **ADR liés** : aucun
> **Hypothèses clés** : aucune version n'est encore publiée ; les délais ci-dessous sont des engagements cibles proposés.

## Versions supportées

| Version | Support |
|---|---|
| aucune release publiée | — (phase de cadrage) |

(Ce tableau sera tenu à jour à chaque release ; politique de versions
proposée : dernière mineure + correctifs de la majeure précédente pendant
6 mois.)

## Signaler une vulnérabilité

1. **Canal préféré — GitHub Private Vulnerability Reporting** (activé le
   2026-08-22 sur `github.com/vigile-project/vigile`, vérifié) : onglet
   *Security → Advisories* → bouton *Report a vulnerability*. Suivi
   structuré, advisory privée, possibilité de demander un CVE via GitHub.
2. **Contact chiffré de secours** : `vigile.cdkfn@simplelogin.com` —
   chiffrez votre message avec la clé OpenPGP ci-dessous (canal défini le
   2026-08-21) ; utile hors GitHub.
3. **Contenu du signalement** : description, reproduction (PoC), impact
   estimé, versions concernées, coordonnées de retour.
4. **Ne pas ouvrir d'issue publique** pour une faille exploitable.

## Clé publique OpenPGP du contact sécurité

- Empreinte : `6EBC EDCE B072 BB4C 2245 9E56 7A53 6120 9A44 9E11`
- Type : Ed25519 (signature) / Cv25519 (chiffrement) — expiration :
  2028-08-20 (renouvellement prévu avant échéance).

```text
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEaoi1ExYJKwYBBAHaRw8BAQdAftY2zwKV14VTnHcKV1/tOw7MhmpyjsAO7Sbx
gIuLnIS0NlZpZ2lsZSBTZWN1cml0eSBDb250YWN0IDx2aWdpbGUuY2RrZm5Ac2lt
cGxlbG9naW4uY29tPoiZBBMWCgBBFiEEbrztzrByu0wiRZ5WelNhIJpEnhEFAmqI
tRMCGwMFCQPCZwAFCwkIBwICIgIGFQoJCAsCBBYCAwECHgcCF4AACgkQelNhIJpE
nhEmIQEAm5tAgkM8S3KGh/xGSw045aF+nssirZhKS8oh8cBrD2QA/1EyLWeDYsKG
HSZGXKN278Wu6ZGGuUBraOpj+GkyHL8MuDgEaoi1ExIKKwYBBAGXVQEFAQEHQFFm
nmWtduO2Q20QW5Njyn+LezICmcNEqE5gLkU+Y8RKAwEIB4h+BBgWCgAmFiEEbrzt
zrByu0wiRZ5WelNhIJpEnhEFAmqItRMCGwwFCQPCZwAACgkQelNhIJpEnhGZ4wD/
UaCHgVkePBafB4dAcX5HbAmLzwyAU8MUtuvV6CzEHJMBAIDrkQr+QWUQPbwizOKE
FlcudJMuk1HQ7WBF4GXvMDoL
=P9+b
-----END PGP PUBLIC KEY BLOCK-----
```

Cette clé est **spécifique au canal sécurité de Vigile** ; elle n'est ni
une clé de signature de code/release, ni une clé de la hiérarchie TUF
(KEY_MANAGEMENT.md — rôles séparés).

## Engagements cibles (propositions)

- Accusé de réception : ≤ 48 h ouvrées.
- Évaluation initiale et classification : ≤ 7 jours.
- Correction : vulnérabilités critiques/élevées priorisées ; délai de
  divulgation coordonnée par défaut 90 jours, ajustable d'un commun accord.
- Divulgation publique après correction + grâce raisonnable pour le déploiement.

## Périmètre couvert

Agent, exécuteur, serveur, portail, CLI, protocoles et artefacts de
distribution du projet. Les dépendances tierces : signaler d'abord en amont ;
nous suivre pour la coordination. Configuration non durcie, matériel, et
compromissions par root local volontaire : hors périmètre (voir
`THREAT_MODEL.md` §6, `NON_GOALS.md` NG-02).

## Safe harbor

La recherche de sécurité de bonne foi (pas d'accès à données d'autrui, pas
de DoS sur infrastructures partagées, pas de disclosure avant délai convenu)
est bienvenue et ne fera pas l'objet de poursuites.

## Critères d'acceptation du document

- [x] Contact et clé publiés (2026-08-21, avant toute release signée).
- [x] GitHub Private Vulnerability Reporting activé (2026-08-22, vérifié).
- [ ] Délais validés par la gouvernance (DEC-04).

## Risques connus

- Alias SimpleLogin : si l'alias est perdu/révoqué, le canal devient
  inopérant — garder un moyen documenté de migration (nouvelle adresse +
  nouvelle clé + note de version signée).
- Clé à échéance 2028-08-20 : renouvellement à inscrire au calendrier
  d'exploitation (rotation avant expiration, cf. KEY_MANAGEMENT.md).
