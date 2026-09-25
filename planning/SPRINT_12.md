# SPRINT 12 — Phase 10 : durcissement production & qualification

> **Statut** : **Terminé** — ouvert le 2026-09-11, clos le 2026-09-25
> **Gate de sortie franchie** : tag signé `0.1.0-rc1` (clé Vigile Security
> Contact 9A449E11), revue sécurité A→I complète, 42 suites de tests
> vertes, exercice DR chronométré. Les issues 087→093 sont closes ;
> écarts restants tracés dans le backlog (090-2/4/5, P2/P3).
> **Périmètre** : qualification production selon ROADMAP (audit externe,
> pentest, charge, DR, rotation, pilote, RC). Gate de sortie : critères §30
> du cahier des charges + checklist de revue de sécurité complète
> (sections A→I + revue pré-release).
> **Prérequis vérifiés** : pipeline end-to-end prouvé le 2026-09-11
> (portail → compile → GET /agent/v1/policy → agent deploy → validation
> fapolicyd-cli → déploiement plat rules.d → daemon → événements FANOTIFY).

## Constat d'entrée (dette technique bloquante pour la qualification)

Le pipeline fonctionne mais trois garanties conçues ne sont **pas encore
effectives** sur le chemin de production :

1. **Transport chiffré** : le serveur écoute en HTTP brut (parseur maison
   strict, mais pas de TLS). Le portail et l'API admin transitent en clair.
2. **Signature des règles** : l'agent déploie les règles servies par
   `/agent/v1/policy` sans vérifier de signature (le manifeste SHA-256 est
   produit mais non contrôlé côté agent, et non signé côté serveur).
3. **Persistance** : la politique compilée vit en mémoire du serveur
   (`DeployedPolicy`) — un redémarrage la perd ; les jetons admin sont
   comparés en clair.

## Issues détaillées (ISS-087..093)

| Issue | Objet | Critère de sortie | Priorité |
|---|---|---|---|
| ISS-087 | **mTLS effectif agent↔serveur** : TLS sur la boucle de service (certificats de la hiérarchie Ed25519 existante), l'agent présente son certificat, le serveur vérifie ; anti-rejeu sur les requêtes agent | `curl -k` refusé, connexion sans certificat client rejetée, test négatif présent | P0 |
| ISS-088 | **Règles signées de bout en bout** : le serveur signe le manifeste (clé de signature du déploiement), l'agent vérifie signature + SHA-256 avant staging ; refus en cas d'échec | Test négatif : manifeste altéré → déploiement refusé + audit | P0 |
| ISS-089 | **Persistance & secrets serveur** : politiques compilées persistées (stockage signé, redémarrage sans perte), jetons admin stockés hachés (argon2/balloon), rotation des jetons | Test : redémarrage serveur → politique toujours servie ; jeton volé en base inutilisable | P0 |
| ISS-090 | **Auto-revue sécurité complète** : checklist A→I passée sur tout le workspace, chaque case cochée ou justifiée par écrit ; résolution des « NON VÉRIFIÉ » restants | Document de revue daté + issues tracées pour tout écart | P0 |
| ISS-091 | **Charge & limites** : fuzz du parseur HTTP maison (corpus + aléatoire), test de débit agent→serveur, bornes documentées (16 KiB/16 MiB), DoS local | Rapport de fuzz sans crash ; limites testées | P1 |
| ISS-092 | **DR & procédures** : runbook reprise 1 page (perte serveur, reconstruction CA, break-glass déjà couvert), exercice labo chronométré, scénarios chaos à jour (FAILURE_MODES) | Exercice exécuté et documenté | P1 |
| ISS-093 | **Release candidate 0.1.0-rc1** : SBOM/provenance RPM régénérés, reproductibilité vérifiée, tag signé (clé OpenPGP du projet), SECURITY.md (versions supportées), pilote sur le poste labo en mode audit | RC tagguée + note de release | P1 |

## Ordre d'attaque

1. ISS-087 → 088 → 089 (les trois garanties P0, dans cet ordre : transport,
   puis intégrité, puis persistance — chacun réutilise le précédent).
2. ISS-090 (revue exhaustive, validera 087-089 au passage).
3. ISS-091/092 en parallèle.
4. ISS-093 en clôture (figeage).

## Hygiène labo (pré-pilote)

Avant tout test *enforcing* sur le poste de développement : réconcilier les
règles expérimentales issues de la session de durcissement
(`90-deny-execute.rules`, `95-allow-open.rules` — désormais shadowées par le
catch-all audit, mais sources de surprise en mode bloquant). Consigne : ne
jamais passer en enforcing avec des règles non générées par Vigile dans
`rules.d/`.

## Risques spécifiques

- Le parseur HTTP maison passe sous TLS : décider si on conserve le parseur
  (durci par le fuzz ISS-091) ou si TLS impose une réorganisation de la
  boucle de service — trancher par ADR si écart.
- Audit externe et pentest réels supposent un budget/tiers : à décider avec
  le propriétaire du projet (voir DECISIONS_NEEDED).
