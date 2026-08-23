# PROPOSITION DE SPRINT 1

> **Statut** : **Validé** — Phase 0 approuvée par décision humaine le 2026-08-21 (pré-requis : validation de la phase 0)
> **Version** : 0.1 — 2026-08-21
> **Décisions ouvertes** : DEC-01/02/03/15 tranchées le 2026-08-21 (Vigile, AGPL-3.0+, GitHub, EN public/FR interne). DEC-04 (gouvernance) et DEC-05 (versions cibles) : défauts provisoires appliqués (fondateur mainteneur initial + DCO ; Fedora 44+43) — à formaliser.
> **ADR liés** : ADR-0001, ADR-0003, ADR-0004, ADR-0005
> **Hypothèses clés** : durée 2 semaines ; équipe hypothétique 2-3 développeurs + 1 révueur sécurité ; objectif = **réduire les risques techniques avant tout engagement**.

## Objectif

Établir l'ossature du projet et lever les trois incertitudes techniques
majeures (crypto/canonisation, fapolicyd réel, TUF) par des spikes à
livrables mesurables. **Aucune fonctionnalité produit** dans ce sprint.

### Avancement (2026-08-21, soir)

- **Faites** : ISS-001, ISS-002 (CI locale fmt/clippy/tests verts ; gitleaks
  et pin des actions à la création de l'org GitHub), ISS-003 ;
  **ISS-007 (GO)** — canonisation JCS validée sur les vecteurs officiels
  RFC 8785 ; découverte critique : feature `float_roundtrip` de serde_json
  **obligatoire** (sinon arrondi à 1 ULP) ; **ISS-010** — schéma
  `policy/v0` + canonisation + validation stricte intégrés dans
  `vigile-policy` (serde_json, ryu, jsonschema 0.50 **sans résolution
  réseau**), 15 suites de tests vertes, clippy strict 0 erreur ;
  **ISS-006 (GO conditionnel)** — rustls 0.23 + rcgen 0.14 + x509-cert 0.3
  (CRL) recommandés, backend crypto (ring vs aws-lc-rs) à trancher par
  prototype ; **ISS-008 (GO)** — fapolicyd 2.0-1.fc44 vérifié, capacités
  réelles cartographiées (scripts par hash confirmés ; bash interactif,
  NFS client, conteneurs, memfd : non couverts → à déclarer non
  applicables) ; **ISS-009 (GO)** — `tough` 0.24.0 + `tuftool` retenus,
  prototype de validation en 10 points défini. Rapports : `docs/spikes/`.
- **ISS-004 close** : canal `vigile.cdkfn@simplelogin.com` + clé OpenPGP
  Ed25519 (`6EBC…9E11`, expiration 2028-08-20) publiés dans
  `docs/SECURITY.md` ; **GitHub Private Vulnerability Reporting activé le
  2026-08-22** sur `github.com/vigile-project/vigile` (bouton
  « Report a vulnerability » vérifié) — canal préféré.
- **ISS-005 faite** (2026-08-21, soir) : harnais `tests/vm/` opérationnel —
  QEMU **mode utilisateur** (aucun privilège ni démon ; libvirt absent de
  l'hôte), image Fedora Cloud 44 vérifiée (CHECKSUM **signé GPG** avec les
  clés Fedora locales + SHA-256), seed cloud-init (clé SSH jetable),
  boot→SSH en ~10 s, scénario smoke complet passé : installation
  **fapolicyd 2.0-1.fc44** (confirme empiriquement le spike ISS-008),
  service **jamais démarré**, validation hors ligne `fapolicyd-cli
  --check-rules` OK (« 14 rules » — valide SEC-501), VM arrêtée proprement.
- Toolchain Rust 1.98.0 installée côté utilisateur (rustup-init officiel,
  sans sudo, sans `curl | sh`).

**Sprint 1 : 10 issues sur 10 closes.** Le critère de sortie n°3 est
partiellement couvert : version fapolicyd F44 et `--check-rules` vérifiées
empiriquement ; les items restants (memfd, objet supprimé) sont des
scénarios de la phase 2.

## Périmètre (issues `planning/BACKLOG.md` — M0)

| Issue | Livrable de fin de sprint |
|---|---|
| ISS-001 | Dépôt opérationnel : ossature, workspace cargo, web/ vide, LICENSE |
| ISS-002 | CI verte : fmt, clippy strict, deny/audit, SAST, secrets |
| ISS-003 | Templates PR (volet sécurité + IA + dépendances) appliqués |
| ISS-004 | SECURITY.md opérationnel (contact + clé publiés) |
| ISS-005 | Harnais VM : 1 VM Fedora WS + 1 Server provisionnées et pilotables, 1 scénario « smoke » |
| ISS-006 (spike) | Rapport : bibliothèques TLS/PKI retenues (DEC-07), limitations constatées, preuves (code jetable) |
| ISS-007 (spike) | Canonisation JCS validée sur vecteurs officiels ; crate squelette + tests |
| ISS-008 (spike) | Rapport de capacités fapolicyd réel : scripts, memfd, namespaces — chaque NON VÉRIFIÉ devient vérifié ou déni documenté |
| ISS-009 (spike) | Rapport TUF : implémentation retenue ou ADR complémentaire justifié |
| ISS-010 | JSON Schema `policy/v0` publié + crate validation (rejet champs inconnus testé) |

## Critères de sortie (definition of done du sprint)

1. CI verte sur un commit vide de fonctionnalité (l'ossature compte).
2. Les trois rapports de spike écrits, relus, avec conclusions « GO / NO-GO /
   conditionnel » et décisions mises à jour (DEC-07 au minimum).
3. Tous les « NON VÉRIFIÉ » des documents Phase 0 qui dépendaient des spikes
   sont mis à jour (vérifiés ou explicitement maintenus avec plan).
4. Harnais VM démontre l'exécution d'un scénario de bout en bout (provision →
   commande → collecte de logs).

## Hors périmètre

Enrôlement, inventaire, serveur, portail, toute distribution de politique,
tout code privilégié (l'IPC vient au sprint 2-3 après validation des spikes).

## Risques du sprint

- DEC-03 (forge) non tranchée à J0 → décalage de 2-3 jours : prévoir une
  décision « forge provisoire » explicitement temporaire.
- Spike fapolicyd négatif sur un point clé (ex. memfd) → conséquence gérée
  par le registre des risques (RISK-04), pas par contournement improvisé.

## Sprint 2 (aperçu, pour situer)

M1 entamé : PKI + enrôlement + enveloppe anti-rejeu (ISS-011..015) — dès
lors que les spikes ont validé les fondations.
