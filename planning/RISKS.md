# RISQUES (DONT BLOQUANTS)

> **Statut** : **Validé** — Phase 0 approuvée par décision humaine le 2026-08-21
> **Version** : 0.1 — 2026-08-21
> **Décisions ouvertes** : plus aucun risque bloquant ; RISK-01/03 levés, RISK-02 partiellement levé (2026-08-21)
> **ADR liés** : tous
> **Hypothèses clés** : probabilité/impact qualitatifs initiaux ; revue à chaque gate de phase.

| ID | Risque | Prob. | Impact | Atténuation | Statut |
|---|---|---|---|---|---|
| RISK-01 | Licence non choisie : aucune contribution externe possible, statut juridique flou | — | — | DEC-02 tranchée le 2026-08-21 (AGPL-3.0-or-later) | **Levé** |
| RISK-02 | Gouvernance non établie : décisions et clés sans responsable | Moyenne | Élevé | Défaut provisoire appliqué (fondateur = mainteneur initial, DCO) ; formalisation DEC-04 requise avant multi-contributeurs | **Partiellement levé** |
| RISK-03 | Forge/hébergement non choisi : CI et coordination impossibles | — | — | DEC-03 tranchée le 2026-08-21 (GitHub, runners éphémères) | **Levé** |
| RISK-04 | Capacités fapolicyd surestimées (memfd, namespaces, scripts) | Moyenne | Moyen (résiduel) | Spike ISS-008 terminé : scripts par hash CONFIRMÉS, rechargement transactionnel et `--check-rules --lint` confirmés ; bash interactif, NFS client, conteneurs, memfd NON couverts → déclarés « non applicables » dans le manifeste d'artefacts ; memfd à trancher par test empirique en VM | Partiellement levé (2026-08-21) |
| RISK-05 | Aucune implémentation TUF Rust satisfaisante | Faible | Élevé | Spike ISS-009 terminé : `tough` 0.24.0 retenue (active, MIT/Apache, aucun avis ouvert) + `tuftool`/RSTUF ; implémentation interne rejetée ; prototype de validation en 10 points défini | Levé sous condition du prototype |
| RISK-06 | Complexité du compilateur multi-backends dérivant vers l'abstraction fragile | Moyenne | Élevé | MVP = fapolicyd seul ; manifeste des non-applicables ; revue ADR-0006 | Ouvert |
| RISK-07 | Auto-blocage d'un anneau malgré les défenses | Faible | Critique | Simulation + catégorie D + seuils + break-glass testé | Ouvert — permanent |
| RISK-08 | Dérive « fail-open implicite » dans des coins de code | Moyenne | Critique | Matrice FAILURE_MODES §4 + tests chaos systématiques + checklist revue | Ouvert — permanent |
| RISK-09 | Charge de tests multi-VM insoutenable (temps/argent) | Moyenne | Moyen | Priorisation Fedora ; nightly autres ; DEC-17 | Ouvert |
| RISK-10 | Clés racines perdues (dépositaires indisponibles) | Faible | Élevé | n≥3 supports géographiques + exercices de restauration | Ouvert — procédure |
| RISK-11 | Notification GNOME fragile (Wayland/portails) | Moyenne | Faible (fonctionnel) | Prototype ISS-045 tôt ; repli : notification texte simple | Ouvert — prototype |
| RISK-12 | Pression pour élargir le périmètre (EDR, AV, multi-tenant précoce) | Élevée | Moyen | NON_GOALS + gates de phase + validation humaine | Ouvert — permanent |
| RISK-13 | Dérive d'horloge en environnement virtuel faussant validité/fraîcheur | Moyenne | Moyen | Bornes DEC-09 + tests chaos horloge + chevauchements de validité | Ouvert |
| RISK-14 | Petit nombre de contributeurs initial → goulot de revue | Élevée | Moyen | Priorisation des revues sécurité ; recrutement ciblé ; documentation | Ouvert |

## Critères d'acceptation

- [ ] Les risques ⛔ convertis en décisions tranchées avant la fin Phase 0.
- [ ] Chaque risque ouvert a un owner désigné à l'entrée en phase 1.

## Risques connus de ce document lui-même

- Registre initial forcément incomplet : revue obligatoire à chaque gate.
