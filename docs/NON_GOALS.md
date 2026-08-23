# NON-OBJECTIFS

> **Statut** : **Validé** — Phase 0 approuvée par décision humaine le 2026-08-21
> **Version** : 0.1 — 2026-08-21
> **Décisions ouvertes** : aucune directement ; ce document contraint DEC-05 (versions cibles) et le périmètre MVP
> **ADR liés** : ADR-0009, ADR-0010
> **Hypothèses clés** : les non-objectifs ci-dessous sont des exclusions durables ou des reports explicites, pas des oublis.

Principe : un non-objectif est une décision assumée, documentée et motivée.
Sortir un élément de cette liste exige un ADR et une validation humaine.

## Exclusions durables

| # | Non-objectif | Motivation |
|---|---|---|
| NG-01 | Remplacer le LSM ni écrire un module noyau ou un LSM maison | Surface d'attaque, maintenance noyau, relecture impossible à petite échelle ; on orchestre des mécanismes existants (fapolicyd, SELinux, AppArmor…) |
| NG-02 | Garantir la survie de l'agent face à un root ou un noyau pleinement compromis | Impossible depuis l'espace utilisateur ; cette limite est affichée publiquement, jamais masquée |
| NG-03 | Antivirus / moteur de détection de signatures de malwares | Autre domaine ; l'allowlisting repose sur l'identité et la provenance, pas sur des signatures de menaces |
| NG-03b | EDR comportemental complet (suivi d'arborescence de processus, détection d'anomalies en temps réel) | Hors du modèle de contrôle par politiques ; pourrait venir bien plus tard, sans priorité |
| NG-04 | Support de Windows, macOS, BSD | Le projet est Linux natif ; un portage diluerait les moyens |
| NG-05 | Machine learning décisionnel (auto-approbation par modèle) | Décisions de sécurité explicites, auditables et humaines ; un modèle ne peut pas être tenu responsable |
| NG-06 | Gestion des correctifs / patch management des distributions | Le gestionnaire de paquets de la distribution reste responsable ; Vigile ne le remplace pas |
| NG-07 | Chiffrement de disque, MDM, NAC, gestion de configuration générale | Autres outils, autres périmètres ; intégrations possibles, pas de réimplémentation |
| NG-08 | Porte dérobée universelle / clé maîtresse de contournement | Incompatible avec les exigences break-glass (local, contraint, audité, révocable) |
| NG-09 | Copie d'interface, de marque, de protocole ou de fonctionnalité brevetée d'un produit commercial | Exigence du cahier des charges ; conception indépendante documentée |
| NG-10 | « Support universel » de toute distribution Linux | Matrice de capacités explicite ; une fonction indisponible est refusée proprement, jamais simulée |

## Reports explicites (hors MVP, §26 du cahier des charges)

| # | Élément reporté | Reprise prévue |
|---|---|---|
| NG-11 | Multi-tenant complet | Phase 11 (architecture néanmoins conçue pour ne pas l'empêcher : `tenant_id` obligatoire dès le départ) |
| NG-12 | Kubernetes obligatoire | Jamais obligatoire ; optionnel seulement |
| NG-13 | Contrôle réseau complet par application | Phase 7, après prototype d'identité de charge stable |
| NG-14 | Génération automatique complète de politiques SELinux | Phase 6, encadrée (jamais de politique excessivement permissive générée des événements observés) |
| NG-15 | eBPF complexe | Seulement si utilité, portabilité et surface d'attaque justifiées (ADR dédié à venir) |
| NG-16 | Contrôle USB (USBGuard) | Phase 4 |
| NG-17 | Debian/Ubuntu + AppArmor | Phase 5 |
| NG-18 | NixOS | Phase 9 |
| NG-19 | Élévation contrôlée des privilèges | Phase 8 |
| NG-20 | Haute disponibilité / grande échelle (>10 000 agents) | Phase 11 |
| NG-21 | TPM 2.0 obligatoire | Optionnel à toutes les phases (jamais dépendance du MVP) |

## Critères d'acceptation du document

- [ ] Chaque non-objectif est compris comme engagement public par le valideur.
- [ ] Le MVP (§26) est confirmé comme strictement borné par cette liste.
- [ ] Toute demande future hors périmètre sera traitée par ADR, pas par
      extension silencieuse.

## Risques connus

- Pression « fonctionnalitaire » (EDR, AV…) diluant le cœur : mitigation par
  cette liste et par les gates de phase.
- Confusion « Zero Trust » compris comme garantie de sécurité absolue :
  mitigation par glossaire et communications précises.
