# ADR-0001 — Langage de l'agent et des composants natifs

**Statut** : Accepté — validé avec la Phase 0 le 2026-08-21
**Date** : 2026-08-21
**Décideurs** : validateur humain de la Phase 0 (2026-08-21)

## Contexte

L'agent et surtout l'exécuteur privilégié tournent sur des machines critiques,
traitent des données distantes non fiables (politiques, métadonnées,
événements), et doivent résister aux entrées malveillantes sans panic ni
corruption mémoire. Le serveur partage une base de code et des contrats
(schémas, signatures). Cahier des charges §20 : Rust privilégié pour
agent/exécuteur ; Go ou Rust pour le back-end ; TypeScript strict pour le web.

## Options étudiées

| Option | Avantages | Risques/inconvénients |
|---|---|---|
| **Rust partout (natif)** | Sé mémoire par construction ; écosystème crypto/TLS mature (rustls, ed25519) ; erreurs typées ; pas d'interprète embarqué ; un seul outilchain natif | Courbe d'apprentissage ; compilation plus lente ; some crates moins matures (à évaluer au cas par cas) |
| Go (agent) + Rust (exécuteur) | Développement rapide côté agent ; déploiement simple | Deux toolchains ; GC moins prévisible pour le composant temps réel local ; divergence de culture sécurité |
| C/C++ | Contrôle total | Coût de sécurité inacceptable (mémoire) pour du code privilégié |
| Autres (Python, etc.) | — | Interprété : inacceptable pour l'exécuteur privilégié et les chemins chauds |

## Décision (recommandée)

1. **Rust** pour : `vigile-agent`, `vigile-executor`, `vigile-server`,
   `vigile-signer`, CLI. Règles : `unsafe` interdit par défaut ; tout `unsafe`
   isolé/documenté/audité ; `clippy -D warnings` ; `rustfmt` ; gestion typée
   des erreurs ; aucun panic sur entrée distante ; fuzzing des parseurs.
2. **TypeScript strict** pour le portail web.
3. Dépendances minimales, évaluées selon la check-list (SUPPLY_CHAIN_SECURITY).

## Conséquences

- Un seul langage natif : mutualisation des schémas/signatures entre agent et
  serveur ; revue de sécurité plus homogène.
- Le choix des crates précises (TLS, crypto, CBOR/JSON canonique, TPM)
  fait l'objet de spikes phase 1 (DEC-07) — aucune API supposée exister
  sans vérification (règle §28).

## Alternatives rejetées

Go pour l'agent : acceptable techniquement mais double toolchain et GC ;
rejeté pour homogénéité sécurité. C/C++ rejeté d'emblée.

## Risques et critères de révision

- Pénurie de contributeurs Rust : à surveiller ; atténué par TypeScript
  (portail) et documentation.
- Réviser cet ADR si une brique essentielle (ex. TPM, mTLS sur contrainte
  matérielle) s'avère impraticable en Rust — avec preuve, pas par préférence.
