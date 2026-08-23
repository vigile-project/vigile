# ARBORESCENCE INITIALE DU DÉPÔT

> **Statut** : **Validé** — Phase 0 approuvée par décision humaine le 2026-08-21
> **Version** : 0.1 — 2026-08-21
> **Décisions ouvertes** : DEC-03 (forge — adapte `.github`/`.forgejo`), DEC-06 (framework web)
> **ADR liés** : ADR-0001, ADR-0002, ADR-0007, ADR-0008
> **Hypothèses clés** : monorepo ; création effective de l'ossature à la phase 1 (aucun code auj.) ; seuls `docs/`, `adr/`, `planning/` existent aujourd'hui.

```
vigile/
├── README.md                      # index + statut + avertissement « aucune revendication »
├── LICENSE                        # à la décision DEC-02
├── CODE_OF_CONDUCT.md             # à adopter (gouvernance DEC-04)
├── SECURITY.md  (lien → docs/)    # publié à la racine à la première release
├── docs/                          # ← EXISTE (Phase 0 : 20 documents)
├── adr/                           # ← EXISTE (ADR-0001…0010)
├── planning/                      # ← EXISTE (backlog, risques, décisions, sprint, checklist)
│
│   ─────────── ci-dessous : créé en phase 1 (sprint 1 bootstrap) ───────────
│
├── rust/                          # workspace cargo unique (ADR-0001)
│   ├── Cargo.toml                 # workspace, profils durcis, [workspace.lints]
│   ├── deny.toml                  # cargo-deny (licences, sources, vulnérabilités)
│   ├── crates/
│   │   ├── vigile-agent/          # agent non privilégié (ADR-0002)
│   │   ├── vigile-executor/       # exécuteur privilégié minimal (ADR-0002)
│   │   ├── vigile-server/         # API + modules internes (ADR-0007, DEC-10)
│   │   │   └── (api/ identity/ policy/ approval/ distribution/ audit/ store/)
│   │   ├── vigile-signer/         # service de signature isolé (TB-5)
│   │   ├── vigile-policy/         # schéma policy/vN, canonisation, compilateur
│   │   ├── vigile-pki/            # PKI interne Ed25519 : hiérarchie CA, CRL (ISS-011)
│   │   ├── vigile-store/          # stockage PostgreSQL : migrations + registre (ISS-016)
│   │   ├── vigile-ipc/            # protocole ipc/v1 (catalogue d'actions)
│   │   ├── vigile-client/         # CLI d'administration
│   │   └── backends/
│   │       ├── vigile-backend-fapolicyd/
│   │       ├── vigile-backend-selinux/     # phase 6
│   │       ├── vigile-backend-apparmor/    # phase 5
│   │       ├── vigile-backend-nftables/    # phase 7
│   │       ├── vigile-backend-usbguard/    # phase 4
│   │       └── vigile-backend-inventory/   # adaptateurs dnf/apt/nix + exécutables
│   └── tests/                     # tests d'intégration Rust (hors VM)
├── web/                           # portail TypeScript strict (DEC-06)
├── packaging/
│   ├── rpm/                       # spec, unités systemd durcies, ancre de confiance
│   ├── deb/                       # phase 5
│   └── nix/                       # flake + module NixOS (phase 9, ADR-0008)
├── tests/
│   ├── vm/                        # harnais QEMU/libvirt + scénarios B/C/D (DEC-17)
│   ├── chaos/                     # scénarios E (FM-01..18)
│   ├── perf/                      # budgets F, harnais 100/1k/10k agents
│   └── vectors/                   # vecteurs JCS, politiques invalides, corpus fuzz
├── examples/                      # politiques d'exemple sûres, jamais dangereuses
└── .github/  (ou .forgejo/)       # CI : lint, tests, SBOM, reproductibilité, VM
```

## Règles d'ossature

1. **Aucun code avant validation Phase 0** (cahier des charges §31) ; le
   sprint 1 (_bootstrap_) crée l'ossature vide + CI + licences + outils.
2. Les crates `vigile-policy` et `vigile-ipc` n'ont **aucune dépendance vers
   le réseau ou le système** : testables seules, réutilisées par agent et
   serveur.
3. `packaging/` suit la matrice de compatibilité ; tout backend embarque son
   manifeste de capacités (ADR-0009).
4. `tests/vectors/` est versionné : vecteurs canonisation RFC 8785,
   politiques invalides (contradictions §3.3 de POLICY_MODEL.md), corpus
   IPC malveillants.

## Critères d'acceptation

- [ ] Arborescence validée ; création effective planifiée au sprint 1.
- [ ] Emplacements runtime (`/etc/vigile`, `/var/lib/vigile`, `/run/vigile`)
      cohérents avec ARCHITECTURE.md §3.

## Risques connus

- Monorepo Rust + web : duplication CI à maîtriser dès le départ (jobs
  séparés, artefacts signés une seule fois).
