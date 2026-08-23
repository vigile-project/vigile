# Vigile — Open-source Zero Trust application control for Linux

> **Nom** : « Vigile » — projet (DEC-01, 2026-08-21). Dépôt officiel :
> `github.com/vigile-project/vigile` (login « vigile » = compte personnel
> inactif ; crates `vigile*` libres sur crates.io). Reste avant
> médiatisation : recherche de marques (INPI/EUIPO).

## What is this?

Vigile is a **free, open-source** application control platform for
Linux, functionally inspired by the "application allowlisting /
control" product category — **without copying any code, interface,
trademark, proprietary protocol or patented feature** from any
existing product.

The platform progressively provides:
1. Application and executable inventory
2. Application allowlisting
3. Default-deny for unapproved applications
4. Script, interpreter, library and binary control
5. Legitimate behavior learning
6. Application confinement
7. Per-application network control
8. USB device control
9. Controlled and time-limited privilege elevation
10. Temporary or permanent approvals
11. Centralized multi-site administration
12. Progressive deployment with automatic rollback
13. Telemetry, audit and SIEM integration
14. Offline or heavily segmented operation
15. Cryptographic verification of policies and updates

**No claim of being "secure", "Zero Trust achieved", "production-ready"
or "compliant" may be made without proof, testing, independent review
and a precise scope definition.**

## Status

| Milestone | Description | Tests | Status |
|---|---|---|---|
| Phase 0 | Framing (20 docs, 10 ADRs, backlog) | — | ✅ Validated |
| M1 | Identity: PKI, enrollment, mTLS, clone detection | 67 | ✅ Validated |
| M2 | Inventory: packages, executables, scripts, journal | 101 | ✅ Validated |
| M3 | Policy compiler: fapolicyd rules, contradictions, simulation | 122 | ✅ Validated |
| M4 | Server: HTTP/mTLS, admin API, RBAC, audit journal | 157 | ✅ Validated |
| M5 | fapolicyd audit mode (Phase 2) | 187 | ✅ Validated |
| M6 | Executor: IPC, transactions, systemd hardening | 182 | ✅ Validated |
| M7 | Enforcement, approvals, thresholds, portal (Phase 3) | 205 | ✅ Validated |
| M8 | Packaging: RPM spec, break-glass recovery | 205 | ✅ Validated |
| Phase 4 | USBGuard backend (types, rules, approvals) | +4 | ✅ |
| Phase 5 | AppArmor backend (profiles, aa-status) | +5 | ✅ |
| Phase 6 | SELinux backend (AVC parsing, aggregation) | +7 | ✅ |
| Phase 7 | nftables backend (workload identity, rules) | +6 | ✅ |
| Phase 8 | Controlled elevation (typed actions, time-limited) | +10 | ✅ |
| Phase 9 | NixOS module + flake | — | ✅ |
| **Total** | | **237** | |

## Quick start (developer)

```bash
# Clone and build
git clone https://github.com/vigile-project/vigile.git
cd vigile/rust
cargo build --workspace
cargo test --workspace

# Compile a policy and validate with fapolicyd
cargo run --example compile-policy -- ../examples/policy-workstation-firefox.v0.json /tmp/out
cat /tmp/out/*.rules          # generated fapolicyd rules
fapolicyd-cli --check-rules /tmp/out/*.rules  # native validation

# Run the agent inventory
cargo run --release -p vigile-agent -- inventory
```

## Architecture

```text
┌─────────────────────────────────────────────────────┐
│                  Control Plane                       │
│  ┌─────────────┐  ┌──────────┐  ┌───────────────┐  │
│  │ API admin   │  │ Policy   │  │ Audit journal │  │
│  │ (RBAC, MFA) │  │ compiler │  │ (SHA-256)     │  │
│  └──────┬──────┘  └────┬─────┘  └───────────────┘  │
│         │               │                            │
│  ┌──────┴───────────────┴──────┐  ┌──────────────┐  │
│  │    Agent API (HTTPS/mTLS)  │  │  Approvals   │  │
│  └─────────────┬──────────────┘  │  Thresholds  │  │
│                │                  └──────────────┘  │
└────────────────┼────────────────────────────────────┘
                 │
┌────────────────┼────────────────────────────────────┐
│  Managed machine│                                   │
│  ┌──────────────┴──────────┐                        │
│  │ vigile-agent (no priv) │                        │
│  │  - inventory            │                        │
│  │  - sync (pull)          │                        │
│  │  - event collection     │                        │
│  └──────────┬──────────────┘                        │
│             │ IPC (SO_PEERCRED)                     │
│  ┌──────────┴──────────────┐                        │
│  │ vigile-executor (root)  │                        │
│  │  - closed catalog       │                        │
│  │  - transactions (LKG)   │                        │
│  │  - O_NOFOLLOW, fsync    │                        │
│  └──────────┬──────────────┘                        │
│             │                                       │
│  ┌──────────┴──────────────┐                        │
│  │ Security backends       │                        │
│  │  fapolicyd  SELinux     │                        │
│  │  AppArmor   nftables    │                        │
│  │  USBGuard               │                        │
│  └─────────────────────────┘                        │
└─────────────────────────────────────────────────────┘
```

## Security properties

| Property | Mechanism | Reference |
|---|---|---|
| Deny by default | Terminal `deny perm=execute all : all` | ADR-0010 |
| Signed policies | Ed25519, canonical JSON (RFC 8785) | ADR-0004 |
| mTLS agent-server | rustls, ring backend | ADR-0003 |
| Anti-replay | Server nonce + monotonic sequence | SEC-106 |
| Clone detection | Machine fingerprint + sticky quarantine | SEC-107 |
| Append-only audit | SHA-256 hash chain + DB trigger | SEC-305 |
| Self-lockout prevention | C8: protected_services required | SEC-801 |
| Auto-stop thresholds | Denials, health, rollbacks | SEC-803 |
| Local expiration | SEC-303: works without server | SEC-303 |
| No shell in executor | Closed action catalog (8 actions) | ADR-0002 |
| O_NOFOLLOW | Symlinks never followed | SEC-402 |

## Repository layout

```
vigile/
├── README.md, LICENSE (AGPL-3.0-or-later)
├── flake.nix                    # Nix flake (module + package)
├── docs/                        # 20+ documents (architecture, threat model, etc.)
├── adr/                         # 10 Architecture Decision Records
├── planning/                    # Backlog, sprints, risks, decisions
├── web/                         # Admin portal (single-file HTML)
├── examples/                    # Example policies
├── tests/
│   ├── vectors/                 # Policy test vectors
│   └── vm/                      # Fedora VM lab harness
├── packaging/
│   ├── rpm/vigile.spec          # RPM package
│   ├── systemd/                 # Hardened units + audit
│   ├── nix/vigile-module.nix    # NixOS module
│   └── recovery/                # Break-glass script
└── rust/                        # Rust workspace
    └── crates/
        ├── vigile-pki           # PKI, enrollment, rotation, anti-replay
        ├── vigile-policy        # Schema, compiler, simulation
        ├── vigile-server        # HTTP server, admin API, audit
        ├── vigile-executor      # Privileged executor (transactions)
        ├── vigile-ipc           # Local IPC protocol
        ├── vigile-agent         # Unprivileged agent binary
        ├── vigile-store         # PostgreSQL persistence
        ├── vigile-signer        # Isolated signing service
        ├── vigile-client        # Admin CLI
        └── backends/
            ├── vigile-backend-inventory   # Platform, packages, executables
            ├── vigile-backend-fapolicyd   # fapolicyd validation/deploy
            ├── vigile-backend-usbguard    # USB device control
            ├── vigile-backend-apparmor    # AppArmor profiles
            ├── vigile-backend-selinux     # SELinux AVC/module
            └── vigile-backend-nftables    # Network rules per workload
```

## License

- Code: **AGPL-3.0-or-later** (`LICENSE`)
- Documentation: **CC BY-SA 4.0** (`docs/LICENSE-docs.txt`)

## Contact

- Security: see `docs/SECURITY.md` (PGP key included)
- General: GitHub issues at `github.com/vigile-project/vigile`

---

**Warning**: This software is in alpha stage (v0.1.0). It has NOT been
independently audited, pentested, or certified for production use.
See `docs/ROADMAP.md` Phase 10 for the qualification criteria.
