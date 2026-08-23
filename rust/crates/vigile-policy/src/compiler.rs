// SPDX-License-Identifier: AGPL-3.0-or-later
//! Policy compiler (ISS-023/024/025): `policy/v0` IR → deterministic
//! fapolicyd 2.0 artifacts + manifest.
//!
//! Doctrine:
//! - PURE: no I/O, no wall-clock, no randomness in outputs — identical
//!   input + compiler version ⇒ identical bytes (SEC-209, tested).
//! - AUDIT FIRST: unless the rollout strategy is an explicit enforcement
//!   strategy (canary/rings/percentage), every generated decision carries
//!   the `_audit` suffix — compilation never emits a blocking rule
//!   directly (§26: phase 2 is observation).
//! - NO SILENT IGNORE: fields the fapolicyd backend cannot honor
//!   (filesystem/network/usb) are DECLARED in the manifest as
//!   non-applicable (ISS-025), with the phase that will bring them.
//!
//! Rule shapes emitted (fapolicyd 2.0 semantics, first match wins —
//! capabilities verified by spike ISS-008):
//!   <dec> perm=execute exe=<interp> : all FILE_HASH=<sha>   (pinned scripts
//!                                                         through a denied
//!                                                         interpreter)
//!   <dec> perm=execute all : all FILE_HASH=<sha>            (pinned binaries)
//!   <dec> perm=execute all : all trust=1                    (package-level,
//!                                                         coarse — warned)
//!   <dec> perm=execute exe=<interp> : all                   (denied interpreter)
//!   <dec> perm=execute all : all                            (terminal rule)

use crate::model::{Decision, Policy, RolloutStrategy, Vendor};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Compiler version — bump on ANY output-shape change; part of the
/// manifest so artifacts are traceable to the exact generator.
pub const COMPILER_VERSION: &str = "policy-compiler/0.1.0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileError {
    /// Stable contradiction code (ISS-024): C1..C7, or E for structural.
    pub code: &'static str,
    pub detail: String,
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.detail)
    }
}

impl std::error::Error for CompileError {}

/// One generated file (relative name + content).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Artifact {
    pub name: String,
    pub content: String,
}

/// A declared non-applicable field (ISS-025) — what the backend cannot
/// honor and why, never silently ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NonApplicable {
    pub field: String,
    pub backend: &'static str,
    pub arrives_with: &'static str,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArtifactHash {
    pub name: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Manifest {
    pub compiler_version: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub schema_version: String,
    pub audit_mode: bool,
    pub artifacts: Vec<ArtifactHash>,
    pub non_applicable: Vec<NonApplicable>,
    pub warnings: Vec<String>,
}

/// Full compilation output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compiled {
    pub artifacts: Vec<Artifact>,
    pub manifest: Manifest,
}

const RESERVED_GROUPS: [&str; 2] = ["all", "*"];

/// Runs all contradiction checks (ISS-024). Public so the API layer can
/// reject before signing.
pub fn check_contradictions(policy: &Policy) -> Result<(), CompileError> {
    let err = |code: &'static str, detail: String| Err(CompileError { code, detail });

    // C5 — reserved group names: never an implicit "all".
    for group in &policy.target.groups {
        if RESERVED_GROUPS.contains(&group.as_str()) {
            return err(
                "C5",
                format!("target group '{group}' is reserved (no implicit all)"),
            );
        }
    }

    // C1 — an interpreter cannot be both allowed and denied.
    if let Some(interpreters) = &policy.execution.interpreters {
        for denied in &interpreters.deny {
            if interpreters.allow.contains(denied) {
                return err(
                    "C1",
                    format!("interpreter '{denied}' is both allowed and denied"),
                );
            }
        }
        // Interpreters must be absolute, normalized paths (SEC-402).
        for interp in interpreters.allow.iter().chain(interpreters.deny.iter()) {
            if !interp.starts_with('/') || interp.contains("..") || interp.contains("//") {
                return err(
                    "C1",
                    format!("interpreter '{interp}' must be an absolute normalized path"),
                );
            }
        }
    }

    // C2 — validity window must be ordered (RFC3339).
    let nb = parse_rfc3339(&policy.validity.not_before)?;
    if let Some(na) = policy.validity.not_after.as_deref() {
        let na = parse_rfc3339(na)?;
        if nb >= na {
            return err(
                "C2",
                format!(
                    "validity.not_before ({}) is not before validity.not_after ({})",
                    policy.validity.not_before,
                    na_original(policy, na)
                ),
            );
        }
    }

    // C3/C6 — hashes: SHA-256 hex, no duplicates.
    if let Some(identity) = policy
        .application
        .as_ref()
        .and_then(|a| a.identity.as_ref())
    {
        let mut seen = std::collections::BTreeSet::new();
        for hash in &identity.hashes {
            if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                return err("C6", format!("hash '{hash}' is not a SHA-256 hex digest"));
            }
            if !seen.insert(hash.clone()) {
                return err("C3", format!("duplicate hash '{hash}'"));
            }
        }
        // C7 — a custom identity without hashes is unanchored.
        if identity.hashes.is_empty() {
            match identity.package.as_ref().map(|p| p.vendor) {
                Some(Vendor::Custom) | None => {
                    return err(
                        "C7",
                        "custom application identity requires at least one SHA-256 hash \
                         (package scoping needs per-file learning, phase 2)"
                            .into(),
                    );
                }
                _ => {}
            }
        }
    }

    // C4 — an approval on a denial is meaningless.
    if policy.execution.decision == Decision::Deny {
        if let Some(approval) = &policy.approval {
            if !approval.required_roles.is_empty() {
                return err(
                    "C4",
                    "approval required for a policy whose execution decision is 'deny'".into(),
                );
            }
        }
    }

    // C8 — enforcement mode (ISS-042): a policy with an enforcement
    // rollout strategy MUST declare protected services. The terminal
    // `deny perm=execute all : all` would block EVERYTHING not
    // explicitly allowed — without a protected list, this risks
    // self-lockout (§12 cahier des charges).
    if !policy.audit_mode() {
        let has_protected = policy
            .safety
            .as_ref()
            .map(|s| !s.protected_services.is_empty())
            .unwrap_or(false);
        if !has_protected {
            return err(
                "C8",
                "enforcement rollout strategy requires safety.protected_services \
                 to be non-empty (self-lockout prevention, SEC-801)"
                    .into(),
            );
        }
    }

    Ok(())
}

fn na_original(_policy: &Policy, _na: i64) -> String {
    // Helper kept simple: the detail uses the parsed ordering only.
    "not_after".to_string()
}

fn parse_rfc3339(s: &str) -> Result<i64, CompileError> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map(|t| t.unix_timestamp())
        .map_err(|e| CompileError {
            code: "E",
            detail: format!("invalid RFC3339 timestamp '{s}': {e}"),
        })
}

fn sha256_hex(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Compiles a validated policy. Deterministic: sort orders are fixed,
/// no timestamps, no environment, no randomness.
pub fn compile(policy: &Policy) -> Result<Compiled, CompileError> {
    check_contradictions(policy)?;

    let audit = policy.audit_mode();
    let dec = |base: &str| -> String {
        if audit {
            format!("{base}_audit")
        } else {
            base.to_string()
        }
    };

    let mut lines: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    lines.push(format!(
        "# vigile policy {} v{} (schema {}, compiler {}, mode {})",
        policy.id,
        policy.version,
        policy.schema_version,
        COMPILER_VERSION,
        if audit { "audit-only" } else { "enforce" }
    ));

    let identity = policy
        .application
        .as_ref()
        .and_then(|a| a.identity.as_ref());
    let interpreters = policy.execution.interpreters.as_ref();

    match policy.execution.decision {
        Decision::Allow | Decision::AuditOnly => {
            if let Some(identity) = identity {
                // Pinned scripts: allowed hashes THROUGH each denied
                // interpreter, before the interpreter deny rule
                // (first-match-wins — spike ISS-008 pattern).
                if let (Some(interpreters), false) = (interpreters, identity.hashes.is_empty()) {
                    for interp in &interpreters.deny {
                        for hash in &identity.hashes {
                            lines.push(format!(
                                "{} perm=execute exe={interp} : all FILE_HASH={hash}",
                                dec("allow")
                            ));
                        }
                    }
                }
                // Pinned binaries: hash allow regardless of subject.
                for hash in &identity.hashes {
                    lines.push(format!(
                        "{} perm=execute all : all FILE_HASH={hash}",
                        dec("allow")
                    ));
                }
                // Package-level allow (distribution/upstream signed).
                if identity.hashes.is_empty() {
                    if let Some(package) = &identity.package {
                        lines.push(format!("{} perm=execute all : all trust=1", dec("allow")));
                        let _ = package;
                        warnings.push(
                            "package-level allow compiles to 'trust=1' (all rpmdb-trusted \
                             files match): coarse until per-file learning (phase 2, ISS-036)"
                                .into(),
                        );
                    }
                }
            }
        }
        Decision::Deny => {
            if let Some(identity) = identity {
                for hash in &identity.hashes {
                    lines.push(format!(
                        "{} perm=execute all : all FILE_HASH={hash}",
                        dec("deny")
                    ));
                }
            }
        }
        Decision::NotApplicable => {
            lines.push("# execution.decision=not-applicable: no fapolicyd rule emitted".into());
        }
    }

    // Denied interpreters (after the pinned-hash allows above).
    if let Some(interpreters) = interpreters {
        for interp in &interpreters.deny {
            lines.push(format!("{} perm=execute exe={interp} : all", dec("deny")));
        }
        // Explicitly allowed interpreters (when not in audit mode this
        // allows the interpreter itself to run before the terminal rule).
        for interp in &interpreters.allow {
            lines.push(format!("{} perm=execute exe={interp} : all", dec("allow")));
        }
    }

    // Terminal rule: default-deny execution (audit-suffixed in audit mode).
    lines.push(format!("{} perm=execute all : all", dec("deny")));

    // Non-applicable declarations (ISS-025) — what we REFUSE to fake.
    let mut non_applicable = Vec::new();
    if let Some(fs) = &policy.filesystem {
        let _ = fs;
        non_applicable.push(NonApplicable {
            field: "filesystem".into(),
            backend: "fapolicyd",
            arrives_with: "AppArmor (phase 5) / SELinux (phase 6) backends",
            reason: "fapolicyd has no filesystem read/write rule semantics".into(),
        });
    }
    if let Some(network) = &policy.network {
        let _ = network;
        non_applicable.push(NonApplicable {
            field: "network".into(),
            backend: "fapolicyd",
            arrives_with: "nftables backend (phase 7, after workload-identity prototype)",
            reason: "fapolicyd does not filter network flows".into(),
        });
    }
    if policy.usb.decision != crate::model::UsbDecision::NotApplicable {
        non_applicable.push(NonApplicable {
            field: "usb".into(),
            backend: "fapolicyd",
            arrives_with: "USBGuard backend (phase 4)",
            reason: "fapolicyd does not control USB devices".into(),
        });
    }

    let rule_name = format!("90-vigile-{}.rules", &policy.id[..8.min(policy.id.len())]);
    let content = lines.join("\n") + "\n";

    let artifacts = vec![Artifact {
        name: rule_name,
        content,
    }];

    let artifact_hashes: Vec<ArtifactHash> = artifacts
        .iter()
        .map(|a| ArtifactHash {
            name: a.name.clone(),
            sha256: sha256_hex(&a.content),
        })
        .collect();

    // Determinism guard: trust.d entries are NOT generated in v0 (the
    // schema has no per-file paths) — learning (phase 2) will supply
    // path+size+hash triples. Declared as a warning, never silent.
    if let Some(identity) = identity {
        if !identity.hashes.is_empty() {
            warnings.push(
                "trust.d entries deferred: schema v0 hashes carry no file paths; \
                 per-file trust generation arrives with learning (ISS-036)"
                    .into(),
            );
        }
    }
    if matches!(
        policy.rollout.as_ref().map(|r| r.strategy),
        Some(RolloutStrategy::Simulation)
    ) {
        warnings.push(
            "rollout.strategy=simulation: artifacts are for the simulator only, \
             never deploy"
                .into(),
        );
    }

    let manifest = Manifest {
        compiler_version: COMPILER_VERSION.to_string(),
        policy_id: policy.id.clone(),
        policy_version: policy.version,
        schema_version: policy.schema_version.clone(),
        audit_mode: audit,
        artifacts: artifact_hashes,
        non_applicable,
        warnings,
    };

    Ok(Compiled {
        artifacts,
        manifest,
    })
}
