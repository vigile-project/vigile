// SPDX-License-Identifier: AGPL-3.0-or-later
//! Compiler tests (ISS-023/024/025): determinism, contradiction table,
//! non-applicable declarations, audit-mode doctrine.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use serde_json::json;
use vigile_policy::{check_contradictions, compile, model::PolicyDocument, parse_and_validate};

fn policy_doc(extra: serde_json::Value) -> PolicyDocument {
    let mut base = json!({
        "policy": {
            "id": "11111111-2222-3333-4444-555555555555",
            "version": 1,
            "schema_version": "policy/v0",
            "tenant": "00000000-0000-0000-0000-000000000001",
            "target": { "groups": ["lab"] },
            "execution": { "decision": "audit-only" },
            "usb": { "decision": "not-applicable" },
            "validity": { "not_before": "2026-09-01T00:00:00Z", "not_after": "2026-12-01T00:00:00Z" }
        }
    });
    // Fusion superficielle : les clés de extra écrasent la base.
    let extra = json!({ "policy": extra });
    let mut extra = extra;
    if let (Some(base_p), Some(extra_p)) = (base.get_mut("policy"), extra.get_mut("policy")) {
        if let (Some(b), Some(e)) = (base_p.as_object_mut(), extra_p.as_object_mut()) {
            for (k, v) in e.iter_mut() {
                b.insert(k.clone(), v.take());
            }
        }
    }
    let source = serde_json::to_string(&base).unwrap();
    let value = parse_and_validate(&source).expect("policy valid");
    serde_json::from_value(value).expect("model ok")
}

fn policy(extra: serde_json::Value) -> vigile_policy::model::Policy {
    policy_doc(extra).policy
}

const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

// ---------------------------------------------------------------- ISS-023

#[test]
fn t23_01_compilation_is_deterministic() {
    let p = policy(json!({
        "application": { "identity": { "hashes": [HASH_A, HASH_B],
            "package": { "name": "tool", "vendor": "custom" } } },
        "execution": { "decision": "allow",
            "interpreters": { "allow": [], "deny": ["/usr/bin/bash"] } }
    }));
    let c1 = compile(&p).expect("compile 1");
    let c2 = compile(&p).expect("compile 2");
    assert_eq!(c1, c2, "identical input must produce identical bytes");

    // The manifest hash actually matches the artifact content.
    let artifact = &c1.artifacts[0];
    let recorded = &c1.manifest.artifacts[0];
    assert_eq!(recorded.name, artifact.name);
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest as _;
    hasher.update(artifact.content.as_bytes());
    let hex: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(recorded.sha256, hex);
}

#[test]
fn t23_02_audit_mode_by_default_and_enforce_by_strategy() {
    let mut p = policy(json!({}));
    let c = compile(&p).expect("compile");
    assert!(c.manifest.audit_mode);
    assert!(c.artifacts[0]
        .content
        .contains("deny_audit perm=execute all : all"));

    p.rollout = Some(vigile_policy::model::Rollout {
        strategy: vigile_policy::model::RolloutStrategy::Canary,
        rings: vec![],
    });
    let c = compile(&p).expect("compile");
    assert!(!c.manifest.audit_mode);
    assert!(c.artifacts[0]
        .content
        .contains("deny perm=execute all : all"));
}

#[test]
fn t23_03_pinned_hashes_and_interpreter_ordering() {
    let p = policy(json!({
        "application": { "identity": { "hashes": [HASH_A],
            "package": { "name": "tool", "vendor": "custom" } } },
        "execution": { "decision": "allow",
            "interpreters": { "allow": [], "deny": ["/usr/bin/bash"] } }
    }));
    let c = compile(&p).expect("compile");
    let lines: Vec<&str> = c.artifacts[0].content.lines().collect();
    // Pinned allow THROUGH the interpreter comes BEFORE the deny.
    let allow_pos = lines
        .iter()
        .position(|l| l.contains("exe=/usr/bin/bash") && l.contains(HASH_A))
        .expect("pinned allow rule");
    let deny_pos = lines
        .iter()
        .position(|l| l.contains("deny_audit perm=execute exe=/usr/bin/bash : all"))
        .expect("interpreter deny rule");
    assert!(allow_pos < deny_pos, "first-match-wins ordering");
    // Hash allow regardless of subject.
    assert!(lines
        .iter()
        .any(|l| l.starts_with("allow_audit perm=execute all : all FILE_HASH=")));
}

// ---------------------------------------------------------------- ISS-024

fn contradiction(extra: serde_json::Value) -> vigile_policy::CompileError {
    check_contradictions(&policy(extra)).expect_err("must be a contradiction")
}

#[test]
fn t24_c1_interpreter_both_allowed_and_denied() {
    let e = contradiction(json!({
        "execution": { "decision": "audit-only",
            "interpreters": { "allow": ["/usr/bin/python3"], "deny": ["/usr/bin/python3"] } }
    }));
    assert_eq!(e.code, "C1");
}

#[test]
fn t24_c1_relative_interpreter_path() {
    let e = contradiction(json!({
        "execution": { "decision": "audit-only",
            "interpreters": { "allow": ["usr/bin/python3"], "deny": [] } }
    }));
    assert_eq!(e.code, "C1");
}

#[test]
fn t24_c2_inverted_validity() {
    let e = contradiction(json!({
        "validity": { "not_before": "2026-12-01T00:00:00Z", "not_after": "2026-09-01T00:00:00Z" }
    }));
    assert_eq!(e.code, "C2");
}

#[test]
fn t24_c2_malformed_timestamp() {
    let e = contradiction(json!({
        "validity": { "not_before": "tomorrow", "not_after": "2026-12-01T00:00:00Z" }
    }));
    assert!(e.code == "E", "structural error: {}", e.code);
}

#[test]
fn t24_c3_duplicate_hash() {
    let e = contradiction(json!({
        "application": { "identity": { "hashes": [HASH_A, HASH_A],
            "package": { "name": "t", "vendor": "custom" } } }
    }));
    assert_eq!(e.code, "C3");
}

#[test]
fn t24_c4_approval_on_denial() {
    let e = contradiction(json!({
        "execution": { "decision": "deny" },
        "approval": { "required_roles": ["security-approver"] }
    }));
    assert_eq!(e.code, "C4");
}

#[test]
fn t24_c5_reserved_group() {
    for group in ["all", "*"] {
        let e = contradiction(json!({ "target": { "groups": [group] } }));
        assert_eq!(e.code, "C5");
    }
}

#[test]
fn t24_c6_malformed_hash() {
    // The SCHEMA already rejects short hashes (SEC-208); the compiler
    // re-checks as defense-in-depth for direct API callers. Build the
    // typed policy by hand, bypassing the schema.
    let mut p = policy(json!({
        "application": { "identity": { "hashes": [HASH_A],
            "package": { "name": "t", "vendor": "custom" } } }
    }));
    p.application
        .as_mut()
        .unwrap()
        .identity
        .as_mut()
        .unwrap()
        .hashes = vec!["deadbeef".into()];
    let e = check_contradictions(&p).expect_err("defense-in-depth");
    assert_eq!(e.code, "C6");
}

#[test]
fn t24_c7_custom_identity_without_hash() {
    let e = contradiction(json!({
        "application": { "identity": { "hashes": [],
            "package": { "name": "t", "vendor": "custom" } } },
        "execution": { "decision": "allow" }
    }));
    assert_eq!(e.code, "C7");
    // Distribution vendor without hashes is accepted (coarse trust=1).
    let ok = policy(json!({
        "application": { "identity": { "hashes": [],
            "package": { "name": "firefox", "vendor": "distribution" } } },
        "execution": { "decision": "allow" }
    }));
    assert!(check_contradictions(&ok).is_ok());
}

// ---------------------------------------------------------------- ISS-025

#[test]
fn t25_01_non_applicable_fields_are_declared_never_silent() {
    let p = policy(json!({
        "filesystem": { "read": { "allow": ["$HOME/Downloads/**"], "deny": ["$HOME/.ssh/**"] },
                         "write": { "allow": ["$HOME/Downloads/**"], "deny": [] } },
        "network": { "default": "deny",
            "allow": [ { "protocol": "tcp", "destination": "update.example", "ports": [443] } ] },
        "usb": { "decision": "allow" }
    }));
    let c = compile(&p).expect("compile");
    let fields: Vec<&str> = c
        .manifest
        .non_applicable
        .iter()
        .map(|n| n.field.as_str())
        .collect();
    assert!(fields.contains(&"filesystem"), "{fields:?}");
    assert!(fields.contains(&"network"), "{fields:?}");
    assert!(fields.contains(&"usb"), "{fields:?}");
    // Each declaration carries a reason and an arrival phase.
    for n in &c.manifest.non_applicable {
        assert!(!n.reason.is_empty());
        assert!(n.arrives_with.contains("phase"));
    }
}

#[test]
fn t25_02_not_applicable_usb_is_not_declared() {
    // usb.decision=not-applicable in the source → nothing to declare.
    let c = compile(&policy(json!({}))).expect("compile");
    assert!(!c.manifest.non_applicable.iter().any(|n| n.field == "usb"));
}

#[test]
fn t25_03_package_allow_warns_about_coarseness() {
    let p = policy(json!({
        "application": { "identity": { "hashes": [],
            "package": { "name": "firefox", "vendor": "distribution" } } },
        "execution": { "decision": "allow" }
    }));
    let c = compile(&p).expect("compile");
    assert!(c.manifest.warnings.iter().any(|w| w.contains("coarse")));
    assert!(c.artifacts[0].content.contains("trust=1"));
}

#[test]
fn t23_04_not_applicable_decision_emits_no_rule() {
    let p = policy(json!({ "execution": { "decision": "not-applicable" } }));
    let c = compile(&p).expect("compile");
    let rules: Vec<&str> = c.artifacts[0]
        .content
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .collect();
    // Only the terminal rule remains — no application-specific rule.
    assert_eq!(rules.len(), 1);
    assert!(rules[0].contains("deny_audit perm=execute all : all"));
}
