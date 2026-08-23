// SPDX-License-Identifier: AGPL-3.0-or-later
//! Simulation and diff tests (ISS-026).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use serde_json::json;
use vigile_policy::{
    compile, model::PolicyDocument, parse_and_validate, policy_diff, simulate, SimDecision,
    SimEvent,
};

const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn policy(extra: serde_json::Value) -> vigile_policy::model::Policy {
    let mut base = json!({
        "policy": {
            "id": "11111111-2222-3333-4444-555555555555",
            "version": 1,
            "schema_version": "policy/v0",
            "tenant": "00000000-0000-0000-0000-000000000001",
            "target": { "groups": ["lab"] },
            "execution": { "decision": "allow",
                "interpreters": { "allow": [], "deny": ["/usr/bin/bash"] } },
            "application": { "identity": { "hashes": [HASH_A],
                "package": { "name": "tool", "vendor": "custom" } } },
            "usb": { "decision": "not-applicable" },
            "validity": { "not_before": "2026-09-01T00:00:00Z", "not_after": "2026-12-01T00:00:00Z" }
        }
    });
    let extra = json!({ "policy": extra });
    let mut extra = extra;
    if let (Some(base_p), Some(extra_p)) = (base.get_mut("policy"), extra.get_mut("policy")) {
        if let (Some(b), Some(e)) = (base_p.as_object_mut(), extra_p.as_object_mut()) {
            for (k, v) in e.iter_mut() {
                b.insert(k.clone(), v.take());
            }
        }
    }
    let value = parse_and_validate(&serde_json::to_string(&base).unwrap()).expect("valid");
    let doc: PolicyDocument = serde_json::from_value(value).expect("model");
    doc.policy
}

#[test]
fn t26_01_pinned_hash_passes_through_denied_interpreter() {
    let compiled = compile(&policy(json!({}))).expect("compile");
    // A script with the pinned hash, executed by the DENIED interpreter:
    // the pinned allow rule matches BEFORE the interpreter deny.
    let result = simulate(
        &compiled,
        &SimEvent {
            exe: Some("/usr/bin/bash".into()),
            hash: Some(HASH_A.into()),
            trusted: Some(false),
        },
    )
    .expect("simulation");
    assert_eq!(result.decision, SimDecision::AllowAudit); // audit mode default

    // Same interpreter, UNKNOWN script: denied by the interpreter rule.
    let result = simulate(
        &compiled,
        &SimEvent {
            exe: Some("/usr/bin/bash".into()),
            hash: Some(HASH_B.into()),
            trusted: Some(false),
        },
    )
    .expect("simulation");
    assert_eq!(result.decision, SimDecision::DenyAudit);
}

#[test]
fn t26_02_unknown_binary_hits_terminal_deny() {
    let compiled = compile(&policy(json!({}))).expect("compile");
    let result = simulate(
        &compiled,
        &SimEvent {
            exe: Some("/opt/mystery".into()),
            hash: Some(HASH_B.into()),
            trusted: Some(false),
        },
    )
    .expect("simulation");
    assert_eq!(result.decision, SimDecision::DenyAudit);
    // Points at the terminal rule line.
    let lines: Vec<&str> = compiled.artifacts[0].content.lines().collect();
    let terminal = lines[result.matched_line - 1];
    assert!(terminal.ends_with("deny_audit perm=execute all : all"));
}

#[test]
fn t26_03_enforce_strategy_produces_blocking_decisions() {
    let mut p = policy(json!({}));
    p.rollout = Some(vigile_policy::model::Rollout {
        strategy: vigile_policy::model::RolloutStrategy::Canary,
        rings: vec![],
    });
    // C8 requires protected services for enforcement strategies.
    p.safety = Some(vigile_policy::model::Safety {
        protected_services: vec!["vigile-agent.service".into()],
    });
    let compiled = compile(&p).expect("compile");
    let result = simulate(
        &compiled,
        &SimEvent {
            exe: Some("/usr/bin/bash".into()),
            hash: Some(HASH_B.into()),
            trusted: Some(false),
        },
    )
    .expect("simulation");
    assert_eq!(result.decision, SimDecision::Deny);
}

#[test]
fn t26_04_policy_diff_is_readable_and_exact() {
    let previous = policy(json!({}));
    let mut current = policy(json!({}));
    current.version = 2;
    current
        .execution
        .interpreters
        .as_mut()
        .unwrap()
        .deny
        .push("/usr/bin/python3".into());
    current
        .application
        .as_mut()
        .unwrap()
        .identity
        .as_mut()
        .unwrap()
        .hashes
        .push(HASH_B.into());

    let diff = policy_diff(&previous, &current);
    let text = diff.join("\n");
    assert!(text.contains("version: 1 → 2"), "{text}");
    assert!(
        text.contains("execution.interpreters.deny[1]: (absent) → \"/usr/bin/python3\""),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "application.identity.hashes[1]: (absent) → \"{HASH_B}\""
        )),
        "{text}"
    );
    // Identical policies produce no diff.
    assert!(policy_diff(&previous, &previous).is_empty());
}

#[test]
fn t26_05_simulation_of_fuzzed_event_never_panics() {
    let compiled = compile(&policy(json!({}))).expect("compile");
    for exe in [
        None,
        Some(String::new()),
        Some("/".into()),
        Some("relative".into()),
        Some("a b c".into()),
    ] {
        for hash in [
            None,
            Some(String::new()),
            Some(HASH_A.into()),
            Some("zz".into()),
        ] {
            for trusted in [None, Some(true), Some(false)] {
                let event = SimEvent {
                    exe: exe.clone(),
                    hash: hash.clone(),
                    trusted,
                };
                // Every well-formed ruleset has a terminal rule: this
                // must ALWAYS resolve, never panic.
                assert!(simulate(&compiled, &event).is_ok());
            }
        }
    }
}
