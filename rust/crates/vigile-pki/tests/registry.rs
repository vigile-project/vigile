// SPDX-License-Identifier: AGPL-3.0-or-later
//! Clone / snapshot detection tests (ISS-014): fingerprint mismatch,
//! sequence regression (restored snapshot), exact replay, fingerprint
//! reuse at enrollment, sticky quarantine, admin actions, audit trail.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)] // tests : échec rapide acceptable

use vigile_pki::{AgentRegistry, AgentStatus, QuarantineReason, RegistryError, SecurityEventKind};

const FP: &str = "machine-id:test-lab-01";
const AGENT: &str = "agent-0123456789abcdef0123456789abcdef";

fn registry_with_agent() -> AgentRegistry {
    let mut registry = AgentRegistry::new();
    registry
        .register_enrollment(AGENT, "tenant-lab", FP, vec![1, 2, 3])
        .expect("enrollment");
    registry
}

#[test]
fn t01_normal_heartbeat_progression_accepted() {
    let mut r = registry_with_agent();
    for seq in [1, 2, 3, 100] {
        let status = r.observe(AGENT, FP, seq).expect("valid heartbeat");
        assert_eq!(status, AgentStatus::Active);
    }
    assert_eq!(r.record(AGENT).unwrap().last_sequence, 100);
}

#[test]
fn t02_clone_with_other_fingerprint_quarantined() {
    let mut r = registry_with_agent();
    r.observe(AGENT, FP, 5).expect("original heartbeat");

    // Cloned image with a regenerated machine-id presents another
    // fingerprint under the SAME agent id.
    let err = r
        .observe(AGENT, "machine-id:clone-99", 6)
        .expect_err("clone must be detected");
    match &err {
        RegistryError::CloneSuspected {
            expected,
            presented,
            ..
        } => {
            assert_eq!(expected, FP);
            assert_eq!(presented, "machine-id:clone-99");
        }
        other => panic!("unexpected error: {other:?}"),
    }
    assert_eq!(r.record(AGENT).unwrap().status, AgentStatus::Quarantined);
}

#[test]
fn t03_quarantine_is_sticky_until_admin_reinstate() {
    let mut r = registry_with_agent();
    r.observe(AGENT, FP, 5).expect("heartbeat");
    r.observe(AGENT, "machine-id:clone-99", 6)
        .expect_err("trigger quarantine");

    // Even the ORIGINAL machine (correct fingerprint, valid sequence) is
    // refused while quarantined: nobody can talk the agent out of it.
    let err = r
        .observe(AGENT, FP, 7)
        .expect_err("quarantine must be sticky");
    assert!(matches!(err, RegistryError::Quarantined { .. }), "{err}");

    // Reinstatement is an explicit admin action, audited.
    r.reinstate(AGENT).expect("reinstate");
    let status = r.observe(AGENT, FP, 8).expect("valid after reinstatement");
    assert_eq!(status, AgentStatus::Active);
}

#[test]
fn t04_snapshot_regression_detected_and_quarantined() {
    let mut r = registry_with_agent();
    for seq in [1, 2, 10] {
        r.observe(AGENT, FP, seq).expect("progress");
    }

    // Restored old snapshot replays an already-seen sequence.
    let err = r
        .observe(AGENT, FP, 4)
        .expect_err("snapshot replay must be detected");
    match &err {
        RegistryError::SequenceRegression {
            presented,
            last_seen,
            ..
        } => {
            assert_eq!(*presented, 4);
            assert_eq!(*last_seen, 10);
        }
        other => panic!("unexpected error: {other:?}"),
    }
    assert_eq!(r.record(AGENT).unwrap().status, AgentStatus::Quarantined);
    assert!(matches!(
        r.record(AGENT).unwrap().quarantine_reason,
        Some(QuarantineReason::SequenceRegression { .. })
    ));
}

#[test]
fn t05_exact_replay_rejected() {
    let mut r = registry_with_agent();
    r.observe(AGENT, FP, 7).expect("heartbeat");

    // Captured message replayed bit-for-bit (same sequence) is NOT
    // idempotent-accepted: strictly increasing sequences are required.
    let err = r
        .observe(AGENT, FP, 7)
        .expect_err("exact replay must be rejected");
    assert!(
        matches!(err, RegistryError::SequenceRegression { .. }),
        "{err}"
    );
}

#[test]
fn t06_fingerprint_reenrollment_rejected() {
    let mut r = registry_with_agent();

    // The same machine fingerprint cannot enroll a second agent id
    // (cloned image that ran enrollment again).
    let err = r
        .register_enrollment("agent-second", "tenant-lab", FP, vec![9, 9])
        .expect_err("fingerprint reuse must be rejected");
    match &err {
        RegistryError::FingerprintInUse { held_by, .. } => assert_eq!(held_by, AGENT),
        other => panic!("unexpected error: {other:?}"),
    }
    // The original agent is unaffected and still active.
    assert_eq!(r.record(AGENT).unwrap().status, AgentStatus::Active);
    assert!(r.record("agent-second").is_none());
}

#[test]
fn t07_unknown_agent_rejected() {
    let mut r = registry_with_agent();
    let err = r
        .observe("agent-nobody", FP, 1)
        .expect_err("unknown agent must be rejected");
    assert!(matches!(err, RegistryError::UnknownAgent(_)));
}

#[test]
fn t08_manual_quarantine_and_audit_trail() {
    let mut r = registry_with_agent();

    // Admin quarantine for suspected compromise.
    r.quarantine(AGENT, "incident INC-42").expect("quarantine");
    let err = r
        .observe(AGENT, FP, 1)
        .expect_err("quarantined agent refused");
    assert!(matches!(err, RegistryError::Quarantined { .. }));

    // Full audit trail, in order.
    let kinds: Vec<&SecurityEventKind> = r.events().iter().map(|e| &e.kind).collect();
    assert!(matches!(kinds[0], SecurityEventKind::Enrolled { .. }));
    assert!(matches!(
        kinds[1],
        SecurityEventKind::Quarantined {
            reason: QuarantineReason::Manual { .. },
            ..
        }
    ));
    assert!(kinds
        .iter()
        .all(|e| matches!(e, SecurityEventKind::Enrolled { .. })
            || matches!(e, SecurityEventKind::Quarantined { .. })));
    // Timestamps are monotonic (same second allowed).
    let times: Vec<i64> = r.events().iter().map(|e| e.at_unix).collect();
    assert!(times.windows(2).all(|w| w[0] <= w[1]));
}
