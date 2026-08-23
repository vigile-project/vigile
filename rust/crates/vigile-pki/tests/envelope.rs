// SPDX-License-Identifier: AGPL-3.0-or-later
//! Anti-replay envelope tests (ISS-015, SEC-106): nonce rotation and
//! replay, bounded clock drift (± 10 min proposal), sequence regression
//! (quarantine via registry), strict schema, protocol pinning.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::{Duration, SystemTime};
use vigile_pki::{
    AgentRegistry, EnvelopeError, EnvelopeVerifier, MessageEnvelope, MessageKind, PROTOCOL,
};

const AGENT: &str = "agent-0123456789abcdef0123456789abcdef";
const FP: &str = "machine-id:test-lab-01";

struct Fixture {
    verifier: EnvelopeVerifier,
    registry: AgentRegistry,
}

fn fixture() -> Fixture {
    let mut registry = AgentRegistry::new();
    registry
        .register_enrollment(AGENT, "tenant-lab", FP, vec![1])
        .expect("enrollment");
    let mut verifier = EnvelopeVerifier::default();
    verifier.issue_nonce(AGENT).expect("initial nonce");
    Fixture { verifier, registry }
}

fn rfc3339(at: SystemTime) -> String {
    let secs = at.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    time::OffsetDateTime::from_unix_timestamp(secs)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

fn envelope(sequence: u64, nonce: &str, at: SystemTime) -> MessageEnvelope {
    MessageEnvelope {
        protocol: PROTOCOL.into(),
        agent_id: AGENT.into(),
        sequence,
        server_nonce: nonce.into(),
        timestamp: rfc3339(at),
        request_id: "0123456789abcdef0123456789abcdef".into(),
        kind: MessageKind::Heartbeat,
        body: serde_json::json!({}),
    }
}

/// One successful exchange: returns the nonce for the NEXT message.
fn exchange(f: &mut Fixture, sequence: u64, at: SystemTime) -> String {
    let nonce = f.verifier.outstanding_nonce(AGENT).expect("nonce");
    let next = f
        .verifier
        .verify(
            &mut f.registry,
            &envelope(sequence, &nonce, at),
            SystemTime::now(),
        )
        .expect("valid exchange");
    next.next_nonce
}

#[test]
fn t01_nonce_rotates_each_accepted_message() {
    let mut f = fixture();
    let n1 = exchange(&mut f, 1, SystemTime::now());
    assert_ne!(n1.len(), 0);
    let n2 = exchange(&mut f, 2, SystemTime::now());
    assert_ne!(n1, n2, "nonce must rotate at every accepted message");
}

#[test]
fn t02_replayed_envelope_rejected() {
    let mut f = fixture();
    let nonce = f.verifier.outstanding_nonce(AGENT).unwrap();
    let msg = envelope(1, &nonce, SystemTime::now());

    f.verifier
        .verify(&mut f.registry, &msg, SystemTime::now())
        .expect("first use");

    // Bit-for-bit replay: the nonce was consumed.
    let err = f
        .verifier
        .verify(&mut f.registry, &msg, SystemTime::now())
        .expect_err("replay must be rejected");
    assert!(matches!(err, EnvelopeError::WrongNonce { .. }), "{err}");
}

#[test]
fn t03_wrong_nonce_rejected_without_touching_registry() {
    let mut f = fixture();
    let err = f
        .verifier
        .verify(
            &mut f.registry,
            &envelope(1, "ffffffffffffffffffffffffffffffff", SystemTime::now()),
            SystemTime::now(),
        )
        .expect_err("wrong nonce must be rejected");
    assert!(matches!(err, EnvelopeError::WrongNonce { .. }), "{err}");
    // The legitimate agent is unaffected: its sequence baseline is intact.
    exchange(&mut f, 1, SystemTime::now());
}

#[test]
fn t04_unknown_agent_nonce_rejected() {
    let mut f = fixture();
    let mut msg = envelope(1, "00", SystemTime::now());
    msg.agent_id = "agent-other".into();
    let err = f
        .verifier
        .verify(&mut f.registry, &msg, SystemTime::now())
        .expect_err("agent without outstanding nonce must be rejected");
    assert!(
        matches!(err, EnvelopeError::UnknownAgentNonce { .. }),
        "{err}"
    );
}

#[test]
fn t05_stale_timestamp_rejected() {
    let mut f = fixture();
    let nonce = f.verifier.outstanding_nonce(AGENT).unwrap();
    let err = f
        .verifier
        .verify(
            &mut f.registry,
            &envelope(1, &nonce, SystemTime::now() - Duration::from_secs(601)),
            SystemTime::now(),
        )
        .expect_err("11-minute-old message must be rejected");
    assert!(
        matches!(err, EnvelopeError::TimestampOutOfWindow { skew_secs: 600, delta_secs } if delta_secs < -600),
        "{err}"
    );
}

#[test]
fn t06_future_timestamp_rejected() {
    let mut f = fixture();
    let nonce = f.verifier.outstanding_nonce(AGENT).unwrap();
    let err = f
        .verifier
        .verify(
            &mut f.registry,
            &envelope(1, &nonce, SystemTime::now() + Duration::from_secs(601)),
            SystemTime::now(),
        )
        .expect_err("11-minutes-in-the-future message must be rejected");
    assert!(
        matches!(err, EnvelopeError::TimestampOutOfWindow { skew_secs: 600, delta_secs } if delta_secs > 600),
        "{err}"
    );
}

#[test]
fn t07_drift_within_bounds_accepted() {
    let mut f = fixture();
    // ±9 minutes: inside the ±10-minute window (DEC-09 proposal).
    exchange(&mut f, 1, SystemTime::now() - Duration::from_secs(540));
    exchange(&mut f, 2, SystemTime::now() + Duration::from_secs(540));
}

#[test]
fn t08_sequence_regression_quarantines_agent() {
    let mut f = fixture();
    exchange(&mut f, 10, SystemTime::now());

    // Snapshot restore replays an old sequence with a FRESH nonce: the
    // registry must catch it and quarantine.
    let nonce = f.verifier.outstanding_nonce(AGENT).unwrap();
    let err = f
        .verifier
        .verify(
            &mut f.registry,
            &envelope(4, &nonce, SystemTime::now()),
            SystemTime::now(),
        )
        .expect_err("sequence regression must be rejected");
    assert!(
        matches!(
            err,
            EnvelopeError::SequenceRegression {
                presented: 4,
                last_seen: 10,
                ..
            }
        ),
        "{err}"
    );
    assert_eq!(
        f.registry.record(AGENT).unwrap().status,
        vigile_pki::AgentStatus::Quarantined
    );

    // Even a perfectly formed message from the quarantined agent fails.
    let nonce = f.verifier.outstanding_nonce(AGENT).unwrap();
    let err = f
        .verifier
        .verify(
            &mut f.registry,
            &envelope(11, &nonce, SystemTime::now()),
            SystemTime::now(),
        )
        .expect_err("quarantined agent must be refused");
    assert!(matches!(err, EnvelopeError::Quarantined { .. }), "{err}");
}

#[test]
fn t09_protocol_mismatch_rejected() {
    let mut f = fixture();
    let nonce = f.verifier.outstanding_nonce(AGENT).unwrap();
    let mut msg = envelope(1, &nonce, SystemTime::now());
    msg.protocol = "agent/v0".into();
    let err = f
        .verifier
        .verify(&mut f.registry, &msg, SystemTime::now())
        .expect_err("protocol mismatch must be rejected");
    assert!(
        matches!(err, EnvelopeError::ProtocolMismatch { .. }),
        "{err}"
    );
}

#[test]
fn t10_strict_schema_and_bad_timestamp() {
    // Unknown fields are rejected by the strict schema (SEC-208).
    let json = serde_json::json!({
        "protocol": PROTOCOL,
        "agent_id": AGENT,
        "sequence": 1,
        "server_nonce": "00",
        "timestamp": "2026-08-22T10:00:00Z",
        "request_id": "0123456789abcdef0123456789abcdef",
        "kind": "heartbeat",
        "body": {},
        "shell_command": "rm -rf /"
    });
    let err = serde_json::from_value::<MessageEnvelope>(json)
        .expect_err("unknown field must be rejected");
    assert!(err.to_string().contains("shell_command"), "{err}");

    // Malformed timestamp is rejected at verification time.
    let mut f = fixture();
    let nonce = f.verifier.outstanding_nonce(AGENT).unwrap();
    let mut msg = envelope(1, &nonce, SystemTime::now());
    msg.timestamp = "not-a-timestamp".into();
    let err = f
        .verifier
        .verify(&mut f.registry, &msg, SystemTime::now())
        .expect_err("malformed timestamp must be rejected");
    assert!(matches!(err, EnvelopeError::MalformedTimestamp(_)), "{err}");
}

#[test]
fn t11_bad_request_id_rejected() {
    let mut f = fixture();
    let nonce = f.verifier.outstanding_nonce(AGENT).unwrap();
    let mut msg = envelope(1, &nonce, SystemTime::now());
    msg.request_id = "short".into();
    let err = f
        .verifier
        .verify(&mut f.registry, &msg, SystemTime::now())
        .expect_err("malformed request id must be rejected");
    assert!(matches!(err, EnvelopeError::BadRequestId), "{err}");
}
