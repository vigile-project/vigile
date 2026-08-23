// SPDX-License-Identifier: AGPL-3.0-or-later
//! Enrollment protocol tests (ISS-012): one positive path, the full
//! end-to-end enrollment (CSR -> certificate -> live mTLS handshake), and
//! the mandatory negative tests (chart §1: no security function is done
//! without one).

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::{mtls_handshake, HandshakeOutcome, SERVER_NAME};
use std::time::{Duration, SystemTime};
use vigile_pki::{
    generate_agent_csr, process_enrollment, CaHierarchy, EnrollmentError, EnrollmentRequest,
    EnrollmentTokenClaims, EnrollmentTokenIssuer, EnrollmentTokenVerifier, InMemorySingleUseStore,
};

const TENANT: &str = "tenant-lab";

struct Fixture {
    ca: CaHierarchy,
    issuer: EnrollmentTokenIssuer,
    verifier: EnrollmentTokenVerifier,
    store: InMemorySingleUseStore,
    server: vigile_pki::IssuedCertificate,
}

fn fixture() -> Fixture {
    let ca = CaHierarchy::generate("Vigile Test Root", "Vigile Test Issuer").expect("hierarchy");
    let issuer = EnrollmentTokenIssuer::generate().expect("token issuer");
    let verifier = EnrollmentTokenVerifier::from_verifying_key(issuer.verifying_key());
    let server = ca
        .issue_server_certificate(SERVER_NAME)
        .expect("server certificate");
    Fixture {
        ca,
        issuer,
        verifier,
        store: InMemorySingleUseStore::default(),
        server,
    }
}

fn token(f: &Fixture) -> String {
    f.issuer
        .issue(TENANT, Some("workstations".into()), 3600, SystemTime::now())
        .expect("token issuance")
}

fn request(token: String) -> EnrollmentRequest {
    let csr = generate_agent_csr().expect("agent CSR");
    EnrollmentRequest {
        token,
        csr_der: csr.csr_der,
        machine_fingerprint: "machine-id:test-lab-01".into(),
    }
}

fn claims_now() -> EnrollmentTokenClaims {
    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    EnrollmentTokenClaims {
        typ: EnrollmentTokenClaims::TYPE.into(),
        jti: "0123456789abcdef0123456789abcdef".into(),
        tenant: TENANT.into(),
        group: None,
        not_before: now - 60,
        expires_at: now + 3600,
    }
}

#[test]
fn t01_token_roundtrip_verifies() {
    let mut f = fixture();
    let token = token(&f);
    let claims = f
        .verifier
        .verify(&token, SystemTime::now(), TENANT, &mut f.store)
        .expect("fresh token must verify");
    assert_eq!(claims.tenant, TENANT);
}

#[test]
fn t02_token_replay_rejected() {
    let f = fixture();
    let token = token(&f);
    let mut store = InMemorySingleUseStore::default();
    f.verifier
        .verify(&token, SystemTime::now(), TENANT, &mut store)
        .expect("first use");
    let err = f
        .verifier
        .verify(&token, SystemTime::now(), TENANT, &mut store)
        .expect_err("replay must be rejected");
    assert_eq!(err, EnrollmentError::AlreadyUsed);
}

#[test]
fn t03_expired_token_rejected() {
    let mut f = fixture();
    let token = f
        .issuer
        .issue(
            TENANT,
            None,
            60,
            SystemTime::now() - Duration::from_secs(3600),
        )
        .expect("token");
    let err = f
        .verifier
        .verify(&token, SystemTime::now(), TENANT, &mut f.store)
        .expect_err("expired token must be rejected");
    assert_eq!(err, EnrollmentError::Expired);
}

#[test]
fn t04_token_not_yet_valid_rejected() {
    let mut f = fixture();
    let token = f
        .issuer
        .issue(
            TENANT,
            None,
            60,
            SystemTime::now() + Duration::from_secs(3600),
        )
        .expect("token");
    let err = f
        .verifier
        .verify(&token, SystemTime::now(), TENANT, &mut f.store)
        .expect_err("future token must be rejected");
    assert_eq!(err, EnrollmentError::NotYetValid);
}

#[test]
fn t05_tampered_payload_rejected() {
    let mut f = fixture();
    let token = token(&f);
    // Flip the first hex character of the payload.
    let mut chars: Vec<char> = token.chars().collect();
    chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
    let tampered: String = chars.into_iter().collect();
    let err = f
        .verifier
        .verify(&tampered, SystemTime::now(), TENANT, &mut f.store)
        .expect_err("tampered token must be rejected");
    assert!(matches!(
        err,
        EnrollmentError::BadSignature | EnrollmentError::Malformed(_)
    ));
}

#[test]
fn t06_wrong_signing_key_rejected() {
    let mut f = fixture();
    let token = token(&f);
    let other = EnrollmentTokenIssuer::generate().expect("other key");
    let verifier = EnrollmentTokenVerifier::from_verifying_key(other.verifying_key());
    let err = verifier
        .verify(&token, SystemTime::now(), TENANT, &mut f.store)
        .expect_err("foreign key must be rejected");
    assert_eq!(err, EnrollmentError::BadSignature);
}

#[test]
fn t07_wrong_tenant_rejected() {
    let mut f = fixture();
    let token = token(&f);
    let err = f
        .verifier
        .verify(&token, SystemTime::now(), "tenant-other", &mut f.store)
        .expect_err("cross-tenant token must be rejected");
    assert_eq!(err, EnrollmentError::WrongTenant);
}

#[test]
fn t08_garbage_token_rejected() {
    let mut f = fixture();
    for garbage in ["", "not-a-token", "aaaa.bbbb.cccc", "zz..", "a.b"] {
        let err = f
            .verifier
            .verify(garbage, SystemTime::now(), TENANT, &mut f.store)
            .expect_err("garbage must be rejected");
        assert!(matches!(err, EnrollmentError::Malformed(_)), "{garbage}");
    }
}

#[test]
fn t09_wrong_token_type_rejected() {
    let mut f = fixture();
    let mut claims = claims_now();
    claims.typ = "something-else/v1".into();
    let token = f.issuer.issue_with_claims(&claims).expect("token");
    let err = f
        .verifier
        .verify(&token, SystemTime::now(), TENANT, &mut f.store)
        .expect_err("wrong type must be rejected");
    assert_eq!(err, EnrollmentError::WrongType);
}

#[test]
fn t10_unknown_claims_field_rejected() {
    let mut f = fixture();
    // Signed by the GENUINE key but carrying an unknown field: the
    // signature is valid, the strict schema must refuse it.
    let mut claims = claims_now();
    claims.typ = EnrollmentTokenClaims::TYPE.into();
    let mut json = serde_json::to_value(&claims).unwrap().to_string();
    json.truncate(json.len() - 1); // drop trailing '}'
    json.push_str(r#","backdoor":true}"#);
    let token = f.issuer.sign_raw(json.as_bytes());
    let err = f
        .verifier
        .verify(&token, SystemTime::now(), TENANT, &mut f.store)
        .expect_err("unknown field must be rejected");
    assert!(matches!(err, EnrollmentError::Malformed(_)), "{err}");
}

#[test]
fn t11_full_enrollment_end_to_end_with_handshake() {
    let f = fixture();
    let token = token(&f);
    let csr = generate_agent_csr().expect("agent CSR");
    let agent_key_der = csr.key_pair.serialize_der();

    let enrolled = process_enrollment(
        &f.ca,
        &f.verifier,
        &mut { f.store },
        &EnrollmentRequest {
            token,
            csr_der: csr.csr_der,
            machine_fingerprint: "machine-id:test-lab-01".into(),
        },
        SystemTime::now(),
        TENANT,
    )
    .expect("enrollment");

    // Agent id derives deterministically from the token id.
    assert_eq!(enrolled.agent_id, format!("agent-{}", enrolled.jti));
    assert_eq!(enrolled.machine_fingerprint, "machine-id:test-lab-01");

    // The enrolled certificate actually works for mTLS with the agent key.
    let outcome = mtls_handshake(
        f.ca.root_cert(),
        &f.server.chain,
        &f.server.private_key_der,
        &enrolled.certificate.chain,
        Some(&agent_key_der),
        &[],
    )
    .expect("handshake with enrolled certificate");
    assert_eq!(outcome, HandshakeOutcome::Success);
}

#[test]
fn t12_full_enrollment_replay_rejected() {
    let f = fixture();
    let token = token(&f);
    let mut store = InMemorySingleUseStore::default();
    let first = process_enrollment(
        &f.ca,
        &f.verifier,
        &mut store,
        &request(token.clone()),
        SystemTime::now(),
        TENANT,
    );
    assert!(first.is_ok(), "first enrollment must succeed");
    let err = process_enrollment(
        &f.ca,
        &f.verifier,
        &mut store,
        &request(token),
        SystemTime::now(),
        TENANT,
    )
    .expect_err("token replay must be rejected");
    assert_eq!(err, EnrollmentError::AlreadyUsed);
}

#[test]
fn t13_csr_with_tampered_signature_rejected() {
    let f = fixture();
    let token = token(&f);
    let csr = generate_agent_csr().expect("agent CSR");
    let mut tampered = csr.csr_der.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff;
    let err = process_enrollment(
        &f.ca,
        &f.verifier,
        &mut { f.store },
        &EnrollmentRequest {
            token,
            csr_der: tampered,
            machine_fingerprint: "machine-id:x".into(),
        },
        SystemTime::now(),
        TENANT,
    )
    .expect_err("tampered CSR must be rejected");
    assert!(matches!(err, EnrollmentError::Csr(_)), "{err}");
}

#[test]
fn t14_invalid_fingerprint_rejected() {
    let f = fixture();
    let token = token(&f);
    let csr = generate_agent_csr().expect("agent CSR");
    let err = process_enrollment(
        &f.ca,
        &f.verifier,
        &mut { f.store },
        &EnrollmentRequest {
            token,
            csr_der: csr.csr_der,
            machine_fingerprint: "   ".into(),
        },
        SystemTime::now(),
        TENANT,
    )
    .expect_err("blank fingerprint must be rejected");
    assert_eq!(err, EnrollmentError::InvalidFingerprint);
}
