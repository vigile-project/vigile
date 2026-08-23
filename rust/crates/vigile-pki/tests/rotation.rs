// SPDX-License-Identifier: AGPL-3.0-or-later
//! Certificate rotation tests (ISS-013): renewal decision at T-30 days,
//! validity overlap, key rotation, revocation of the old certificate, and
//! CRL expiration enforcement (`enforce_revocation_expiration`).

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::{mtls_handshake, mtls_handshake_with_options, HandshakeOutcome, SERVER_NAME};
use rustls::pki_types::CertificateRevocationListDer;
use std::time::{Duration, SystemTime};
use vigile_pki::{certificate_expiry, generate_agent_csr, should_renew, CaHierarchy};

fn fixture() -> (CaHierarchy, vigile_pki::IssuedCertificate) {
    let ca = CaHierarchy::generate("Vigile Test Root", "Vigile Test Issuer").expect("hierarchy");
    let server = ca
        .issue_server_certificate(SERVER_NAME)
        .expect("server certificate");
    (ca, server)
}

#[test]
fn t01_should_renew_triggers_at_threshold() {
    let (ca, server) = fixture();
    let _ = server;
    let csr = generate_agent_csr().expect("CSR");
    let cert = ca
        .issue_agent_certificate_from_csr(&csr.csr_der, "agent-r1")
        .expect("certificate (90 days)");
    let expiry = certificate_expiry(cert.certificate.as_ref()).expect("expiry");

    // Far from expiry: no renewal needed.
    assert!(!should_renew(cert.certificate.as_ref(), SystemTime::now()).unwrap());

    // Inside the T-30d window: renewal needed.
    let near_expiry = expiry - Duration::from_secs(vigile_pki::RENEWAL_THRESHOLD_SECS / 2);
    assert!(should_renew(cert.certificate.as_ref(), near_expiry).unwrap());

    // After expiry: renewal (long) overdue — still true.
    let after = expiry + Duration::from_secs(3600);
    assert!(should_renew(cert.certificate.as_ref(), after).unwrap());
}

#[test]
fn t02_renewal_overlaps_with_previous_certificate() {
    let (ca, server) = fixture();
    let old_csr = generate_agent_csr().expect("old CSR");
    let old = ca
        .issue_agent_certificate_from_csr(&old_csr.csr_der, "agent-r2")
        .expect("old certificate");

    // Renewal: fresh key (rotation) issued "later" (real now) — windows
    // overlap because both are anchored at their issuance time.
    let new_csr = generate_agent_csr().expect("new CSR");
    let new = ca
        .issue_agent_certificate_from_csr(&new_csr.csr_der, "agent-r2")
        .expect("renewed certificate");
    assert_ne!(old.serial, new.serial, "renewal must change the serial");

    let old_expiry = certificate_expiry(old.certificate.as_ref()).unwrap();
    let new_start = SystemTime::now();
    assert!(
        new_start < old_expiry,
        "validity windows must overlap during rotation"
    );

    // Both certificates authenticate live during the overlap.
    let old_key = old_csr.key_pair.serialize_der();
    let new_key = new_csr.key_pair.serialize_der();
    for (label, chain, key) in [
        ("old", &old.chain, old_key.as_slice()),
        ("new", &new.chain, new_key.as_slice()),
    ] {
        let result = mtls_handshake(
            ca.root_cert(),
            &server.chain,
            &server.private_key_der,
            chain,
            Some(key),
            &[],
        );
        assert_eq!(
            result,
            Ok(HandshakeOutcome::Success),
            "{label} certificate must work during overlap"
        );
    }
}

#[test]
fn t03_revoked_old_certificate_rejected_new_accepted() {
    let (ca, server) = fixture();
    let old_csr = generate_agent_csr().expect("old CSR");
    let old = ca
        .issue_agent_certificate_from_csr(&old_csr.csr_der, "agent-r3")
        .expect("old certificate");
    let new_csr = generate_agent_csr().expect("new CSR");
    let new = ca
        .issue_agent_certificate_from_csr(&new_csr.csr_der, "agent-r3")
        .expect("new certificate");

    // Typical post-rotation state: only the OLD serial is revoked.
    let inter_crl =
        CertificateRevocationListDer::from(ca.intermediate_crl(1, &[]).expect("root CRL"));
    let leaf_crl = CertificateRevocationListDer::from(
        ca.leaf_crl(2, std::slice::from_ref(&old.serial))
            .expect("leaf CRL revoking old serial"),
    );
    let crls = [inter_crl, leaf_crl];

    let err = mtls_handshake(
        ca.root_cert(),
        &server.chain,
        &server.private_key_der,
        &old.chain,
        Some(&old_csr.key_pair.serialize_der()),
        &crls,
    )
    .expect_err("revoked old certificate must be rejected");
    assert!(err.to_lowercase().contains("revok"), "got: {err}");

    let outcome = mtls_handshake(
        ca.root_cert(),
        &server.chain,
        &server.private_key_der,
        &new.chain,
        Some(&new_csr.key_pair.serialize_der()),
        &crls,
    )
    .expect("renewed certificate must still be accepted");
    assert_eq!(outcome, HandshakeOutcome::Success);
}

#[test]
fn t04_expired_certificate_rejected() {
    let (ca, server) = fixture();
    let csr = generate_agent_csr().expect("CSR");
    let now = SystemTime::now();
    let expired = ca
        .issue_agent_certificate_from_csr_with_window(
            &csr.csr_der,
            "agent-r4",
            (
                now - Duration::from_secs(7200),
                now - Duration::from_secs(3600),
            ),
        )
        .expect("certificate valid [now-2h, now-1h]");

    let err = mtls_handshake(
        ca.root_cert(),
        &server.chain,
        &server.private_key_der,
        &expired.chain,
        Some(&csr.key_pair.serialize_der()),
        &[],
    )
    .expect_err("expired certificate must be rejected");
    assert!(
        err.to_lowercase().contains("expir"),
        "expiry expected, got: {err}"
    );
}

#[test]
fn t05_expired_crl_rejected_when_enforced() {
    let (ca, server) = fixture();
    let csr = generate_agent_csr().expect("CSR");
    let agent = ca
        .issue_agent_certificate_from_csr(&csr.csr_der, "agent-r5")
        .expect("certificate");

    // CRL whose nextUpdate is already in the past, plus an empty root CRL.
    let inter_crl = CertificateRevocationListDer::from(
        ca.intermediate_crl_with_ttl(1, &[], -3600)
            .expect("root CRL (expired)"),
    );
    let leaf_crl = CertificateRevocationListDer::from(
        ca.leaf_crl_with_ttl(1, &[], -3600)
            .expect("leaf CRL (expired)"),
    );
    let crls = [inter_crl, leaf_crl];

    // Fail-closed posture (production): expired CRL = error.
    let err = mtls_handshake_with_options(
        ca.root_cert(),
        &server.chain,
        &server.private_key_der,
        &agent.chain,
        Some(&csr.key_pair.serialize_der()),
        &crls,
        true,
    )
    .expect_err("expired CRL must be an error when enforced");
    let lower = err.to_lowercase();
    assert!(
        lower.contains("crl") || lower.contains("revocation"),
        "CRL expiry expected, got: {err}"
    );

    // Default rustls posture (Ignore) still succeeds — documented
    // fail-open that Vigile must never use in production.
    let outcome = mtls_handshake_with_options(
        ca.root_cert(),
        &server.chain,
        &server.private_key_der,
        &agent.chain,
        Some(&csr.key_pair.serialize_der()),
        &crls,
        false,
    )
    .expect("rustls default ignores CRL expiry (documented fail-open)");
    assert_eq!(outcome, HandshakeOutcome::Success);
}
