// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests: the six prototype scenarios (ISS-011) replayed on
//! the production crate.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::{mtls_handshake, HandshakeOutcome, SERVER_NAME};
use rustls::pki_types::CertificateRevocationListDer;
use vigile_pki::CaHierarchy;
use x509_cert::der::Decode as _;
use x509_cert::ext::pkix::BasicConstraints;

struct Fixture {
    ca: CaHierarchy,
    root: rustls::pki_types::CertificateDer<'static>,
    server: vigile_pki::IssuedCertificate,
    agent: vigile_pki::IssuedCertificate,
}

fn fixture() -> Fixture {
    let ca = CaHierarchy::generate("Vigile Test Root", "Vigile Test Issuer").expect("hierarchy");
    let server = ca
        .issue_server_certificate(SERVER_NAME)
        .expect("server certificate");
    let agent = ca
        .issue_agent_certificate("agent-0001")
        .expect("agent certificate");
    let root = ca.root_cert().clone();
    Fixture {
        ca,
        root,
        server,
        agent,
    }
}

fn der(cert: &rustls::pki_types::CertificateDer<'_>) -> x509_cert::Certificate {
    x509_cert::Certificate::from_der(cert.as_ref()).unwrap()
}

#[test]
fn t01_chain_profiles_are_constrained() {
    let f = fixture();
    let inter = der(&f.ca.intermediate_cert().clone());
    let agent = der(&f.agent.certificate);

    let (_, bc) = inter
        .tbs_certificate()
        .get_extension::<BasicConstraints>()
        .unwrap()
        .expect("intermediate must have basicConstraints");
    assert!(bc.ca);
    assert_eq!(bc.path_len_constraint, Some(0));

    let bc_agent = agent
        .tbs_certificate()
        .get_extension::<BasicConstraints>()
        .unwrap();
    assert!(
        bc_agent.is_none() || !bc_agent.unwrap().1.ca,
        "agent certificate must not be a CA"
    );
    // clientAuth EKU is proven by the handshake itself (t02).
}

#[test]
fn t02_mtls_ed25519_ring_succeeds() {
    let f = fixture();
    let outcome = mtls_handshake(
        &f.root,
        &f.server.chain,
        &f.server.private_key_der,
        &f.agent.chain,
        Some(&f.agent.private_key_der),
        &[],
    )
    .expect("Ed25519 mTLS handshake with the ring backend");
    assert_eq!(outcome, HandshakeOutcome::Success);
}

#[test]
fn t03_client_without_certificate_is_rejected() {
    let f = fixture();
    let err = mtls_handshake(
        &f.root,
        &f.server.chain,
        &f.server.private_key_der,
        &[],
        None,
        &[],
    )
    .expect_err("client without certificate must be rejected");
    let lower = err.to_lowercase();
    assert!(
        lower.contains("certificat")
            || lower.contains("certificate")
            || lower.contains("handshake"),
        "unexpected error: {err}"
    );
}

#[test]
fn t04_leaf_crl_revokes_agent() {
    let f = fixture();
    // rustls checks the whole chain: both CRLs are required.
    let inter_crl =
        CertificateRevocationListDer::from(f.ca.intermediate_crl(1, &[]).expect("root CRL"));
    let leaf_crl = CertificateRevocationListDer::from(
        f.ca.leaf_crl(1, std::slice::from_ref(&f.agent.serial))
            .expect("leaf CRL"),
    );
    let err = mtls_handshake(
        &f.root,
        &f.server.chain,
        &f.server.private_key_der,
        &f.agent.chain,
        Some(&f.agent.private_key_der),
        &[inter_crl, leaf_crl],
    )
    .expect_err("revoked agent must be rejected");
    assert!(
        err.to_lowercase().contains("revok"),
        "revocation expected, got: {err}"
    );
}

#[test]
fn t05_clean_crl_does_not_affect_others() {
    let f = fixture();
    let inter_crl =
        CertificateRevocationListDer::from(f.ca.intermediate_crl(1, &[]).expect("root CRL"));
    let leaf_crl = CertificateRevocationListDer::from(
        f.ca.leaf_crl(1, &[vec![0x0f, 0xf0, 0x00]])
            .expect("leaf CRL"),
    );
    let outcome = mtls_handshake(
        &f.root,
        &f.server.chain,
        &f.server.private_key_der,
        &f.agent.chain,
        Some(&f.agent.private_key_der),
        &[inter_crl, leaf_crl],
    )
    .expect("non-revoked agent must succeed despite CRLs");
    assert_eq!(outcome, HandshakeOutcome::Success);
}

#[test]
fn t06_root_crl_revoking_intermediate_kills_chain() {
    let f = fixture();
    let inter_serial = {
        let parsed = der(&f.ca.intermediate_cert().clone());
        parsed.tbs_certificate().serial_number().as_bytes().to_vec()
    };
    let inter_crl = CertificateRevocationListDer::from(
        f.ca.intermediate_crl(1, &[inter_serial]).expect("root CRL"),
    );
    let leaf_crl = CertificateRevocationListDer::from(f.ca.leaf_crl(1, &[]).expect("leaf CRL"));
    let err = mtls_handshake(
        &f.root,
        &f.server.chain,
        &f.server.private_key_der,
        &f.agent.chain,
        Some(&f.agent.private_key_der),
        &[inter_crl, leaf_crl],
    )
    .expect_err("revoked intermediate must be rejected");
    assert!(
        err.to_lowercase().contains("revok"),
        "revocation expected, got: {err}"
    );
}
