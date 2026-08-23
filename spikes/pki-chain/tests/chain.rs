// SPDX-License-Identifier: AGPL-3.0-or-later
//! Prototype PKI sprint 2 — tests tranchant les points ouverts d'ISS-006.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use pki_chain_spike::{build_crl, build_root_crl, generate, mtls_handshake, HandshakeOutcome, Pki};
use rustls::pki_types::CertificateRevocationListDer;
use x509_cert::der::Decode;
use x509_cert::ext::pkix::BasicConstraints;

fn pki() -> Pki {
    generate().expect("génération PKI Ed25519")
}

#[test]
fn t01_chaine_ed25519_avec_profils_contraints() {
    let pki = pki();
    let client = x509_cert::Certificate::from_der(pki.client_cert.as_ref()).unwrap();
    let inter = x509_cert::Certificate::from_der(pki.intermediate_cert.as_ref()).unwrap();

    // Le client n'est pas une CA (pas de basicConstraints)
    assert!(inter
        .tbs_certificate()
        .get_extension::<BasicConstraints>()
        .unwrap()
        .is_some());
    let bc_client = client
        .tbs_certificate()
        .get_extension::<BasicConstraints>()
        .unwrap();
    assert!(
        bc_client.is_none() || !bc_client.unwrap().1.ca,
        "le certificat client ne doit pas être une CA"
    );

    // L'intermédiaire est une CA avec path-length 0
    let (_critical, bc) = inter
        .tbs_certificate()
        .get_extension::<BasicConstraints>()
        .unwrap()
        .expect("basicConstraints présent sur la CA");
    assert!(bc.ca);
    assert_eq!(bc.path_len_constraint, Some(0));

    // NB : l'EKU clientAuth est prouvé cryptographiquement par le handshake
    // (le WebPkiClientVerifier de rustls l'exige) — pas re-vérifié ici.
}

#[test]
fn t02_mtls_ed25519_backend_ring_reussit() {
    // C'était le point NON VÉRIFIÉ du spike ISS-006 : le signing Ed25519
    // côté client TLS avec le backend ring.
    let pki = pki();
    let outcome = mtls_handshake(&pki, &[], true).expect("handshake mTLS Ed25519");
    assert_eq!(outcome, HandshakeOutcome::Success);
}

#[test]
fn t03_client_sans_certificat_rejete() {
    let pki = pki();
    let err = mtls_handshake(&pki, &[], false).expect_err("refus attendu sans certificat client");
    assert!(
        err.to_lowercase().contains("certificat")
            || err.to_lowercase().contains("certificate")
            || err.to_lowercase().contains("handshake"),
        "erreur inattendue : {err}"
    );
}

#[test]
fn t04_crl_revoque_le_client() {
    let pki = pki();
    // rustls vérifie TOUTE la chaîne : il faut la CRL de la racine
    // (intermédiaires) ET celle de l'intermédiaire (feuilles).
    let root_crl = CertificateRevocationListDer::from(build_root_crl(&pki, &[]).unwrap());
    let inter_crl = CertificateRevocationListDer::from(
        build_crl(&pki, std::slice::from_ref(&pki.client_serial)).expect("CRL signée par l'intermédiaire"),
    );
    let err = mtls_handshake(&pki, &[root_crl, inter_crl], true)
        .expect_err("client révoqué : refus attendu");
    assert!(
        err.to_lowercase().contains("revok"),
        "révocation attendue dans l'erreur, obtenu : {err}"
    );
}

#[test]
fn t05_crl_propre_ninterrompt_pas_les_autres() {
    let pki = pki();
    let root_crl = CertificateRevocationListDer::from(build_root_crl(&pki, &[]).unwrap());
    // CRL qui révoque un autre numéro de série que celui du client
    let inter_crl = CertificateRevocationListDer::from(
        build_crl(&pki, &[vec![0x0f, 0xf0, 0x00]]).expect("CRL"),
    );
    let outcome = mtls_handshake(&pki, &[root_crl, inter_crl], true)
        .expect("client non révoqué : succès attendu malgré la CRL");
    assert_eq!(outcome, HandshakeOutcome::Success);
}

#[test]
fn t06_crl_de_la_racine_revoque_lintermediaire() {
    let pki = pki();
    // Révoquer l'intermédiaire via la CRL racine doit couper toute la
    // chaîne de confiance.
    let root_crl = CertificateRevocationListDer::from(
        build_root_crl(&pki, std::slice::from_ref(&pki.inter_serial)).expect("CRL racine"),
    );
    let inter_crl = CertificateRevocationListDer::from(build_crl(&pki, &[]).unwrap());
    let err = mtls_handshake(&pki, &[root_crl, inter_crl], true)
        .expect_err("intermédiaire révoqué : refus attendu");
    assert!(
        err.to_lowercase().contains("revok"),
        "révocation attendue dans l'erreur, obtenu : {err}"
    );
}
