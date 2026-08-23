// SPDX-License-Identifier: AGPL-3.0-or-later
//! Prototype PKI — sprint 2 (ISS-011), points ouverts du spike ISS-006 :
//!
//! 1. chaîne racine (hors ligne simulée) → intermédiaire (en ligne) →
//!    certificats client/serveur, tout en Ed25519, profils contraints
//!    (EKU clientAuth/serverAuth, path-length 0 sur l'intermédiaire) ;
//! 2. handshake mTLS validé par rustls avec le backend **ring** (le
//!    signing Ed25519 côté ring était NON VÉRIFIÉ) ;
//! 3. CRL construite par `x509-cert::builder::CrlBuilder`, signée Ed25519
//!    par l'intermédiaire, consommée par rustls → révocation effective.

pub mod adapters;

use adapters::{Ed25519Sig, Ed25519Signer};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::error::Error;

pub const ROOT_CN: &str = "Vigile Lab Root CA";
pub const INTERMEDIATE_CN: &str = "Vigile Lab Issuing CA";
pub const CLIENT_CN: &str = "agent-0001";
pub const SERVER_CN: &str = "vigile-server.lab";

/// Matériel PKI complet pour un test (clés régénérées à chaque appel :
/// un test = une PKI fraîche, aucun état partagé).
pub struct Pki {
    pub root_cert: CertificateDer<'static>,
    pub root_key_der: Vec<u8>,
    pub intermediate_cert: CertificateDer<'static>,
    pub inter_key_der: Vec<u8>,
    pub client_cert: CertificateDer<'static>,
    pub client_key_der: Vec<u8>,
    pub server_cert: CertificateDer<'static>,
    pub server_key_der: Vec<u8>,
    pub client_serial: Vec<u8>,
    pub inter_serial: Vec<u8>,
}

fn ed25519_key() -> Result<KeyPair, Box<dyn Error>> {
    // Généré explicitement en Ed25519 (jamais d'algorithme implicite).
    KeyPair::generate_for(&rcgen::PKCS_ED25519).map_err(Into::into)
}

fn ca_params(cn: &str) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, cn);
    params
}

fn leaf_params(san: &str, cn: &str) -> Result<CertificateParams, Box<dyn Error>> {
    let mut params = CertificateParams::new(vec![san.to_string()])?;
    params.distinguished_name.push(DnType::CommonName, cn);
    Ok(params)
}

/// Génère la chaîne complète en Ed25519 avec profils contraints.
pub fn generate() -> Result<Pki, Box<dyn Error>> {
    // --- Racine (simule la clé hors ligne) --------------------------------
    let root_key = ed25519_key()?;
    let mut root_params = ca_params(ROOT_CN);
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let root = root_params.self_signed(&root_key)?;
    let root_issuer = Issuer::from_ca_cert_der(root.der(), &root_key)?;

    // --- Intermédiaire : CA contrainte (path-length 0) ---------------------
    let inter_key = ed25519_key()?;
    let mut inter_params = ca_params(INTERMEDIATE_CN);
    inter_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    inter_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let intermediate = inter_params.signed_by(&inter_key, &root_issuer)?;
    let inter_issuer = Issuer::from_ca_cert_der(intermediate.der(), &inter_key)?;

    // --- Certificat client (agent) : EKU clientAuth uniquement -------------
    let client_key = ed25519_key()?;
    let mut client_params = leaf_params(CLIENT_CN, CLIENT_CN)?;
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let client = client_params.signed_by(&client_key, &inter_issuer)?;

    // --- Certificat serveur : EKU serverAuth uniquement ---------------------
    let server_key = ed25519_key()?;
    let mut server_params = leaf_params(SERVER_CN, SERVER_CN)?;
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server = server_params.signed_by(&server_key, &inter_issuer)?;

    let client_serial = {
        use x509_cert::der::Decode;
        let parsed = x509_cert::Certificate::from_der(client.der().as_ref())?;
        parsed.tbs_certificate().serial_number().as_bytes().to_vec()
    };
    let inter_serial = {
        use x509_cert::der::Decode;
        let parsed = x509_cert::Certificate::from_der(intermediate.der().as_ref())?;
        parsed.tbs_certificate().serial_number().as_bytes().to_vec()
    };

    Ok(Pki {
        root_cert: root.into(),
        root_key_der: root_key.serialize_der(),
        intermediate_cert: intermediate.into(),
        inter_key_der: inter_key.serialize_der(),
        client_cert: client.into(),
        client_key_der: client_key.serialize_der(),
        server_cert: server.into(),
        server_key_der: server_key.serialize_der(),
        client_serial,
        inter_serial,
    })
}

/// Construit une CRL X.509 signée Ed25519 par l'émetteur donné, révoquant
/// les numéros de série fournis (DER en sortie).
///
/// NOTE rustls : `revocation_check_depth` vaut `Chain` par défaut — la
/// révocation est vérifiée sur TOUTE la chaîne ; il faut donc une CRL par
/// émetteur (racine → CRL des intermédiaires, intermédiaire → CRL des
/// feuilles), comme en RFC 5280.
pub fn build_crl_for(
    issuer_cert_der: &[u8],
    issuer_key_der: &[u8],
    revoked_serials: &[Vec<u8>],
) -> Result<Vec<u8>, Box<dyn Error>> {
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    use x509_cert::builder::{Builder, CrlBuilder};
    use x509_cert::der::{Decode, Encode};
    use x509_cert::ext::pkix::CrlNumber;
    use x509_cert::time::Time;

    let issuer = x509_cert::Certificate::from_der(issuer_cert_der)?;
    let signer = Ed25519Signer(ed25519_dalek::SigningKey::from_pkcs8_der(issuer_key_der)?);

    let now = der::asn1::UtcTime::from_system_time(std::time::SystemTime::now())?;
    let next = der::asn1::UtcTime::from_system_time(
        std::time::SystemTime::now() + std::time::Duration::from_secs(7 * 24 * 3600),
    )?;

    let revoked: x509_cert::der::Result<Vec<x509_cert::crl::RevokedCert>> = revoked_serials
        .iter()
        .map(|serial| {
            Ok(x509_cert::crl::RevokedCert {
                serial_number: x509_cert::serial_number::SerialNumber::new(serial)?,
                revocation_date: Time::UtcTime(now),
                crl_entry_extensions: None,
            })
        })
        .collect();

    let crl = CrlBuilder::new(&issuer, CrlNumber::try_from(1u32)?)?
        .with_next_update(Some(Time::UtcTime(next)))
        .with_certificates(revoked?.into_iter())
        .build::<_, Ed25519Sig>(&signer)?;

    Ok(crl.to_der()?)
}

/// CRL de l'intermédiaire (révoque des certificats feuilles).
pub fn build_crl(pki: &Pki, revoked_serials: &[Vec<u8>]) -> Result<Vec<u8>, Box<dyn Error>> {
    build_crl_for(
        pki.intermediate_cert.as_ref(),
        &pki.inter_key_der,
        revoked_serials,
    )
}

/// CRL de la racine (révoque des intermédiaires).
pub fn build_root_crl(pki: &Pki, revoked_serials: &[Vec<u8>]) -> Result<Vec<u8>, Box<dyn Error>> {
    build_crl_for(pki.root_cert.as_ref(), &pki.root_key_der, revoked_serials)
}

#[derive(Debug, PartialEq, Eq)]
pub enum HandshakeOutcome {
    Success,
}

/// Exécute un handshake mTLS lockstep client↔serveur rustls (backend ring),
/// en mémoire, puis un octet applicatif de preuve. Les erreurs sont
/// aplaties en `String` pour faciliter les tests négatifs.
pub fn mtls_handshake(
    pki: &Pki,
    crls: &[rustls::pki_types::CertificateRevocationListDer<'static>],
    present_client_cert: bool,
) -> Result<HandshakeOutcome, String> {
    inner_mtls(pki, crls, present_client_cert).map_err(|e| {
        let mut msg = e.to_string();
        let mut src: &dyn Error = e.as_ref();
        while let Some(cause) = src.source() {
            msg.push_str(" / cause: ");
            msg.push_str(&cause.to_string());
            src = cause;
        }
        msg
    })
}

fn inner_mtls(
    pki: &Pki,
    crls: &[rustls::pki_types::CertificateRevocationListDer<'static>],
    present_client_cert: bool,
) -> Result<HandshakeOutcome, Box<dyn Error>> {
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());

    // Côté serveur : vérification des certificats clients (mTLS) + CRL
    let mut roots = rustls::RootCertStore::empty();
    roots.add(pki.root_cert.clone())?;
    let mut verifier_builder =
        rustls::server::WebPkiClientVerifier::builder(std::sync::Arc::new(roots));
    if !crls.is_empty() {
        verifier_builder = verifier_builder.with_crls(crls.iter().cloned());
    }
    let verifier = verifier_builder.build()?;

    let server_config = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![pki.server_cert.clone(), pki.intermediate_cert.clone()],
            PrivateKeyDer::Pkcs8(pki.server_key_der.clone().into()),
        )?;

    // Côté client : racine de confiance + (option) certificat agent
    let mut client_roots = rustls::RootCertStore::empty();
    client_roots.add(pki.root_cert.clone())?;
    let client_config = if present_client_cert {
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(client_roots)
            .with_client_auth_cert(
                vec![pki.client_cert.clone(), pki.intermediate_cert.clone()],
                PrivateKeyDer::Pkcs8(pki.client_key_der.clone().into()),
            )?
    } else {
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(client_roots)
            .with_no_client_auth()
    };

    let mut server = rustls::ServerConnection::new(std::sync::Arc::new(server_config))?;
    let mut client = rustls::ClientConnection::new(
        std::sync::Arc::new(client_config),
        rustls::pki_types::ServerName::try_from(SERVER_CN.to_string())?,
    )?;

    // Pump lockstep jusqu'à la fin du handshake (ou l'échec explicite)
    for step in 0..32 {
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
        if step == 31 {
            return Err("handshake sans convergence (32 étapes)".into());
        }
        let mut wire = Vec::new();
        client.write_tls(&mut wire)?;
        if !wire.is_empty() {
            server.read_tls(&mut &wire[..])?;
            server.process_new_packets()?;
        }
        let mut wire = Vec::new();
        server.write_tls(&mut wire)?;
        if !wire.is_empty() {
            client.read_tls(&mut &mut &wire[..])?;
            client.process_new_packets()?;
        }
    }

    // Un octet applicatif dans chaque sens prouve la session établie
    std::io::Write::write_all(&mut client.writer(), b"ping")?;
    let mut wire = Vec::new();
    client.write_tls(&mut wire)?;
    server.read_tls(&mut &mut &wire[..])?;
    server.process_new_packets()?;
    let mut buf = [0u8; 4];
    let n = std::io::Read::read(&mut server.reader(), &mut buf)?;
    if n == 4 && &buf == b"ping" {
        Ok(HandshakeOutcome::Success)
    } else {
        Err("session établie mais données non transmises".into())
    }
}
