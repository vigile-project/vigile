// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shared test helpers: in-memory lockstep mTLS handshake (rustls, ring).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
use std::sync::Arc;

pub const SERVER_NAME: &str = "vigile-server.lab";

#[derive(Debug, PartialEq, Eq)]
pub enum HandshakeOutcome {
    Success,
}

/// Runs a lockstep client<->server rustls handshake over in-memory
/// buffers, then moves one application byte each way. Errors are flattened
/// to a string for negative tests.
pub fn mtls_handshake(
    root: &CertificateDer<'static>,
    server_chain: &[CertificateDer<'static>],
    server_key: &[u8],
    client_chain: &[CertificateDer<'static>],
    client_key: Option<&[u8]>,
    crls: &[CertificateRevocationListDer<'static>],
) -> Result<HandshakeOutcome, String> {
    mtls_handshake_with_options(
        root,
        server_chain,
        server_key,
        client_chain,
        client_key,
        crls,
        false,
    )
}

/// Same as [`mtls_handshake`] with an explicit policy on CRL expiration.
/// NOTE: rustls IGNORES expired CRLs by default (fail-open); the Vigile
/// server must always enforce expiration (ADR-0010) — production configs
/// must pass `true` here.
#[allow(clippy::too_many_arguments)]
pub fn mtls_handshake_with_options(
    root: &CertificateDer<'static>,
    server_chain: &[CertificateDer<'static>],
    server_key: &[u8],
    client_chain: &[CertificateDer<'static>],
    client_key: Option<&[u8]>,
    crls: &[CertificateRevocationListDer<'static>],
    enforce_crl_expiration: bool,
) -> Result<HandshakeOutcome, String> {
    run(
        root,
        server_chain,
        server_key,
        client_chain,
        client_key,
        crls,
        enforce_crl_expiration,
    )
    .map_err(flatten)
}

fn flatten(e: Box<dyn std::error::Error>) -> String {
    let mut msg = e.to_string();
    let mut src: &dyn std::error::Error = e.as_ref();
    while let Some(cause) = src.source() {
        msg.push_str(" / cause: ");
        msg.push_str(&cause.to_string());
        src = cause;
    }
    msg
}

fn run(
    root: &CertificateDer<'static>,
    server_chain: &[CertificateDer<'static>],
    server_key: &[u8],
    client_chain: &[CertificateDer<'static>],
    client_key: Option<&[u8]>,
    crls: &[CertificateRevocationListDer<'static>],
    enforce_crl_expiration: bool,
) -> Result<HandshakeOutcome, Box<dyn std::error::Error>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    // Server: mTLS verification of client certificates + CRLs.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root.clone())?;
    let mut verifier_builder = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots));
    if !crls.is_empty() {
        verifier_builder = verifier_builder.with_crls(crls.iter().cloned());
        if enforce_crl_expiration {
            verifier_builder = verifier_builder.enforce_revocation_expiration();
        }
    }
    let verifier = verifier_builder.build()?;

    let server_config = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            server_chain.to_vec(),
            PrivateKeyDer::Pkcs8(server_key.to_vec().into()),
        )?;

    // Client: trust root, optional client certificate.
    let mut client_roots = rustls::RootCertStore::empty();
    client_roots.add(root.clone())?;
    let client_config = match client_key {
        Some(key) => rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(client_roots)
            .with_client_auth_cert(
                client_chain.to_vec(),
                PrivateKeyDer::Pkcs8(key.to_vec().into()),
            )?,
        None => rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(client_roots)
        .with_no_client_auth(),
    };

    let mut server = rustls::ServerConnection::new(Arc::new(server_config))?;
    let mut client = rustls::ClientConnection::new(
        Arc::new(client_config),
        rustls::pki_types::ServerName::try_from(SERVER_NAME.to_string())?,
    )?;

    for step in 0..32 {
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
        if step == 31 {
            return Err("handshake did not converge".into());
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
        Err("session established but application data did not flow".into())
    }
}
