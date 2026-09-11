// SPDX-License-Identifier: AGPL-3.0-or-later
//! Mutual TLS configuration built on the existing X.509 hierarchy.
//!
//! The certificates issued by [`crate::ca::CaHierarchy`] are standard DER
//! X.509 with Ed25519 keys, which rustls (ring provider) accepts directly.
//! This module turns them into ready-to-use `rustls` configs:
//!
//! - [`server_config`]: terminates TLS and **requires** a client certificate
//!   issued by the hierarchy (agent authentication).
//! - [`agent_client_config`]: presents the agent certificate and only trusts
//!   the Vigile hierarchy (server authentication).
//!
//! Both directions are verified: neither side accepts an anonymous peer.

use std::sync::Arc;

use rustls::pki_types::{CertificateRevocationListDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use crate::ca::{CaHierarchy, IssuedCertificate};
use crate::PkiError;

fn trust_store(ca: &CaHierarchy) -> Result<RootCertStore, PkiError> {
    let mut roots = RootCertStore::empty();
    roots
        .add(ca.root_cert().clone())
        .map_err(|e| PkiError::CertificateIssuance(format!("root not usable: {e}")))?;
    roots
        .add(ca.intermediate_cert().clone())
        .map_err(|e| PkiError::CertificateIssuance(format!("intermediate not usable: {e}")))?;
    Ok(roots)
}

fn private_key(der: &[u8]) -> Result<PrivateKeyDer<'static>, PkiError> {
    // `IssuedCertificate::private_key_der` is always PKCS#8 DER for
    // locally-generated keys (CSR-issued certs have no key and must not
    // reach this path).
    if der.is_empty() {
        return Err(PkiError::CertificateIssuance(
            "no private key (CSR-issued certificate cannot drive a TLS endpoint)".into(),
        ));
    }
    Ok(PrivateKeyDer::Pkcs8(der.to_vec().into()))
}

/// Server-side mTLS config: requires a client certificate chaining to the
/// Vigile intermediate. `server` must carry `serverAuth` EKU and a SAN
/// matching the name agents dial.
///
/// Revocation is fail-closed (ADR-0010): fresh empty CRLs are attached for
/// both chain levels so any status other than "present and valid" denies
/// the peer. Production callers that maintain real CRLs should resolve
/// agent identity through them before reaching here.
pub fn server_config(
    server: &IssuedCertificate,
    ca: &CaHierarchy,
) -> Result<Arc<ServerConfig>, PkiError> {
    let leaf_crl = ca.leaf_crl(1, &[])?;
    let intermediate_crl = ca.intermediate_crl(1, &[])?;
    let verifier = WebPkiClientVerifier::builder(trust_store(ca)?.into())
        .with_crls(vec![
            CertificateRevocationListDer::from(leaf_crl),
            CertificateRevocationListDer::from(intermediate_crl),
        ])
        .build()
        .map_err(|e| PkiError::CertificateIssuance(format!("client verifier: {e}")))?;
    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server.chain.clone(), private_key(&server.private_key_der)?)
        .map_err(|e| PkiError::CertificateIssuance(format!("server cert rejected: {e}")))?;
    Ok(Arc::new(config))
}

/// Server-side TLS config with **optional** client certificates: browsers
/// reach the portal anonymously, but agent endpoints must check
/// `peer_certificates()` themselves and refuse `None` (single-port lab
/// deployment). When present, the certificate must still chain to the
/// Vigile hierarchy — no third-party credential is accepted.
pub fn server_config_optional_client(
    server: &IssuedCertificate,
    ca: &CaHierarchy,
) -> Result<Arc<ServerConfig>, PkiError> {
    let leaf_crl = ca.leaf_crl(1, &[])?;
    let intermediate_crl = ca.intermediate_crl(1, &[])?;
    let verifier = WebPkiClientVerifier::builder(trust_store(ca)?.into())
        .with_crls(vec![
            CertificateRevocationListDer::from(leaf_crl),
            CertificateRevocationListDer::from(intermediate_crl),
        ])
        .allow_unauthenticated()
        .build()
        .map_err(|e| PkiError::CertificateIssuance(format!("client verifier: {e}")))?;
    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server.chain.clone(), private_key(&server.private_key_der)?)
        .map_err(|e| PkiError::CertificateIssuance(format!("server cert rejected: {e}")))?;
    Ok(Arc::new(config))
}

/// Agent-side mTLS config: presents `agent` (clientAuth EKU, CN = agent id)
/// and trusts only the Vigile hierarchy for the server certificate.
pub fn agent_client_config(
    agent: &IssuedCertificate,
    ca: &CaHierarchy,
) -> Result<Arc<ClientConfig>, PkiError> {
    let config = ClientConfig::builder()
        .with_root_certificates(trust_store(ca)?)
        .with_client_auth_cert(agent.chain.clone(), private_key(&agent.private_key_der)?)
        .map_err(|e| PkiError::CertificateIssuance(format!("agent cert rejected: {e}")))?;
    Ok(Arc::new(config))
}

/// Client config without a certificate — used by tests to prove the server
/// rejects anonymous peers. Never use it in production code paths.
#[cfg(test)]
pub fn anonymous_client_config(ca: &CaHierarchy) -> Result<Arc<ClientConfig>, PkiError> {
    let config = ClientConfig::builder()
        .with_root_certificates(trust_store(ca)?)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

// Re-exported for callers that need to build raw certificate chains.
pub use rustls::pki_types::ServerName;

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    use rustls::{ClientConnection, ServerConnection};

    use super::*;
    use crate::ca::CaHierarchy;

    fn test_ca() -> CaHierarchy {
        CaHierarchy::generate("Vigile Test Root", "Vigile Test Issuer").expect("hierarchy")
    }

    /// Drives one side of the handshake until it completes or errors.
    fn drive_handshake(
        conn: &mut rustls::Connection,
        stream: &mut TcpStream,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        while conn.is_handshaking() {
            while conn.wants_write() {
                conn.write_tls(stream)?;
            }
            if conn.wants_read() {
                if conn.read_tls(stream)? == 0 {
                    return Err("peer closed during handshake".into());
                }
                conn.process_new_packets()?;
            }
        }
        while conn.wants_write() {
            conn.write_tls(stream)?;
        }
        Ok(())
    }

    /// Runs a full mTLS session against an in-process server and returns the
    /// client connection (handshake completed).
    fn session(
        client_cfg: Arc<ClientConfig>,
        server_cfg: Arc<ServerConfig>,
    ) -> Result<ClientConnection, Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = std::thread::spawn(
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                let (mut sock, _) = listener.accept().expect("accept");
                sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let mut conn: rustls::Connection =
                    ServerConnection::new(server_cfg).expect("server conn").into();
                drive_handshake(&mut conn, &mut sock)?;
                // Server waits for a request byte, echoes it, then the test closes.
                let mut buf = [0u8; 1];
                conn.reader().read_exact(&mut buf).ok();
                conn.writer().write_all(&buf).ok();
                conn.send_close_notify();
                while conn.wants_write() {
                    conn.write_tls(&mut sock).ok();
                }
                Ok(())
            },
        );

        let mut sock = TcpStream::connect(addr).expect("connect");
        sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let name = ServerName::try_from("localhost").expect("server name");
        let mut conn: rustls::Connection =
            ClientConnection::new(client_cfg, name).expect("client conn").into();
        drive_handshake(&mut conn, &mut sock)?;
        let mut client = match conn {
            rustls::Connection::Client(c) => c,
            rustls::Connection::Server(_) => {
                return Err("client connection became server side".into())
            }
        };
        client.writer().write_all(b"x").expect("write");
        client.send_close_notify();
        while client.wants_write() {
            client.write_tls(&mut sock).expect("flush");
        }
        server.join().expect("server thread")?;
        Ok(client)
    }

    #[test]
    fn handshake_succeeds_and_exposes_agent_identity() {
        let ca = test_ca();
        let server_cert = ca.issue_server_certificate("localhost").expect("server cert");
        let agent_cert = ca.issue_agent_certificate("agent-007").expect("agent cert");

        let s = server_config(&server_cert, &ca).expect("server config");
        let c = agent_client_config(&agent_cert, &ca).expect("client config");
        let client = session(c, s).expect("handshake");

        let cert_chain = client.peer_certificates().expect("peer certs");
        assert!(!cert_chain.is_empty());
    }

    #[test]
    fn server_rejects_anonymous_client() {
        let ca = test_ca();
        let server_cert = ca.issue_server_certificate("localhost").expect("server cert");

        let s = server_config(&server_cert, &ca).expect("server config");
        let c = anonymous_client_config(&ca).expect("anon config");
        assert!(session(c, s).is_err(), "anonymous client must be rejected");
    }

    #[test]
    fn csr_issued_certificate_cannot_drive_client_tls() {
        let ca = test_ca();
        let server_cert = ca.issue_server_certificate("localhost").expect("server cert");

        // server_config must also refuse a keyless cert.
        let keyless = crate::ca::IssuedCertificate {
            certificate: server_cert.certificate.clone(),
            chain: server_cert.chain.clone(),
            private_key_der: Vec::new(),
            serial: server_cert.serial,
        };
        assert!(server_config(&keyless, &ca).is_err());
    }

    #[test]
    fn foreign_hierarchy_is_not_trusted() {
        let ca1 = test_ca();
        let ca2 = test_ca();
        let server_cert = ca1.issue_server_certificate("localhost").expect("server cert");
        let agent_cert = ca2.issue_agent_certificate("agent-traitor").expect("agent cert");

        let s = server_config(&server_cert, &ca1).expect("server config");
        let c = agent_client_config(&agent_cert, &ca2).expect("client config");
        assert!(session(c, s).is_err(), "foreign hierarchy must be rejected");
    }
}
