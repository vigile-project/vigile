// SPDX-License-Identifier: AGPL-3.0-or-later
//! Internal CA hierarchy: offline root (simulated) + online intermediate,
//! full Ed25519, constrained profiles, per-issuer CRLs.

use crate::{
    PkiError, AGENT_CERT_VALIDITY_SECS, INTERMEDIATE_CA_VALIDITY_SECS, NOT_BEFORE_SKEW_SECS,
    ROOT_CA_VALIDITY_SECS,
};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::CertificateDer;
use time::OffsetDateTime;

/// A freshly issued certificate with its leaf-first chain and PKCS#8 key.
#[derive(Debug)]
pub struct IssuedCertificate {
    pub certificate: CertificateDer<'static>,
    /// Leaf-first chain to present to a peer (leaf + intermediate).
    pub chain: Vec<CertificateDer<'static>>,
    /// PKCS#8 DER private key.
    pub private_key_der: Vec<u8>,
    pub serial: Vec<u8>,
}

/// Root + intermediate CAs. In production the root key lives offline and
/// only the intermediate key stays on the issuing service (TB-5); here
/// both are held by the same object for lab/testing purposes.
pub struct CaHierarchy {
    root_cert: CertificateDer<'static>,
    root_key_der: Vec<u8>,
    intermediate_cert: CertificateDer<'static>,
    intermediate_key_der: Vec<u8>,
}

pub(crate) fn ed25519_key() -> Result<KeyPair, PkiError> {
    KeyPair::generate_for(&rcgen::PKCS_ED25519).map_err(|e| PkiError::KeyGeneration(e.to_string()))
}

fn set_validity(params: &mut CertificateParams, validity_secs: u64) -> Result<(), PkiError> {
    let (not_before, not_after) = window_from_now(validity_secs);
    params.not_before = to_offset_datetime(not_before)?;
    params.not_after = to_offset_datetime(not_after)?;
    Ok(())
}

fn ca_params(
    cn: &str,
    validity_secs: u64,
    constrained: bool,
) -> Result<CertificateParams, PkiError> {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, cn);
    params.is_ca = IsCa::Ca(if constrained {
        BasicConstraints::Constrained(0)
    } else {
        BasicConstraints::Unconstrained
    });
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    set_validity(&mut params, validity_secs)?;
    Ok(params)
}

/// Standard validity window: [now - skew, now + validity + skew] — the
/// backdated `notBefore` tolerates bounded clock drift (DEC-09).
pub fn window_from_now(validity_secs: u64) -> (std::time::SystemTime, std::time::SystemTime) {
    let now = std::time::SystemTime::now();
    let skew = std::time::Duration::from_secs(NOT_BEFORE_SKEW_SECS);
    (
        now - skew,
        now + skew + std::time::Duration::from_secs(validity_secs),
    )
}

fn to_offset_datetime(t: std::time::SystemTime) -> Result<OffsetDateTime, PkiError> {
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    OffsetDateTime::from_unix_timestamp(secs)
        .map_err(|e| PkiError::CertificateIssuance(format!("unrepresentable time: {e}")))
}

/// Absolute expiration time of a DER certificate.
pub fn certificate_expiry(cert_der: &[u8]) -> Result<std::time::SystemTime, PkiError> {
    use der::Decode as _;
    let parsed =
        x509_cert::Certificate::from_der(cert_der).map_err(|e| PkiError::Parsing(e.to_string()))?;
    time_to_system(&parsed.tbs_certificate().validity().not_after)
}

/// Renewal decision (SEC-104): renew once the remaining validity falls
/// below [`crate::RENEWAL_THRESHOLD_SECS`] (proposal DEC-09: T-30 days).
pub fn should_renew(cert_der: &[u8], now: std::time::SystemTime) -> Result<bool, PkiError> {
    let expiry = certificate_expiry(cert_der)?;
    let threshold = std::time::Duration::from_secs(crate::RENEWAL_THRESHOLD_SECS);
    Ok(now + threshold >= expiry)
}

fn time_to_system(t: &x509_cert::time::Time) -> Result<std::time::SystemTime, PkiError> {
    match t {
        x509_cert::time::Time::UtcTime(u) => Ok(u.to_system_time()),
        x509_cert::time::Time::GeneralTime(g) => Ok(g.to_system_time()),
    }
}

fn serial_of(cert: &rcgen::Certificate) -> Result<Vec<u8>, PkiError> {
    use x509_cert::der::Decode as _;
    let parsed = x509_cert::Certificate::from_der(cert.der().as_ref())
        .map_err(|e| PkiError::Parsing(e.to_string()))?;
    Ok(parsed.tbs_certificate().serial_number().as_bytes().to_vec())
}

impl CaHierarchy {
    /// Generates a fresh hierarchy (one test/lab run = one fresh PKI).
    pub fn generate(root_cn: &str, intermediate_cn: &str) -> Result<Self, PkiError> {
        // Root: simulates the offline key (unconstrained CA).
        let root_key = ed25519_key()?;
        let root_params = ca_params(root_cn, ROOT_CA_VALIDITY_SECS, false)?;
        let root = root_params
            .self_signed(&root_key)
            .map_err(|e| PkiError::CertificateIssuance(e.to_string()))?;
        let root_issuer = Issuer::from_ca_cert_der(root.der(), &root_key)
            .map_err(|e| PkiError::CertificateIssuance(e.to_string()))?;

        // Intermediate: constrained CA (path-length 0) — the online key.
        let inter_key = ed25519_key()?;
        let inter_params = ca_params(intermediate_cn, INTERMEDIATE_CA_VALIDITY_SECS, true)?;
        let intermediate = inter_params
            .signed_by(&inter_key, &root_issuer)
            .map_err(|e| PkiError::CertificateIssuance(e.to_string()))?;

        Ok(Self {
            root_cert: root.into(),
            root_key_der: root_key.serialize_der(),
            intermediate_cert: intermediate.into(),
            intermediate_key_der: inter_key.serialize_der(),
        })
    }

    pub fn root_cert(&self) -> &CertificateDer<'static> {
        &self.root_cert
    }

    pub fn intermediate_cert(&self) -> &CertificateDer<'static> {
        &self.intermediate_cert
    }

    /// Issues an agent (client) certificate: EKU clientAuth only, CN = agent
    /// id, no SAN (agent ids are not DNS names).
    pub fn issue_agent_certificate(&self, agent_id: &str) -> Result<IssuedCertificate, PkiError> {
        let inter_issuer = Issuer::from_ca_cert_der(
            &self.intermediate_cert,
            issue_key(&self.intermediate_key_der)?,
        )
        .map_err(|e| PkiError::CertificateIssuance(e.to_string()))?;

        let key = ed25519_key()?;
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, agent_id);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        set_validity(&mut params, AGENT_CERT_VALIDITY_SECS)?;

        let cert = params
            .signed_by(&key, &inter_issuer)
            .map_err(|e| PkiError::CertificateIssuance(e.to_string()))?;
        let serial = serial_of(&cert)?;

        let leaf: CertificateDer<'static> = cert.into();
        Ok(IssuedCertificate {
            certificate: leaf.clone(),
            chain: vec![leaf, self.intermediate_cert.clone()],
            private_key_der: key.serialize_der(),
            serial,
        })
    }

    /// Issues a server certificate: EKU serverAuth, SAN = DNS name.
    pub fn issue_server_certificate(&self, dns_name: &str) -> Result<IssuedCertificate, PkiError> {
        let inter_issuer = Issuer::from_ca_cert_der(
            &self.intermediate_cert,
            issue_key(&self.intermediate_key_der)?,
        )
        .map_err(|e| PkiError::CertificateIssuance(e.to_string()))?;

        let key = ed25519_key()?;
        let mut params = CertificateParams::new(vec![dns_name.to_string()])
            .map_err(|e| PkiError::CertificateIssuance(e.to_string()))?;
        params.distinguished_name.push(DnType::CommonName, dns_name);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        set_validity(&mut params, AGENT_CERT_VALIDITY_SECS)?;

        let cert = params
            .signed_by(&key, &inter_issuer)
            .map_err(|e| PkiError::CertificateIssuance(e.to_string()))?;
        let serial = serial_of(&cert)?;

        let leaf: CertificateDer<'static> = cert.into();
        Ok(IssuedCertificate {
            certificate: leaf.clone(),
            chain: vec![leaf, self.intermediate_cert.clone()],
            private_key_der: key.serialize_der(),
            serial,
        })
    }

    /// Issues an agent certificate from a verified CSR (public key only —
    /// the server never holds the agent private key). `private_key_der`
    /// is empty in the result for the same reason.
    pub fn issue_agent_certificate_from_csr(
        &self,
        csr_der: &[u8],
        agent_id: &str,
    ) -> Result<IssuedCertificate, PkiError> {
        self.issue_agent_certificate_from_csr_with_window(
            csr_der,
            agent_id,
            window_from_now(AGENT_CERT_VALIDITY_SECS),
        )
    }

    /// Same as [`issue_agent_certificate_from_csr`] with an explicit
    /// validity window. Used by renewal (overlap with the previous
    /// certificate) and by tests exercising expired certificates.
    pub fn issue_agent_certificate_from_csr_with_window(
        &self,
        csr_der: &[u8],
        agent_id: &str,
        window: (std::time::SystemTime, std::time::SystemTime),
    ) -> Result<IssuedCertificate, PkiError> {
        use der::{Decode as _, Encode as _};
        let csr = x509_cert::request::CertReq::from_der(csr_der)
            .map_err(|e| PkiError::Parsing(e.to_string()))?;
        let spki_der = csr
            .info
            .public_key
            .to_der()
            .map_err(|e| PkiError::Parsing(e.to_string()))?;
        let public_key = rcgen::SubjectPublicKeyInfo::from_der(&spki_der)
            .map_err(|e| PkiError::Parsing(e.to_string()))?;

        let inter_issuer = Issuer::from_ca_cert_der(
            &self.intermediate_cert,
            issue_key(&self.intermediate_key_der)?,
        )
        .map_err(|e| PkiError::CertificateIssuance(e.to_string()))?;

        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, agent_id);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.not_before = to_offset_datetime(window.0)?;
        params.not_after = to_offset_datetime(window.1)?;

        let cert = params
            .signed_by(&public_key, &inter_issuer)
            .map_err(|e| PkiError::CertificateIssuance(e.to_string()))?;
        let serial = serial_of(&cert)?;
        let leaf: CertificateDer<'static> = cert.into();
        Ok(IssuedCertificate {
            certificate: leaf.clone(),
            chain: vec![leaf, self.intermediate_cert.clone()],
            private_key_der: Vec::new(),
            serial,
        })
    }

    /// CRL for leaf certificates (signed by the intermediate), default
    /// 7-day validity window (proposal DEC-09).
    pub fn leaf_crl(
        &self,
        crl_number: u32,
        revoked_serials: &[Vec<u8>],
    ) -> Result<Vec<u8>, PkiError> {
        self.leaf_crl_with_ttl(crl_number, revoked_serials, crate::CRL_VALIDITY_SECS as i64)
    }

    /// CRL for leaf certificates with an explicit `nextUpdate` offset in
    /// seconds (may be negative to craft an already-expired CRL in tests;
    /// production must keep it positive and short — DEC-09).
    pub fn leaf_crl_with_ttl(
        &self,
        crl_number: u32,
        revoked_serials: &[Vec<u8>],
        ttl_secs: i64,
    ) -> Result<Vec<u8>, PkiError> {
        build_crl(
            &self.intermediate_cert,
            &self.intermediate_key_der,
            crl_number,
            revoked_serials,
            ttl_secs,
        )
    }

    /// CRL for intermediates (signed by the root).
    pub fn intermediate_crl(
        &self,
        crl_number: u32,
        revoked_serials: &[Vec<u8>],
    ) -> Result<Vec<u8>, PkiError> {
        self.intermediate_crl_with_ttl(crl_number, revoked_serials, crate::CRL_VALIDITY_SECS as i64)
    }

    /// CRL for intermediates with an explicit `nextUpdate` offset (see
    /// [`Self::leaf_crl_with_ttl`]).
    pub fn intermediate_crl_with_ttl(
        &self,
        crl_number: u32,
        revoked_serials: &[Vec<u8>],
        ttl_secs: i64,
    ) -> Result<Vec<u8>, PkiError> {
        build_crl(
            &self.root_cert,
            &self.root_key_der,
            crl_number,
            revoked_serials,
            ttl_secs,
        )
    }
}

// KeyPair is not Clone and Issuer borrows it, so we regenerate a KeyPair
// handle from the stored PKCS#8 DER for each issuance call.
fn issue_key(key_der: &[u8]) -> Result<KeyPair, PkiError> {
    KeyPair::try_from(key_der).map_err(|e| PkiError::KeyGeneration(e.to_string()))
}

fn build_crl(
    issuer_cert: &CertificateDer<'_>,
    issuer_key_der: &[u8],
    crl_number: u32,
    revoked_serials: &[Vec<u8>],
    ttl_secs: i64,
) -> Result<Vec<u8>, PkiError> {
    use ed25519_dalek::pkcs8::DecodePrivateKey as _;
    use x509_cert::builder::{Builder as _, CrlBuilder};
    use x509_cert::der::{Decode as _, Encode as _};
    use x509_cert::ext::pkix::CrlNumber;
    use x509_cert::time::Time;

    let issuer = x509_cert::Certificate::from_der(issuer_cert.as_ref())
        .map_err(|e| PkiError::Parsing(e.to_string()))?;
    let signer = crate::adapters::Ed25519Signer(
        ed25519_dalek::SigningKey::from_pkcs8_der(issuer_key_der)
            .map_err(|e| PkiError::KeyGeneration(e.to_string()))?,
    );

    let now = der::asn1::UtcTime::from_system_time(std::time::SystemTime::now())
        .map_err(|e| PkiError::CrlGeneration(e.to_string()))?;
    let next_update = if ttl_secs >= 0 {
        std::time::SystemTime::now() + std::time::Duration::from_secs(ttl_secs as u64)
    } else {
        std::time::SystemTime::now() - std::time::Duration::from_secs(ttl_secs.unsigned_abs())
    };
    let next = der::asn1::UtcTime::from_system_time(next_update)
        .map_err(|e| PkiError::CrlGeneration(e.to_string()))?;

    let revoked: der::Result<Vec<x509_cert::crl::RevokedCert>> = revoked_serials
        .iter()
        .map(|serial| {
            Ok(x509_cert::crl::RevokedCert {
                serial_number: x509_cert::serial_number::SerialNumber::new(serial)?,
                revocation_date: Time::UtcTime(now),
                crl_entry_extensions: None,
            })
        })
        .collect();
    let revoked = revoked.map_err(|e| PkiError::CrlGeneration(e.to_string()))?;

    let crl_number =
        CrlNumber::try_from(crl_number).map_err(|e| PkiError::CrlGeneration(e.to_string()))?;

    let crl = CrlBuilder::new(&issuer, crl_number)
        .map_err(|e| PkiError::CrlGeneration(e.to_string()))?
        .with_next_update(Some(Time::UtcTime(next)))
        .with_certificates(revoked.into_iter())
        .build::<_, crate::adapters::Ed25519Sig>(&signer)
        .map_err(|e| PkiError::CrlGeneration(e.to_string()))?;

    crl.to_der()
        .map_err(|e| PkiError::CrlGeneration(e.to_string()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    #[test]
    fn hierarchy_issues_agent_and_server_certificates() {
        let ca =
            CaHierarchy::generate("Vigile Test Root", "Vigile Test Issuer").expect("hierarchy");
        let agent = ca
            .issue_agent_certificate("agent-0001")
            .expect("agent cert");
        assert!(!agent.serial.is_empty());
        assert!(!agent.private_key_der.is_empty());
        let server = ca
            .issue_server_certificate("vigile-server.lab")
            .expect("server cert");
        assert_eq!(server.chain.len(), 2);
    }
}
