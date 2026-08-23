// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vigile PKI — internal CA hierarchy for agent identity (ISS-011).
//!
//! Validated by prototype `spikes/pki-chain` (report:
//! `docs/spikes/ISS-011-prototype-pki.md`). Design facts to remember:
//! - rustls checks revocation for the WHOLE chain by default, so one CRL
//!   per issuer is required (root -> intermediates, intermediate -> leaves);
//! - unknown revocation status is DENIED by default (fail-closed, ADR-0010);
//!   never call `allow_unknown_revocation_status()`;
//! - `signature` must stay on major version 3 (see rust/DEPENDENCIES.md).

pub mod adapters;
pub mod ca;
pub mod enrollment;
pub mod envelope;
pub mod registry;

pub use ca::{certificate_expiry, should_renew, CaHierarchy, IssuedCertificate};
pub use enrollment::{
    generate_agent_csr, process_enrollment, AgentCsrMaterial, EnrolledAgent, EnrollmentError,
    EnrollmentRequest, EnrollmentTokenClaims, EnrollmentTokenIssuer, EnrollmentTokenVerifier,
    InMemorySingleUseStore, SingleUseStore, VerifiedEnrollment,
};
pub use envelope::{
    EnvelopeError, EnvelopeVerifier, MessageEnvelope, MessageKind, NextRound,
    DEFAULT_MAX_CLOCK_SKEW_SECS, PROTOCOL,
};
pub use registry::{
    AgentRecord, AgentRegistry, AgentStatus, QuarantineReason, RegistryError, SecurityEvent,
    SecurityEventKind,
};

/// Root CA validity — proposal DEC-09 (2–5 years range).
pub const ROOT_CA_VALIDITY_SECS: u64 = 5 * 365 * 24 * 3600;
/// Intermediate CA validity — proposal DEC-09 (1 year).
pub const INTERMEDIATE_CA_VALIDITY_SECS: u64 = 365 * 24 * 3600;
/// Agent certificate validity — proposal DEC-09 (90 days, renewal at T-30d).
pub const AGENT_CERT_VALIDITY_SECS: u64 = 90 * 24 * 3600;
/// CRL validity window — proposal DEC-09 (7 days).
pub const CRL_VALIDITY_SECS: u64 = 7 * 24 * 3600;
/// Certificate renewal threshold (SEC-104) — proposal DEC-09 (T-30 days).
pub const RENEWAL_THRESHOLD_SECS: u64 = 30 * 24 * 3600;
/// Clock-skew tolerance applied to `notBefore` (backdated 5 minutes).
pub const NOT_BEFORE_SKEW_SECS: u64 = 300;

/// Errors raised by the PKI layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PkiError {
    KeyGeneration(String),
    CertificateIssuance(String),
    CrlGeneration(String),
    Parsing(String),
}

impl std::fmt::Display for PkiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PkiError::KeyGeneration(e) => write!(f, "key generation failed: {e}"),
            PkiError::CertificateIssuance(e) => write!(f, "certificate issuance failed: {e}"),
            PkiError::CrlGeneration(e) => write!(f, "CRL generation failed: {e}"),
            PkiError::Parsing(e) => write!(f, "DER parsing failed: {e}"),
        }
    }
}

impl std::error::Error for PkiError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_is_explicit() {
        assert!(PkiError::KeyGeneration("boom".into())
            .to_string()
            .contains("key generation"));
    }
}
