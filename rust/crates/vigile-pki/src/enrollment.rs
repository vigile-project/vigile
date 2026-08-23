// SPDX-License-Identifier: AGPL-3.0-or-later
//! Enrollment protocol (ISS-012): single-use signed tokens, agent CSRs,
//! and the full enrollment decision with negative-test guarantees.
//!
//! Token format: `HEX(payload_json) . HEX(ed25519_signature)`.
//! The payload is the `serde_json` serialization of [`EnrollmentTokenClaims`]
//! — a fixed struct with no maps and no floats, so serialization is
//! byte-deterministic (same signing mechanics rationale as ADR-0004).
//! The token is a bearer credential presented BY the agent TO the server:
//! only the server verifies it, so no public key distribution is needed.
//!
//! Verification order (each failure is a distinct error): parse →
//! signature → type → tenant → validity window → single-use consumption
//! (last, so a failed check never burns a legitimate token).

use crate::ca::CaHierarchy;
use crate::{IssuedCertificate, PkiError};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

/// Default enrollment token lifetime — proposal DEC-09 (≤ 24 h).
pub const ENROLLMENT_TOKEN_TTL_SECS: u64 = 24 * 3600;
/// Maximum accepted machine fingerprint size.
pub const MAX_FINGERPRINT_BYTES: usize = 512;
/// Random bytes in a token id (32 hex chars).
const JTI_BYTES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentError {
    Malformed(String),
    BadSignature,
    WrongType,
    WrongTenant,
    NotYetValid,
    Expired,
    AlreadyUsed,
    Store(String),
    InvalidFingerprint,
    Csr(String),
    Issuance(String),
}

impl std::fmt::Display for EnrollmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrollmentError::Malformed(e) => write!(f, "malformed enrollment token: {e}"),
            EnrollmentError::BadSignature => write!(f, "enrollment token signature invalid"),
            EnrollmentError::WrongType => write!(f, "enrollment token type mismatch"),
            EnrollmentError::WrongTenant => write!(f, "enrollment token targets another tenant"),
            EnrollmentError::NotYetValid => write!(f, "enrollment token not yet valid"),
            EnrollmentError::Expired => write!(f, "enrollment token expired"),
            EnrollmentError::AlreadyUsed => write!(f, "enrollment token already used"),
            EnrollmentError::Store(e) => write!(f, "single-use store failure: {e}"),
            EnrollmentError::InvalidFingerprint => write!(f, "machine fingerprint invalid"),
            EnrollmentError::Csr(e) => write!(f, "invalid CSR: {e}"),
            EnrollmentError::Issuance(e) => write!(f, "certificate issuance failed: {e}"),
        }
    }
}

impl std::error::Error for EnrollmentError {}

impl From<PkiError> for EnrollmentError {
    fn from(e: PkiError) -> Self {
        EnrollmentError::Issuance(e.to_string())
    }
}

/// Token claims. Field order is fixed by the struct — serialization is
/// deterministic and covered by the signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentTokenClaims {
    pub typ: String,
    pub jti: String,
    pub tenant: String,
    pub group: Option<String>,
    pub not_before: i64,
    pub expires_at: i64,
}

impl EnrollmentTokenClaims {
    pub const TYPE: &'static str = "vigile-enroll/v1";
}

fn unix_secs(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// Issues single-use enrollment tokens (server side).
pub struct EnrollmentTokenIssuer {
    signing_key: SigningKey,
}

impl EnrollmentTokenIssuer {
    pub fn generate() -> Result<Self, EnrollmentError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed)
            .map_err(|e| EnrollmentError::Malformed(format!("RNG unavailable: {e}")))?;
        Ok(Self {
            signing_key: SigningKey::from_bytes(&seed),
        })
    }

    pub fn from_signing_key(key: SigningKey) -> Self {
        Self { signing_key: key }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Issues a token for the given tenant, valid `[now, now + ttl]`.
    pub fn issue(
        &self,
        tenant: &str,
        group: Option<String>,
        ttl_secs: u64,
        now: SystemTime,
    ) -> Result<String, EnrollmentError> {
        let mut jti_bytes = [0u8; JTI_BYTES];
        getrandom::fill(&mut jti_bytes)
            .map_err(|e| EnrollmentError::Malformed(format!("RNG unavailable: {e}")))?;
        let claims = EnrollmentTokenClaims {
            typ: EnrollmentTokenClaims::TYPE.to_string(),
            jti: hex_encode(&jti_bytes),
            tenant: tenant.to_string(),
            group,
            not_before: unix_secs(now),
            expires_at: unix_secs(now) + ttl_secs as i64,
        };
        self.issue_with_claims(&claims)
    }

    /// Signs arbitrary claims (used by `issue` and by tests exercising
    /// malformed/hostile claims).
    pub fn issue_with_claims(
        &self,
        claims: &EnrollmentTokenClaims,
    ) -> Result<String, EnrollmentError> {
        let payload = serde_json::to_vec(claims)
            .map_err(|e| EnrollmentError::Malformed(format!("claims not serializable: {e}")))?;
        Ok(self.sign_raw(&payload))
    }

    /// Low-level: signs an already-encoded payload. Used by `issue` and by
    /// tests that craft hostile payloads signed with the genuine key.
    pub fn sign_raw(&self, payload: &[u8]) -> String {
        let signature = self.signing_key.sign(payload);
        format!(
            "{}.{}",
            hex_encode(payload),
            hex_encode(&signature.to_bytes())
        )
    }
}

/// Atomically-recorded single-use consumption of token ids.
/// The production implementation sits on PostgreSQL (ISS-016).
pub trait SingleUseStore {
    /// `Ok(true)` if `jti` was newly consumed, `Ok(false)` if already used,
    /// `Err` on storage failure.
    fn try_consume(&mut self, jti: &str) -> Result<bool, String>;
}

#[derive(Default)]
pub struct InMemorySingleUseStore {
    used: HashSet<String>,
}

impl SingleUseStore for InMemorySingleUseStore {
    fn try_consume(&mut self, jti: &str) -> Result<bool, String> {
        Ok(self.used.insert(jti.to_string()))
    }
}

/// Verifies enrollment tokens (server side) against the issuer public key.
pub struct EnrollmentTokenVerifier {
    verifying_key: VerifyingKey,
}

impl EnrollmentTokenVerifier {
    pub fn from_verifying_key(key: VerifyingKey) -> Self {
        Self { verifying_key: key }
    }

    pub fn verify(
        &self,
        token: &str,
        now: SystemTime,
        expected_tenant: &str,
        store: &mut dyn SingleUseStore,
    ) -> Result<EnrollmentTokenClaims, EnrollmentError> {
        let (payload_hex, sig_hex) = token
            .split_once('.')
            .ok_or_else(|| EnrollmentError::Malformed("expected payload.signature".into()))?;
        let payload = hex_decode(payload_hex)
            .ok_or_else(|| EnrollmentError::Malformed("payload not hex".into()))?;
        let sig_bytes = hex_decode(sig_hex)
            .ok_or_else(|| EnrollmentError::Malformed("signature not hex".into()))?;
        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|_| EnrollmentError::Malformed("signature not 64 bytes".into()))?;

        // Signature BEFORE any content interpretation.
        self.verifying_key
            .verify(&payload, &signature)
            .map_err(|_| EnrollmentError::BadSignature)?;

        let claims: EnrollmentTokenClaims = serde_json::from_slice(&payload)
            .map_err(|e| EnrollmentError::Malformed(format!("claims not valid JSON: {e}")))?;

        if claims.typ != EnrollmentTokenClaims::TYPE {
            return Err(EnrollmentError::WrongType);
        }
        if claims.tenant != expected_tenant {
            return Err(EnrollmentError::WrongTenant);
        }
        let now = unix_secs(now);
        if now < claims.not_before {
            return Err(EnrollmentError::NotYetValid);
        }
        if now > claims.expires_at {
            return Err(EnrollmentError::Expired);
        }
        // Single-use consumption LAST: a failed check never burns a token.
        if !store
            .try_consume(&claims.jti)
            .map_err(EnrollmentError::Store)?
        {
            return Err(EnrollmentError::AlreadyUsed);
        }
        Ok(claims)
    }
}

/// A successful verification, ready for issuance.
#[derive(Debug)]
pub struct VerifiedEnrollment {
    pub claims: EnrollmentTokenClaims,
}

/// Agent-side enrollment material: a fresh key pair and its PKCS#10 CSR.
#[derive(Debug)]
pub struct AgentCsrMaterial {
    pub key_pair: rcgen::KeyPair,
    pub csr_der: Vec<u8>,
}

/// Generates a fresh agent key pair and CSR. The CN is a placeholder:
/// the server assigns the definitive agent id at issuance.
pub fn generate_agent_csr() -> Result<AgentCsrMaterial, PkiError> {
    let key = crate::ca::ed25519_key()?;
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "enroll-pending");
    let request = params
        .serialize_request(&key)
        .map_err(|e| PkiError::CertificateIssuance(e.to_string()))?;
    Ok(AgentCsrMaterial {
        key_pair: key,
        csr_der: request.der().to_vec(),
    })
}

fn verify_csr_pop(csr_der: &[u8]) -> Result<(), EnrollmentError> {
    use der::Decode as _;
    let csr = x509_cert::request::CertReq::from_der(csr_der)
        .map_err(|e| EnrollmentError::Csr(e.to_string()))?;

    // Algorithm must be Ed25519 (RFC 8410), parameters absent.
    if csr.algorithm.oid.to_string() != crate::adapters::ID_ED25519
        || csr.algorithm.parameters.is_some()
    {
        return Err(EnrollmentError::Csr("unsupported CSR algorithm".into()));
    }

    // Proof of possession: signature over CertificationRequestInfo DER.
    use der::Encode as _;
    let info_der = csr
        .info
        .to_der()
        .map_err(|e| EnrollmentError::Csr(format!("cannot re-encode CSR info: {e}")))?;
    let key_bytes: [u8; 32] = csr
        .info
        .public_key
        .subject_public_key
        .as_bytes()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| EnrollmentError::Csr("subject public key is not 32 bytes".into()))?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| EnrollmentError::Csr(format!("bad public key: {e}")))?;
    let signature =
        Signature::from_slice(csr.signature.as_bytes().ok_or_else(|| {
            EnrollmentError::Csr("CSR signature is not a whole byte string".into())
        })?)
        .map_err(|_| EnrollmentError::Csr("CSR signature is not 64 bytes".into()))?;
    verifying_key
        .verify(&info_der, &signature)
        .map_err(|_| EnrollmentError::Csr("CSR proof-of-possession invalid".into()))?;
    Ok(())
}

/// What an agent submits to enroll.
pub struct EnrollmentRequest {
    pub token: String,
    pub csr_der: Vec<u8>,
    pub machine_fingerprint: String,
}

/// The result of a successful enrollment.
#[derive(Debug)]
pub struct EnrolledAgent {
    pub agent_id: String,
    pub certificate: IssuedCertificate,
    pub machine_fingerprint: String,
    pub jti: String,
}

/// Full enrollment decision (server side): verify token → verify CSR
/// proof-of-possession → issue the agent certificate. The agent id is
/// derived from the token id, so one token can only ever produce one id.
pub fn process_enrollment(
    ca: &CaHierarchy,
    verifier: &EnrollmentTokenVerifier,
    store: &mut dyn SingleUseStore,
    request: &EnrollmentRequest,
    now: SystemTime,
    expected_tenant: &str,
) -> Result<EnrolledAgent, EnrollmentError> {
    if request.machine_fingerprint.trim().is_empty()
        || request.machine_fingerprint.len() > MAX_FINGERPRINT_BYTES
    {
        return Err(EnrollmentError::InvalidFingerprint);
    }

    let claims = verifier.verify(&request.token, now, expected_tenant, store)?;

    // Proof of possession verified; the CA re-parses the SPKI at issuance.
    verify_csr_pop(&request.csr_der)?;

    let agent_id = format!("agent-{}", claims.jti);
    let certificate = ca
        .issue_agent_certificate_from_csr(&request.csr_der, &agent_id)
        .map_err(|e| EnrollmentError::Issuance(e.to_string()))?;

    Ok(EnrolledAgent {
        jti: claims.jti.clone(),
        agent_id,
        certificate,
        machine_fingerprint: request.machine_fingerprint.clone(),
    })
}
