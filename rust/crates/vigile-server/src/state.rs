// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shared server state (ISS-030): the pieces every route handler needs.

use vigile_pki::{
    CaHierarchy, EnrollmentTokenIssuer, EnrollmentTokenVerifier, EnvelopeVerifier,
    InMemorySingleUseStore,
};
use vigile_store::PgStore;

/// Everything the route handlers need, wired together at startup.
pub struct ServerState {
    pub ca: CaHierarchy,
    pub enrollment_issuer: EnrollmentTokenIssuer,
    pub enrollment_verifier: EnrollmentTokenVerifier,
    pub enrollment_store: InMemorySingleUseStore,
    pub envelope_verifier: EnvelopeVerifier,
    /// PostgreSQL-backed agent registry (None = in-memory fallback for
    /// tests without a database).
    pub store: Option<PgStore>,
}

impl ServerState {
    /// Lab/test constructor: fresh PKI + in-memory stores.
    pub fn lab() -> Result<Self, Box<dyn std::error::Error>> {
        let ca = CaHierarchy::generate("Vigile Server Root", "Vigile Server Issuing")?;
        let enrollment_issuer =
            EnrollmentTokenIssuer::generate().map_err(|e| format!("token issuer: {e}"))?;
        let enrollment_verifier =
            EnrollmentTokenVerifier::from_verifying_key(enrollment_issuer.verifying_key());
        let mut envelope_verifier = EnvelopeVerifier::default();

        // The server needs an outstanding nonce per agent; we issue the
        // initial one at enrollment (handled per-request in the route).
        let _ = &mut envelope_verifier;

        Ok(Self {
            ca,
            enrollment_issuer,
            enrollment_verifier,
            enrollment_store: InMemorySingleUseStore::default(),
            envelope_verifier,
            store: None,
        })
    }
}
