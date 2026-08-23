// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shared server state (ISS-030/031/033): the pieces every route
//! handler needs.

use crate::audit::AuditJournal;
use crate::auth::TokenAuth;
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
    /// Admin authentication (bearer tokens per role).
    pub admin_auth: TokenAuth,
    /// Audit journal (append-only, hash-chained).
    pub audit: AuditJournal,
    /// PostgreSQL-backed agent registry (None = in-memory fallback for
    /// tests without a database).
    pub store: Option<PgStore>,
}

impl ServerState {
    /// Lab/test constructor: fresh PKI + in-memory stores + admin tokens.
    pub fn lab() -> Result<Self, Box<dyn std::error::Error>> {
        let ca = CaHierarchy::generate("Vigile Server Root", "Vigile Server Issuing")?;
        let enrollment_issuer =
            EnrollmentTokenIssuer::generate().map_err(|e| format!("token issuer: {e}"))?;
        let enrollment_verifier =
            EnrollmentTokenVerifier::from_verifying_key(enrollment_issuer.verifying_key());
        let envelope_verifier = EnvelopeVerifier::default();

        let (admin_auth, tokens) = crate::auth::TokenAuth::new(&[
            crate::auth::AdminRole::Viewer,
            crate::auth::AdminRole::Admin,
        ])
        .map_err(|e| format!("admin tokens: {e}"))?;

        // Print admin tokens for the operator (lab only — in production
        // these come from configuration/secrets management).
        for t in &tokens {
            eprintln!(
                "vigile-server: admin token ({}): {}",
                match t.role {
                    crate::auth::AdminRole::Viewer => "viewer",
                    crate::auth::AdminRole::Admin => "admin",
                    crate::auth::AdminRole::PlatformAdmin => "platform-admin",
                },
                t.token
            );
        }

        let mut state = Self {
            ca,
            enrollment_issuer,
            enrollment_verifier,
            enrollment_store: InMemorySingleUseStore::default(),
            envelope_verifier,
            admin_auth,
            audit: AuditJournal::new(),
            store: None,
        };

        state
            .audit
            .append("system", "server.started", "server", "ok");
        Ok(state)
    }
}
