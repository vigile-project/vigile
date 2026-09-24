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
    /// Latest compiled policy (rules + manifest) available to agents.
    pub deployed_policy: Option<DeployedPolicy>,
    // Lab deployment-signing seed (ISS-088). Production: isolated signer (TB-5).
    deploy_signing_seed: [u8; 32],
    /// PostgreSQL-backed agent registry (None = in-memory fallback for
    /// tests without a database).
    pub store: Option<PgStore>,
}

/// A compiled policy ready for agent download.
#[derive(Debug, Clone)]
pub struct DeployedPolicy {
    pub policy_id: String,
    pub version: u64,
    pub rules: String,
    pub manifest_json: String,
    /// Ed25519 signature over the exact `rules` bytes (hex). Agents MUST
    /// verify it before staging anything (ISS-088).
    pub rules_signature: String,
    pub deployed_at_unix: i64,
}

impl ServerState {
    /// Ed25519 seed for the lab deployment-signing key. Production moves
    /// signing to the isolated signer service (trust boundary TB-5).
    fn deploy_seed(&self) -> [u8; 32] {
        // Deterministic derivation from the CA would couple the two trust
        // domains; instead the seed is stored alongside the state.
        self.deploy_signing_seed
    }

    /// Public half of the deployment-signing key (hex) — what agents use to
    /// verify served rules.
    pub fn deploy_public_key_hex(&self) -> String {
        let signing = ed25519_dalek::SigningKey::from_bytes(&self.deploy_seed());
        signing.verifying_key().as_bytes().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Signs the exact rules bytes with the deployment key (hex signature).
    pub fn sign_rules(&self, rules: &str) -> Result<String, String> {
        use signature::Signer as _;
        let signing = ed25519_dalek::SigningKey::from_bytes(&self.deploy_seed());
        let signer = vigile_pki::adapters::Ed25519Signer(signing);
        let sig = signer.sign(rules.as_bytes());
        Ok(sig.as_ref().iter().map(|b| format!("{b:02x}")).collect())
    }

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

        let mut deploy_signing_seed = [0u8; 32];
        getrandom::fill(&mut deploy_signing_seed)
            .map_err(|e| format!("RNG (deploy seed): {e}"))?;

        let mut state = Self {
            ca,
            enrollment_issuer,
            enrollment_verifier,
            enrollment_store: InMemorySingleUseStore::default(),
            envelope_verifier,
            admin_auth,
            audit: AuditJournal::new(),
            deployed_policy: None,
            deploy_signing_seed,
            store: None,
        };

        state
            .audit
            .append("system", "server.started", "server", "ok");
        Ok(state)
    }
}
