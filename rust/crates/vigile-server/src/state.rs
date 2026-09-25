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
    /// Where the CA, signing seed and deployed policy persist (ISS-089).
    pub data_dir: std::path::PathBuf,
    /// Enrolled agents (revocation registry, ISS-090-3).
    pub agents: Vec<AgentRecord>,
    /// Bumped on quarantine: the accept loop rebuilds the TLS config
    /// (fresh CRL) when it changes.
    pub tls_generation: u64,
    // Lab deployment-signing seed (ISS-088). Production: isolated signer (TB-5).
    deploy_signing_seed: [u8; 32],
    /// PostgreSQL-backed agent registry (None = in-memory fallback for
    /// tests without a database).
    pub store: Option<PgStore>,
}

/// Enrolled agent tracked for revocation (ISS-090-3).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentRecord {
    pub agent_id: String,
    pub serial_hex: String,
    pub status: String, // "active" | "quarantined"
}

/// A compiled policy ready for agent download.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
    fn load_agents(data_dir: &std::path::Path) -> Vec<AgentRecord> {
        std::fs::read_to_string(data_dir.join("agents.json"))
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default()
    }

    fn save_agents(&self) {
        let path = self.data_dir.join("agents.json");
        let tmp = self.data_dir.join("agents.json.tmp");
        if let Ok(json) = serde_json::to_string_pretty(&self.agents) {
            if std::fs::write(&tmp, json).is_ok() {
                let _ = std::fs::rename(&tmp, path);
            }
        }
    }

    /// Records a newly enrolled agent.
    pub fn register_agent(&mut self, agent_id: &str, serial: &[u8]) {
        let serial_hex: String = serial.iter().map(|b| format!("{b:02x}")).collect();
        self.agents.retain(|a| a.agent_id != agent_id);
        self.agents.push(AgentRecord {
            agent_id: agent_id.to_string(),
            serial_hex,
            status: "active".to_string(),
        });
        self.save_agents();
    }

    /// Quarantines an agent: its serial enters the next CRL.
    pub fn quarantine_agent(&mut self, agent_id: &str) -> Result<(), String> {
        let Some(record) = self.agents.iter_mut().find(|a| a.agent_id == agent_id) else {
            return Err(format!("unknown agent: {agent_id}"));
        };
        record.status = "quarantined".to_string();
        self.save_agents();
        self.tls_generation += 1;
        Ok(())
    }

    /// Serials of quarantined agents, for the leaf CRL.
    pub fn revoked_serials(&self) -> Vec<Vec<u8>> {
        self.agents
            .iter()
            .filter(|a| a.status == "quarantined")
            .filter_map(|a| {
                (0..a.serial_hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(a.serial_hex.get(i..i + 2)?, 16).ok())
                    .collect::<Option<Vec<u8>>>()
            })
            .collect()
    }

    /// Reads a persisted deployed policy (if any) so a restart keeps
    /// serving the last compiled rules and their signature.
    fn load_deployed_policy(data_dir: &std::path::Path) -> Option<DeployedPolicy> {
        let raw = std::fs::read_to_string(data_dir.join("deployed-policy.json")).ok()?;
        match serde_json::from_str(&raw) {
            Ok(p) => {
                eprintln!("vigile-server: deployed policy restored from disk");
                Some(p)
            }
            Err(e) => {
                eprintln!("vigile-server: WARNING corrupted deployed-policy.json ({e})");
                None
            }
        }
    }

    /// Persists the current deployed policy atomically (tmp + rename).
    pub fn save_deployed_policy(&self) -> Result<(), String> {
        let Some(p) = &self.deployed_policy else { return Ok(()) };
        let tmp = self.data_dir.join("deployed-policy.json.tmp");
        let json = serde_json::to_string_pretty(p).map_err(|e| e.to_string())?;
        std::fs::write(&tmp, json).map_err(|e| format!("write policy: {e}"))?;
        std::fs::rename(&tmp, self.data_dir.join("deployed-policy.json"))
            .map_err(|e| format!("commit policy: {e}"))
    }

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
        let data_dir = std::env::var_os("VIGILE_DATA_DIR")
            .map(std::path::PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| {
                let mut d = std::path::PathBuf::from(h);
                d.push(".local/share/vigile");
                d
            }))
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp/vigile-data"));
        std::fs::create_dir_all(&data_dir)
            .map_err(|e| format!("data dir {}: {e}", data_dir.display()))?;

        // Persistent hierarchy: reload if present, generate once otherwise.
        let ca = match CaHierarchy::load_from_dir(&data_dir)? {
            Some(loaded) => {
                eprintln!("vigile-server: PKI loaded from {}", data_dir.display());
                loaded
            }
            None => {
                let fresh = CaHierarchy::generate("Vigile Server Root", "Vigile Server Issuing")?;
                fresh.save_to_dir(&data_dir)?;
                eprintln!("vigile-server: new PKI generated in {}", data_dir.display());
                fresh
            }
        };
        let enrollment_issuer =
            EnrollmentTokenIssuer::generate().map_err(|e| format!("token issuer: {e}"))?;
        let enrollment_verifier =
            EnrollmentTokenVerifier::from_verifying_key(enrollment_issuer.verifying_key());
        let envelope_verifier = EnvelopeVerifier::default();

        // ISS-090-1: admin tokens come from an operator-managed file when
        // present (production path); generated+printed otherwise (lab).
        let (admin_auth, tokens, tokens_from_file) = {
            let path = data_dir.join("admin-tokens.json");
            match std::fs::read_to_string(&path) {
                Ok(raw) => {
                    let parsed: Vec<(String, String)> = serde_json::from_str(&raw)
                        .map_err(|e| format!("admin-tokens.json: {e}"))?;
                    let pairs: Vec<(String, crate::auth::AdminRole)> = parsed
                        .iter()
                        .filter_map(|(t, r)| {
                            let role = match r.as_str() {
                                "viewer" => Some(crate::auth::AdminRole::Viewer),
                                "admin" => Some(crate::auth::AdminRole::Admin),
                                "platform-admin" => Some(crate::auth::AdminRole::PlatformAdmin),
                                _ => None,
                            };
                            role.map(|role| (t.clone(), role))
                        })
                        .collect();
                    if pairs.len() != parsed.len() {
                        return Err("admin-tokens.json: unknown role (expected viewer|admin|platform-admin)"
                            .into());
                    }
                    (
                        crate::auth::TokenAuth::from_pairs(&pairs),
                        Vec::new(),
                        true,
                    )
                }
                Err(_) => {
                    let (auth, toks) = crate::auth::TokenAuth::new(&[
                        crate::auth::AdminRole::Viewer,
                        crate::auth::AdminRole::Admin,
                    ])
                    .map_err(|e| format!("admin tokens: {e}"))?;
                    (auth, toks, false)
                }
            }
        };

        if tokens_from_file {
            eprintln!("vigile-server: admin tokens loaded from admin-tokens.json (not printed)");
        }
        // Print admin tokens for the operator (lab only). Only the SHA-256
        // hashes are retained in memory (ISS-089).
        let roles = [
            crate::auth::AdminRole::Viewer,
            crate::auth::AdminRole::Admin,
        ];
        for (t, role) in tokens.iter().zip(roles.iter()) {
            eprintln!(
                "vigile-server: admin token ({}): {}",
                match role {
                    crate::auth::AdminRole::Viewer => "viewer",
                    crate::auth::AdminRole::Admin => "admin",
                    crate::auth::AdminRole::PlatformAdmin => "platform-admin",
                },
                t
            );
        }

        let seed_path = data_dir.join("deploy-seed.bin");
        let deploy_signing_seed: [u8; 32] = match std::fs::read(&seed_path) {
            Ok(bytes) => <[u8; 32]>::try_from(bytes.as_slice())
                .map_err(|e| format!("deploy seed size: {e}"))?,
            Err(_) => {
                use std::os::unix::fs::PermissionsExt;
                let mut seed = [0u8; 32];
                getrandom::fill(&mut seed)
                    .map_err(|e| format!("RNG (deploy seed): {e}"))?;
                std::fs::write(&seed_path, seed)
                    .and_then(|_| {
                        std::fs::set_permissions(
                            &seed_path,
                            std::fs::Permissions::from_mode(0o600),
                        )
                    })
                    .map_err(|e| format!("persist deploy seed: {e}"))?;
                seed
            }
        };

        let mut state = Self {
            ca,
            enrollment_issuer,
            enrollment_verifier,
            enrollment_store: InMemorySingleUseStore::default(),
            envelope_verifier,
            admin_auth,
            audit: AuditJournal::new(),
            deployed_policy: Self::load_deployed_policy(&data_dir),
            agents: Self::load_agents(&data_dir),
            tls_generation: 0,
            data_dir,
            deploy_signing_seed,
            store: None,
        };

        state
            .audit
            .append("system", "server.started", "server", "ok");
        Ok(state)
    }
}
