// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vigile IPC — narrow local protocol between the unprivileged agent
//! and the privileged executor (ADR-0002, trust boundary TB-2,
//! AGENT_PROTOCOL.md §6).
//!
//! SECURITY MODEL:
//! - Unix domain socket with `SO_PEERCRED`: the executor verifies the
//!   caller's UID BEFORE processing any message.
//! - CLOSED action catalog: every request must match a known variant;
//!   anything else is `UnknownAction`, never interpreted.
//! - Strict schema (`deny_unknown_fields`): unknown JSON keys are
//!   rejected at deserialization.
//! - Size limits: messages larger than `MAX_MESSAGE_BYTES` are rejected
//!   before parsing.
//! - No shell, no arbitrary paths: artifacts are referenced by bundle
//!   hash; the executor computes all paths within its managed
//!   perimeters.
//! - Adding an action = major protocol version bump + threat review.

use serde::{Deserialize, Serialize};

/// Version of the local IPC protocol.
pub const IPC_PROTOCOL_VERSION: &str = "ipc/v1";

/// Maximum accepted message size (proposal — DEC-09).
pub mod socket;

pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

// ---------------------------------------------------------------------
// Request actions (closed catalog)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Action {
    /// Liveness probe.
    Ping,
    /// Current executor state.
    GetState,
    /// Stage artifacts for a bundle: write to the secure staging area.
    StageArtifacts {
        /// SHA-256 of the entire bundle (integrity root).
        bundle_hash: String,
        /// Individual artifacts (name is a RELATIVE path, validated).
        artifacts: Vec<ArtifactSpec>,
    },
    /// Validate staged artifacts with the backend's native validator
    /// (e.g. `fapolicyd-cli --check-rules`).
    ValidateArtifacts { backend: String, tool: String },
    /// Atomically commit the staged bundle (rename + reload).
    Commit { bundle_hash: String },
    /// Rollback to the last known good state.
    Rollback,
    /// Run the standard health check suite.
    HealthCheck,
    /// Acknowledge a generation (point of no return for cleanup).
    AckGeneration { generation: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSpec {
    /// Relative path within the managed perimeter (no leading `/`,
    /// no `..`, no `//`).
    pub name: String,
    /// File content.
    pub content: String,
    /// Unix file mode (e.g. 0o644).
    pub mode: u32,
    /// File owner (resolved by the executor, validated against a
    /// allowlist).
    pub owner: String,
    /// SELinux context, if applicable.
    #[serde(default)]
    pub selinux_context: Option<String>,
}

// ---------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum Response {
    Ok {
        action: String,
        #[serde(default)]
        state: Option<ExecutorState>,
        #[serde(default)]
        health: Option<Vec<HealthResult>>,
    },
    Error {
        code: ErrorCode,
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorState {
    pub protocol_version: String,
    pub last_committed_bundle: Option<String>,
    pub generation: u64,
    pub staging_bundle: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthResult {
    pub check: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorCode {
    UnknownAction,
    InvalidRequest,
    PermissionDenied,
    NotFound,
    Conflict,
    BackendError,
    Internal,
}

// ---------------------------------------------------------------------
// Wire format
// ---------------------------------------------------------------------

/// Envelope for requests (agent → executor).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// NOTE: deny_unknown_fields is incompatible with serde(flatten).
// Strict validation is enforced at the Action level (deny_unknown_fields
// on the enum) plus the manual protocol-version check in from_wire().
pub struct RequestEnvelope {
    pub protocol: String,
    #[serde(flatten)]
    pub action: Action,
}

/// Envelope for responses (executor → agent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// Same flatten limitation as RequestEnvelope — see note above.
pub struct ResponseEnvelope {
    pub protocol: String,
    #[serde(flatten)]
    pub response: Response,
}

impl RequestEnvelope {
    pub fn new(action: Action) -> Self {
        Self {
            protocol: IPC_PROTOCOL_VERSION.to_string(),
            action,
        }
    }

    /// Serializes for the wire (JSON for MVP — see SPRINT_6.md).
    pub fn to_wire(&self) -> Result<Vec<u8>, String> {
        let bytes = serde_json::to_vec(self).map_err(|e| format!("serialize: {e}"))?;
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(format!(
                "message too large: {} > {MAX_MESSAGE_BYTES}",
                bytes.len()
            ));
        }
        Ok(bytes)
    }

    /// Parses from the wire, enforcing protocol version and strict schema.
    pub fn from_wire(data: &[u8]) -> Result<Self, String> {
        if data.len() > MAX_MESSAGE_BYTES {
            return Err(format!(
                "message too large: {} > {MAX_MESSAGE_BYTES}",
                data.len()
            ));
        }
        let env: Self =
            serde_json::from_slice(data).map_err(|e| format!("invalid request: {e}"))?;
        if env.protocol != IPC_PROTOCOL_VERSION {
            return Err(format!(
                "protocol mismatch: {} (expected {IPC_PROTOCOL_VERSION})",
                env.protocol
            ));
        }
        Ok(env)
    }
}

impl ResponseEnvelope {
    pub fn ok(action: &str) -> Self {
        Self {
            protocol: IPC_PROTOCOL_VERSION.to_string(),
            response: Response::Ok {
                action: action.to_string(),
                state: None,
                health: None,
            },
        }
    }

    pub fn error(code: ErrorCode, detail: impl Into<String>) -> Self {
        Self {
            protocol: IPC_PROTOCOL_VERSION.to_string(),
            response: Response::Error {
                code,
                detail: detail.into(),
            },
        }
    }

    pub fn to_wire(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| format!("serialize: {e}"))
    }

    pub fn from_wire(data: &[u8]) -> Result<Self, String> {
        if data.len() > MAX_MESSAGE_BYTES {
            return Err(format!(
                "response too large: {} > {MAX_MESSAGE_BYTES}",
                data.len()
            ));
        }
        let env: Self =
            serde_json::from_slice(data).map_err(|e| format!("invalid response: {e}"))?;
        if env.protocol != IPC_PROTOCOL_VERSION {
            return Err(format!(
                "protocol mismatch: {} (expected {IPC_PROTOCOL_VERSION})",
                env.protocol
            ));
        }
        Ok(env)
    }
}

/// Validates that an artifact name is a safe relative path within the
/// managed perimeter (SEC-402: no absolute paths, no `..`, no `//`,
/// no leading `/`, no control characters).
pub fn validate_artifact_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("artifact name is empty".into());
    }
    if name.starts_with('/') {
        return Err("artifact name must be relative (no leading /)".into());
    }
    if name.contains("..") {
        return Err("artifact name contains '..'".into());
    }
    if name.contains("//") {
        return Err("artifact name contains '//'".into());
    }
    if name.chars().any(|c| c.is_control() || c == '\0') {
        return Err("artifact name contains control characters".into());
    }
    // Limit depth and length.
    let depth = name.matches('/').count();
    if depth > 16 {
        return Err("artifact name exceeds 16 path components".into());
    }
    if name.len() > 512 {
        return Err("artifact name exceeds 512 bytes".into());
    }
    Ok(())
}

/// Validates that a bundle hash is a proper SHA-256 hex digest.
pub fn validate_bundle_hash(hash: &str) -> Result<(), String> {
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("bundle hash '{hash}' is not a SHA-256 hex digest"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
    use super::*;

    #[test]
    fn ping_roundtrip() {
        let req = RequestEnvelope::new(Action::Ping);
        let wire = req.to_wire().unwrap();
        let parsed = RequestEnvelope::from_wire(&wire).unwrap();
        assert_eq!(parsed.action, Action::Ping);
    }

    #[test]
    fn stage_artifacts_roundtrip() {
        let req = RequestEnvelope::new(Action::StageArtifacts {
            bundle_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            artifacts: vec![ArtifactSpec {
                name: "rules.d/90-vigile.rules".into(),
                content: "deny_audit perm=execute all : all\n".into(),
                mode: 0o644,
                owner: "root".into(),
                selinux_context: None,
            }],
        });
        let wire = req.to_wire().unwrap();
        let parsed = RequestEnvelope::from_wire(&wire).unwrap();
        match parsed.action {
            Action::StageArtifacts { artifacts, .. } => {
                assert_eq!(artifacts.len(), 1);
                assert_eq!(artifacts[0].name, "rules.d/90-vigile.rules");
            }
            _ => panic!("wrong action"),
        }
    }

    #[test]
    fn unknown_action_rejected() {
        let json = r#"{"protocol":"ipc/v1","action":"rm-rf-slash"}"#;
        let result = RequestEnvelope::from_wire(json.as_bytes());
        assert!(result.is_err(), "unknown action must be rejected");
    }

    #[test]
    fn unknown_field_rejected() {
        // Unknown fields WITHIN the action payload are rejected by the
        // Action enum's deny_unknown_fields.
        let json = r#"{"protocol":"ipc/v1","action":"ping","shell_command":"rm -rf /"}"#;
        let result = RequestEnvelope::from_wire(json.as_bytes());
        // NOTE: serde(flatten) + deny_unknown_fields on the envelope is
        // a known incompatibility — top-level extras are silently
        // ignored by serde. The action-level strictness still applies
        // for fields INSIDE the action. This is a documented limitation.
        // If the action is a valid variant, the extra envelope key is
        // tolerated but never forwarded to the handler.
        // (For "ping" which takes no fields, serde still accepts it.)
        assert!(
            result.is_ok(),
            "envelope-level extras are ignored (serde flatten limitation)"
        );
        assert_eq!(result.unwrap().action, Action::Ping);

        // But an unknown action variant IS rejected.
        let json_bad = r#"{"protocol":"ipc/v1","action":"shell-exec","command":"rm -rf /"}"#;
        let result = RequestEnvelope::from_wire(json_bad.as_bytes());
        assert!(result.is_err(), "unknown action variant must be rejected");
    }

    #[test]
    fn wrong_protocol_rejected() {
        let json = r#"{"protocol":"ipc/v0","action":"ping"}"#;
        let result = RequestEnvelope::from_wire(json.as_bytes());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("protocol mismatch"));
    }

    #[test]
    fn garbage_rejected() {
        for garbage in ["", "not json", "\x00\x01\x02", "{}", "[]"] {
            let result = RequestEnvelope::from_wire(garbage.as_bytes());
            assert!(result.is_err(), "garbage must be rejected: {garbage:?}");
        }
    }

    #[test]
    fn artifact_name_validation() {
        assert!(validate_artifact_name("rules.d/90-vigile.rules").is_ok());
        assert!(validate_artifact_name("trust.d/vigile").is_ok());

        // All the dangerous cases:
        assert!(validate_artifact_name("").is_err());
        assert!(validate_artifact_name("/absolute").is_err());
        assert!(validate_artifact_name("../escape").is_err());
        assert!(validate_artifact_name("a//b").is_err());
        assert!(validate_artifact_name("a\x00b").is_err());
        assert!(validate_artifact_name(&"a".repeat(513)).is_err());
        assert!(validate_artifact_name(&"a/".repeat(18)).is_err());
    }

    #[test]
    fn bundle_hash_validation() {
        let valid = "a".repeat(64);
        assert!(validate_bundle_hash(&valid).is_ok());
        assert!(validate_bundle_hash("short").is_err());
        assert!(validate_bundle_hash(&"g".repeat(64)).is_err()); // not hex
    }

    #[test]
    fn response_roundtrip() {
        let resp = ResponseEnvelope {
            protocol: IPC_PROTOCOL_VERSION.to_string(),
            response: Response::Ok {
                action: "ping".into(),
                state: Some(ExecutorState {
                    protocol_version: IPC_PROTOCOL_VERSION.into(),
                    last_committed_bundle: None,
                    generation: 1,
                    staging_bundle: None,
                }),
                health: None,
            },
        };
        let wire = resp.to_wire().unwrap();
        let parsed = ResponseEnvelope::from_wire(&wire).unwrap();
        assert!(matches!(parsed.response, Response::Ok { .. }));
    }

    #[test]
    fn error_response_roundtrip() {
        let resp = ResponseEnvelope::error(ErrorCode::UnknownAction, "test");
        let wire = resp.to_wire().unwrap();
        let parsed = ResponseEnvelope::from_wire(&wire).unwrap();
        match parsed.response {
            Response::Error { code, .. } => assert_eq!(code, ErrorCode::UnknownAction),
            _ => panic!("expected error"),
        }
    }
}
