// SPDX-License-Identifier: AGPL-3.0-or-later
//! Approval workflow (ISS-044, SEC-303): requests from blocked
//! applications, bounded decisions from approvers, and LOCAL expiration
//! (works without the server — the policy envelope carries the expiry).

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// What a user asks when an application is blocked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequest {
    pub id: String,
    pub agent_id: String,
    /// SHA-256 of the blocked executable.
    pub executable_hash: String,
    /// Path of the blocked executable.
    pub path: String,
    /// Human-readable reason (mandatory, SEC-304).
    pub reason: String,
    /// Unix seconds.
    pub created_at: i64,
}

/// The scope of an approval decision — what exactly is being allowed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ApprovalScope {
    /// Allow this exact hash once (single execution).
    OneTime { hash: String },
    /// Allow this hash for a duration (seconds from decision).
    Duration { hash: String, duration_secs: u64 },
    /// Allow this hash on this specific machine (until revoked).
    Machine { hash: String, agent_id: String },
    /// Allow any binary signed by this signer.
    Signer { signer_key_id: String },
}

/// A decision made by a human approver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalDecision {
    pub request_id: String,
    /// The scope (what is being approved).
    pub scope: ApprovalScope,
    /// Who approved (admin token id).
    pub approver: String,
    /// Unix seconds.
    pub decided_at: i64,
    /// Unix seconds when this decision expires (None = permanent,
    /// only valid for Signer scope — OneTime/Duration/Machine MUST
    /// have an expiry, POLICY_MODEL §3.3).
    pub expires_at: Option<i64>,
}

/// The outcome of checking whether a decision is still valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalStatus {
    /// The decision is active and covers this hash.
    Active,
    /// The decision has expired (SEC-303: works without the server).
    Expired { expired_at: i64 },
    /// The decision covers a different hash/scope.
    NotApplicable,
}

impl ApprovalDecision {
    /// Checks whether this decision covers the given hash at the given
    /// time. This is the LOCAL check — it works even if the server is
    /// unreachable (the policy envelope carries the decision).
    pub fn check(&self, executable_hash: &str, now: SystemTime) -> ApprovalStatus {
        // Check expiry first (SEC-303: exceptions MUST expire even if
        // the server is down — the expiry is embedded in the signed
        // policy envelope, verified locally).
        if let Some(expires_at) = self.expires_at {
            let now_secs = now
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            if now_secs > expires_at {
                return ApprovalStatus::Expired {
                    expired_at: expires_at,
                };
            }
        }

        // Check scope.
        match &self.scope {
            ApprovalScope::OneTime { hash } | ApprovalScope::Duration { hash, .. } => {
                if hash == executable_hash {
                    ApprovalStatus::Active
                } else {
                    ApprovalStatus::NotApplicable
                }
            }
            ApprovalScope::Machine { hash, .. } => {
                if hash == executable_hash {
                    ApprovalStatus::Active
                } else {
                    ApprovalStatus::NotApplicable
                }
            }
            ApprovalScope::Signer { .. } => {
                // Signer scope requires checking the binary's signature,
                // which is done by the agent (not this local check).
                // For now, we can't verify it here — the agent falls
                // back to the hash check.
                ApprovalStatus::NotApplicable
            }
        }
    }

    /// Validates that the decision is well-formed (SEC-304: mandatory
    /// justification, bounded scope).
    pub fn validate(&self) -> Result<(), String> {
        // Signer scope can be permanent; all others MUST expire.
        if !matches!(self.scope, ApprovalScope::Signer { .. }) && self.expires_at.is_none() {
            return Err("non-signer approvals MUST have an expiry (POLICY_MODEL §3.3)".into());
        }
        if self.approver.is_empty() {
            return Err("approver is empty (SEC-304)".into());
        }
        if self.request_id.is_empty() {
            return Err("request_id is empty".into());
        }
        // Hash format check for hash-based scopes.
        match &self.scope {
            ApprovalScope::OneTime { hash }
            | ApprovalScope::Duration { hash, .. }
            | ApprovalScope::Machine { hash, .. } => {
                if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(format!("invalid hash in scope: {hash}"));
                }
            }
            ApprovalScope::Signer { signer_key_id } => {
                if signer_key_id.is_empty() {
                    return Err("signer_key_id is empty".into());
                }
            }
        }
        Ok(())
    }
}

/// Validates a request (before creating it).
pub fn validate_request(request: &ApprovalRequest) -> Result<(), String> {
    if request.id.is_empty() {
        return Err("id is empty".into());
    }
    if request.agent_id.is_empty() {
        return Err("agent_id is empty".into());
    }
    if request.executable_hash.len() != 64
        || !request
            .executable_hash
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
    {
        return Err("executable_hash is not a SHA-256 hex digest".into());
    }
    if request.path.is_empty() {
        return Err("path is empty".into());
    }
    if request.reason.trim().is_empty() {
        return Err("reason is empty (SEC-304: justification mandatory)".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn request() -> ApprovalRequest {
        ApprovalRequest {
            id: "req-001".into(),
            agent_id: "agent-001".into(),
            executable_hash: HASH.into(),
            path: "/usr/local/bin/tool".into(),
            reason: "needed for work".into(),
            created_at: 1000,
        }
    }

    fn decision(scope: ApprovalScope, expires_at: Option<i64>) -> ApprovalDecision {
        ApprovalDecision {
            request_id: "req-001".into(),
            scope,
            approver: "admin:token1".into(),
            decided_at: 2000,
            expires_at,
        }
    }

    fn at_secs(secs: i64) -> SystemTime {
        UNIX_EPOCH + std::time::Duration::from_secs(secs.unsigned_abs())
    }

    #[test]
    fn request_validation() {
        assert!(validate_request(&request()).is_ok());

        let mut bad = request();
        bad.reason = "   ".into();
        assert!(validate_request(&bad).is_err());

        let mut bad = request();
        bad.executable_hash = "short".into();
        assert!(validate_request(&bad).is_err());
    }

    #[test]
    fn one_time_active_then_expired() {
        let d = decision(ApprovalScope::OneTime { hash: HASH.into() }, Some(5000));
        // Before expiry: active.
        assert_eq!(d.check(HASH, at_secs(4000)), ApprovalStatus::Active);
        // After expiry: expired (even without the server).
        assert_eq!(
            d.check(HASH, at_secs(6000)),
            ApprovalStatus::Expired { expired_at: 5000 }
        );
        // Exactly at expiry boundary: still active (<=).
        assert_eq!(d.check(HASH, at_secs(5000)), ApprovalStatus::Active);
    }

    #[test]
    fn wrong_hash_not_applicable() {
        let d = decision(ApprovalScope::OneTime { hash: HASH.into() }, Some(5000));
        assert_eq!(
            d.check(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                at_secs(4000)
            ),
            ApprovalStatus::NotApplicable
        );
    }

    #[test]
    fn duration_scope() {
        let d = decision(
            ApprovalScope::Duration {
                hash: HASH.into(),
                duration_secs: 3600,
            },
            Some(5600), // decided_at 2000 + 3600
        );
        assert!(d.validate().is_ok());
        assert_eq!(d.check(HASH, at_secs(3000)), ApprovalStatus::Active);
        assert!(matches!(
            d.check(HASH, at_secs(6000)),
            ApprovalStatus::Expired { .. }
        ));
    }

    #[test]
    fn non_signer_must_expire() {
        let d = decision(ApprovalScope::OneTime { hash: HASH.into() }, None);
        assert!(d.validate().is_err());
    }

    #[test]
    fn signer_can_be_permanent() {
        let d = decision(
            ApprovalScope::Signer {
                signer_key_id: "eb10b464".into(),
            },
            None,
        );
        assert!(d.validate().is_ok());
    }

    #[test]
    fn decision_validation_errors() {
        // Empty approver.
        let mut d = decision(ApprovalScope::OneTime { hash: HASH.into() }, Some(5000));
        d.approver = String::new();
        assert!(d.validate().is_err());

        // Bad hash in scope.
        let d = decision(ApprovalScope::OneTime { hash: "bad".into() }, Some(5000));
        assert!(d.validate().is_err());
    }
}
