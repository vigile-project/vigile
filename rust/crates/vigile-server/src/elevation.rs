// SPDX-License-Identifier: AGPL-3.0-or-later
//! Controlled elevation (Phase 8, §9-C cahier des charges): structured
//! actions with approval, duration, least privilege and full audit.
//!
//! DESIGN: users NEVER get a generic root shell. They request a
//! SPECIFIC action (install a package, restart a service, edit a
//! specific file) which is approved by a human, time-limited, and
//! fully audited. The action is executed by the executor as a
//! typed operation — never as a shell command.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// A specific, typed elevation action. Each variant corresponds to a
/// narrowly-scoped privileged operation — there is no "run arbitrary
/// command" variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ElevationAction {
    /// Install a specific package (dnf/apt).
    PackageInstall {
        /// Exact package name (no globs, no version ranges).
        package: String,
    },
    /// Restart a specific systemd service.
    ServiceRestart {
        /// Exact unit name (e.g. "nginx.service").
        unit: String,
    },
    /// Edit a specific file (content provided, not a command).
    FileWrite {
        /// Absolute path of the file to write.
        path: String,
        /// New content (plain text — no shell, no script).
        content: String,
    },
    /// Read a specific file that requires root to read.
    FileRead {
        /// Absolute path of the file to read.
        path: String,
    },
    /// Run a specific predefined command from an allowlist
    /// (defined server-side, never user-supplied).
    PredefinedCommand {
        /// Key into the server's command allowlist.
        command_key: String,
        /// Arguments validated against the allowlist's arg spec.
        args: Vec<String>,
    },
}

/// A user's request for elevated action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElevationRequest {
    pub id: String,
    pub agent_id: String,
    /// Unix username of the requester.
    pub user: String,
    /// The specific action requested.
    pub action: ElevationAction,
    /// Mandatory justification (SEC-304).
    pub reason: String,
    /// Unix seconds.
    pub created_at: i64,
    /// Requested duration (seconds). Capped by policy.
    pub requested_duration_secs: u64,
}

/// An approved elevation (time-limited).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElevationGrant {
    pub request_id: String,
    /// The approved action.
    pub action: ElevationAction,
    /// Who approved (admin identity).
    pub approver: String,
    /// Unix seconds when the grant was issued.
    pub granted_at: i64,
    /// Unix seconds when the grant expires (HARD LIMIT — local check).
    pub expires_at: i64,
    /// Whether this grant has been used (one-use grants).
    pub used: bool,
}

/// Default maximum duration for an elevation (15 minutes).
pub const DEFAULT_MAX_DURATION_SECS: u64 = 15 * 60;
/// Hard ceiling regardless of policy (4 hours).
pub const HARD_MAX_DURATION_SECS: u64 = 4 * 3600;

impl ElevationGrant {
    /// Checks whether this grant is still valid at the given time.
    /// SEC-303: works locally even without the server.
    pub fn is_valid(&self, now: SystemTime) -> bool {
        if self.used {
            return false;
        }
        let now_secs = now
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        now_secs <= self.expires_at
    }

    /// Marks this grant as used (one-time).
    pub fn mark_used(&mut self) {
        self.used = true;
    }
}

/// Validates an elevation request before creating it.
pub fn validate_request(request: &ElevationRequest) -> Result<(), String> {
    if request.id.is_empty() {
        return Err("id is empty".into());
    }
    if request.agent_id.is_empty() {
        return Err("agent_id is empty".into());
    }
    if request.user.is_empty() {
        return Err("user is empty".into());
    }
    if request.reason.trim().is_empty() {
        return Err("reason is empty (SEC-304: justification mandatory)".into());
    }
    if request.requested_duration_secs == 0 {
        return Err("requested_duration_secs must be > 0".into());
    }
    if request.requested_duration_secs > HARD_MAX_DURATION_SECS {
        return Err(format!(
            "requested_duration_secs {} exceeds hard maximum {}",
            request.requested_duration_secs, HARD_MAX_DURATION_SECS
        ));
    }

    // Validate the action's fields.
    match &request.action {
        ElevationAction::PackageInstall { package } => {
            if package.is_empty() || package.contains(char::is_whitespace) {
                return Err("package name must be non-empty, no whitespace".into());
            }
            // Reject shell metacharacters.
            if package.contains(&[';', '|', '&', '$', '`', '\\'][..]) {
                return Err("package name contains shell metacharacters".into());
            }
        }
        ElevationAction::ServiceRestart { unit } => {
            if unit.is_empty() || !unit.ends_with(".service") {
                return Err("unit must be a .service unit name".into());
            }
        }
        ElevationAction::FileWrite { path, .. } | ElevationAction::FileRead { path } => {
            if !path.starts_with('/') {
                return Err("path must be absolute".into());
            }
            if path.contains("..") {
                return Err("path contains '..'".into());
            }
        }
        ElevationAction::PredefinedCommand { command_key, args } => {
            if command_key.is_empty() {
                return Err("command_key is empty".into());
            }
            // Args are validated against the server-side allowlist,
            // but we do basic sanitization here too.
            for arg in args {
                if arg.contains('\0') {
                    return Err("argument contains null byte".into());
                }
            }
        }
    }

    Ok(())
}

/// Creates a grant from an approved request. The duration is capped
/// at `max_duration` (from policy, further capped at HARD_MAX).
pub fn create_grant(
    request: &ElevationRequest,
    approver: &str,
    max_duration: u64,
    now: SystemTime,
) -> Result<ElevationGrant, String> {
    validate_request(request)?;

    if approver.is_empty() {
        return Err("approver is empty".into());
    }

    let now_secs = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let effective_duration = request
        .requested_duration_secs
        .min(max_duration)
        .min(HARD_MAX_DURATION_SECS);

    Ok(ElevationGrant {
        request_id: request.id.clone(),
        action: request.action.clone(),
        approver: approver.to_string(),
        granted_at: now_secs,
        expires_at: now_secs + effective_duration as i64,
        used: false,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    fn request(action: ElevationAction) -> ElevationRequest {
        ElevationRequest {
            id: "elev-001".into(),
            agent_id: "agent-001".into(),
            user: "alice".into(),
            action,
            reason: "need to install debugging tool".into(),
            created_at: 1000,
            requested_duration_secs: 300,
        }
    }

    fn at_secs(secs: i64) -> SystemTime {
        UNIX_EPOCH + std::time::Duration::from_secs(secs.unsigned_abs())
    }

    #[test]
    fn valid_requests_pass() {
        let req = request(ElevationAction::PackageInstall {
            package: "strace".into(),
        });
        assert!(validate_request(&req).is_ok());

        let req = request(ElevationAction::ServiceRestart {
            unit: "nginx.service".into(),
        });
        assert!(validate_request(&req).is_ok());

        let req = request(ElevationAction::FileRead {
            path: "/var/log/secure".into(),
        });
        assert!(validate_request(&req).is_ok());
    }

    #[test]
    fn shell_metacharacters_rejected() {
        let req = request(ElevationAction::PackageInstall {
            package: "foo; rm -rf /".into(),
        });
        assert!(validate_request(&req).is_err());

        let req = request(ElevationAction::PackageInstall {
            package: "$(whoami)".into(),
        });
        assert!(validate_request(&req).is_err());
    }

    #[test]
    fn relative_path_rejected() {
        let req = request(ElevationAction::FileRead {
            path: "etc/passwd".into(),
        });
        assert!(validate_request(&req).is_err());

        let req = request(ElevationAction::FileWrite {
            path: "/etc/../etc/shadow".into(),
            content: "x".into(),
        });
        assert!(validate_request(&req).is_err());
    }

    #[test]
    fn service_name_validated() {
        let req = request(ElevationAction::ServiceRestart {
            unit: "nginx".into(), // missing .service suffix
        });
        assert!(validate_request(&req).is_err());
    }

    #[test]
    fn empty_reason_rejected() {
        let mut req = request(ElevationAction::PackageInstall {
            package: "strace".into(),
        });
        req.reason = "  ".into();
        assert!(validate_request(&req).is_err());
    }

    #[test]
    fn grant_expires_locally() {
        let req = request(ElevationAction::PackageInstall {
            package: "strace".into(),
        });
        let grant = create_grant(&req, "admin:tok1", 300, at_secs(1000)).unwrap();

        // Valid at t=1000.
        assert!(grant.is_valid(at_secs(1000)));
        assert!(grant.is_valid(at_secs(1299)));

        // Expired at t=1301 (1000 + 300).
        assert!(!grant.is_valid(at_secs(1301)));

        // Even without a server, expiry works (SEC-303).
    }

    #[test]
    fn one_use_grant() {
        let req = request(ElevationAction::PackageInstall {
            package: "strace".into(),
        });
        let mut grant = create_grant(&req, "admin", 300, at_secs(1000)).unwrap();
        assert!(grant.is_valid(at_secs(1100)));

        grant.mark_used();
        assert!(!grant.is_valid(at_secs(1100)));
    }

    #[test]
    fn duration_capped() {
        let mut req = request(ElevationAction::PackageInstall {
            package: "strace".into(),
        });
        req.requested_duration_secs = 3 * 3600; // 3 hours (under HARD_MAX, above policy)
        let grant = create_grant(&req, "admin", 3600, at_secs(1000)).unwrap();
        // Capped to 3600 (policy max) and HARD_MAX (4h) → 3600.
        assert_eq!(grant.expires_at - grant.granted_at, 3600);
    }

    #[test]
    fn hard_ceiling_enforced() {
        let mut req = request(ElevationAction::PackageInstall {
            package: "strace".into(),
        });
        req.requested_duration_secs = HARD_MAX_DURATION_SECS;
        // Even with a permissive policy, HARD_MAX is the ceiling.
        let grant = create_grant(&req, "admin", 8 * 3600, at_secs(1000)).unwrap();
        assert_eq!(
            grant.expires_at - grant.granted_at,
            HARD_MAX_DURATION_SECS as i64
        );
    }

    #[test]
    fn null_byte_in_args_rejected() {
        let req = request(ElevationAction::PredefinedCommand {
            command_key: "network-diagnostic".into(),
            args: vec!["--inter\x00face".into()],
        });
        assert!(validate_request(&req).is_err());
    }
}
