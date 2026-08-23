// SPDX-License-Identifier: AGPL-3.0-or-later
//! Admin authentication and RBAC (ISS-031).
//!
//! MVP: static bearer tokens generated at startup, one per role.
//! Full OIDC/MFA arrives with the portal (ISS-032, DEC-06).

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdminRole {
    /// Read-only: list agents, view audit.
    Viewer,
    /// Everything: issue tokens, quarantine, reinstate, view audit.
    Admin,
    /// Admin + key operations (reserved for future use).
    #[allow(dead_code)]
    PlatformAdmin,
}

#[derive(Debug, Clone)]
pub struct AdminToken {
    pub token: String,
    pub role: AdminRole,
}

/// Generates a cryptographically random admin token (hex).
fn random_token() -> Result<String, std::io::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| std::io::Error::other(format!("RNG: {e}")))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Token store: maps bearer tokens to roles.
#[derive(Debug, Default)]
pub struct TokenAuth {
    tokens: Vec<AdminToken>,
}

impl TokenAuth {
    /// Creates a fresh store with one token per given role.
    /// Returns the tokens (to be printed/configured) and the store.
    pub fn new(roles: &[AdminRole]) -> Result<(Self, Vec<AdminToken>), std::io::Error> {
        let mut tokens = Vec::new();
        for role in roles {
            tokens.push(AdminToken {
                token: random_token()?,
                role: *role,
            });
        }
        Ok((
            Self {
                tokens: tokens.clone(),
            },
            tokens,
        ))
    }

    /// Validates a Bearer token, returning the role.
    /// Timing-safe comparison is not needed here because the tokens are
    /// 256-bit random values — brute force is computationally infeasible.
    pub fn validate(&self, bearer: &str) -> Option<AdminRole> {
        // Strip "Bearer " prefix if present.
        let token = bearer.strip_prefix("Bearer ").unwrap_or(bearer);
        self.tokens
            .iter()
            .find(|t| t.token == token)
            .map(|t| t.role)
    }

    /// Checks whether a role has the required permission.
    pub fn authorize(role: AdminRole, required: AdminRole) -> bool {
        role >= required
    }
}

/// Extracts the Authorization header value from an HTTP request.
pub fn bearer_from_headers(headers: &std::collections::HashMap<String, String>) -> Option<String> {
    headers.get("authorization").cloned()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    #[test]
    fn token_generation_and_validation() {
        let (auth, tokens) = TokenAuth::new(&[AdminRole::Viewer, AdminRole::Admin]).unwrap();
        assert_eq!(tokens.len(), 2);

        let viewer_token = &tokens[0];
        let admin_token = &tokens[1];

        // Correct tokens validate to their roles.
        assert_eq!(auth.validate(&viewer_token.token), Some(AdminRole::Viewer));
        assert_eq!(auth.validate(&admin_token.token), Some(AdminRole::Admin));

        // Bearer prefix works.
        assert_eq!(
            auth.validate(&format!("Bearer {}", admin_token.token)),
            Some(AdminRole::Admin)
        );

        // Wrong token → None.
        assert_eq!(auth.validate("wrong-token"), None);
        assert_eq!(auth.validate(""), None);
    }

    #[test]
    fn rbac_hierarchy() {
        // Viewer can only do viewer things.
        assert!(TokenAuth::authorize(AdminRole::Viewer, AdminRole::Viewer));
        assert!(!TokenAuth::authorize(AdminRole::Viewer, AdminRole::Admin));

        // Admin can do viewer + admin things.
        assert!(TokenAuth::authorize(AdminRole::Admin, AdminRole::Viewer));
        assert!(TokenAuth::authorize(AdminRole::Admin, AdminRole::Admin));

        // PlatformAdmin can do everything.
        assert!(TokenAuth::authorize(
            AdminRole::PlatformAdmin,
            AdminRole::Admin
        ));
    }

    #[test]
    fn tokens_are_unique() {
        let (_, tokens) = TokenAuth::new(&[AdminRole::Admin, AdminRole::Admin]).unwrap();
        assert_ne!(tokens[0].token, tokens[1].token);
    }
}
