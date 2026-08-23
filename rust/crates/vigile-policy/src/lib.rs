// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vigile policy — schéma versionné, canonisation JCS et validation.
//!
//! - `canonical` : canonisation JSON RFC 8785 (ADR-0004), validée sur les
//!   vecteurs officiels du RFC (spike ISS-007).
//! - `validate` : validation stricte contre le schéma embarqué
//!   (`schema/policy-v0.schema.json`), rejet des champs inconnus (SEC-208).
//!
//! Le compilateur IR→artefacts par backend arrive avec ISS-023.

/// Version du schéma de politique implémentée par cette crate.
pub const SCHEMA_VERSION: &str = "policy/v0";

/// Schéma JSON (draft 2020-12) de `policy/v0`, embarqué à la compilation.
///
/// NOTE : le mot-clé `format` n'est qu'une annotation par défaut ; la
/// validation par format (date-time) doit être activée à l'usage
/// (docs/POLICY_MODEL.md §3.1).
pub const SCHEMA_JSON: &str = include_str!("../schema/policy-v0.schema.json");

pub mod canonical;
pub mod validate;

pub use canonical::{canonical_json, CanonicalError};
pub use validate::{parse_and_validate, PolicyError, PolicyValidator};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_embarque_present() {
        let trimmed = SCHEMA_JSON.trim();
        assert!(trimmed.starts_with('{') && trimmed.ends_with('}'));
        assert!(trimmed.contains("\"policy/v0\""));
    }

    #[test]
    fn modules_exposes() {
        let v = serde_json::json!({"a": 1});
        assert_eq!(canonical_json(&v), Ok("{\"a\":1}".to_string()));
    }
}
