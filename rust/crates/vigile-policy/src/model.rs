// SPDX-License-Identifier: AGPL-3.0-or-later
//! Typed model for `policy/v0` (ISS-023). Mirrors
//! `schema/policy-v0.schema.json` — parse via serde AFTER schema
//! validation (`crate::validate::parse_and_validate`); deny_unknown_fields
//! on every struct keeps model and schema locked together.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    pub policy: Policy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub id: String,
    pub version: u64,
    pub schema_version: String,
    pub tenant: String,
    pub target: Target,
    #[serde(default)]
    pub application: Option<Application>,
    pub execution: Execution,
    #[serde(default)]
    pub filesystem: Option<FilesystemRules>,
    #[serde(default)]
    pub network: Option<Network>,
    pub usb: Usb,
    pub validity: Validity,
    #[serde(default)]
    pub approval: Option<Approval>,
    #[serde(default)]
    pub rollout: Option<Rollout>,
    #[serde(default)]
    pub safety: Option<Safety>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Application {
    #[serde(default)]
    pub identity: Option<Identity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    #[serde(default)]
    pub package: Option<PackageId>,
    #[serde(default)]
    pub hashes: Vec<String>,
    #[serde(default)]
    pub signer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageId {
    pub name: String,
    pub vendor: Vendor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Vendor {
    Distribution,
    Upstream,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    Allow,
    Deny,
    AuditOnly,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Execution {
    pub decision: Decision,
    #[serde(default)]
    pub interpreters: Option<Interpreters>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Interpreters {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathRules {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemRules {
    #[serde(default)]
    pub read: Option<PathRules>,
    #[serde(default)]
    pub write: Option<PathRules>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum NetworkDefault {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub default: NetworkDefault,
    #[serde(default)]
    pub allow: Vec<NetworkRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkRule {
    pub protocol: String,
    pub destination: String,
    #[serde(default)]
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UsbDecision {
    Allow,
    Deny,
    AuditOnly,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Usb {
    pub decision: UsbDecision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Validity {
    pub not_before: String,
    pub not_after: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    #[serde(default)]
    pub required_roles: Vec<String>,
    #[serde(default)]
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RolloutStrategy {
    AuditOnly,
    Simulation,
    Canary,
    Rings,
    Percentage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rollout {
    pub strategy: RolloutStrategy,
    #[serde(default)]
    pub rings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Safety {
    #[serde(default)]
    pub protected_services: Vec<String>,
}

impl Policy {
    /// True when generated fapolicyd decisions must carry the `_audit`
    /// suffix (observation only — phase 2 doctrine, §26 cahier des
    /// charges: no blocking straight from compilation).
    pub fn audit_mode(&self) -> bool {
        match self.rollout.as_ref().map(|r| r.strategy) {
            Some(RolloutStrategy::Canary)
            | Some(RolloutStrategy::Rings)
            | Some(RolloutStrategy::Percentage) => false,
            // Explicit enforcement strategies emit blocking decisions.
            _ => true,
        }
    }
}
