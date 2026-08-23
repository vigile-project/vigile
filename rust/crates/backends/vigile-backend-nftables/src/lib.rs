// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vigile nftables backend (Phase 7): network rule types, workload
//! identity via cgroups v2, and rule generation.
//!
//! ARCHITECTURE (per ROADMAP phase 7):
//! 1. Applications run in systemd scopes/units (cgroups v2).
//! 2. nftables rules match on `cgroupv2` to identify the workload.
//! 3. Rules are per-application, not per-port.
//!
//! PROTOTYPE REQUIREMENT: a stable workload identity must be
//! demonstrated before deployment (ROADMAP phase 7 gate).

use serde::{Deserialize, Serialize};
use std::fmt;

/// Identifies a workload by its cgroup v2 path.
/// Example: "/system.slice/vigile-agent.service"
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct WorkloadId {
    /// Full cgroup v2 path.
    pub cgroup_path: String,
    /// Extracted systemd unit name (for display).
    pub unit_name: String,
}

impl WorkloadId {
    /// Creates a WorkloadId from a cgroup path.
    /// `/system.slice/httpd.service` → unit_name: `httpd.service`
    pub fn from_cgroup_path(path: &str) -> Option<Self> {
        if path.is_empty() || !path.starts_with('/') {
            return None;
        }
        let unit_name = path
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("unknown")
            .to_string();
        Some(Self {
            cgroup_path: path.to_string(),
            unit_name,
        })
    }

    /// Reads the cgroup v2 path of a PID.
    pub fn from_pid(pid: u32) -> Option<Self> {
        let path = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
        // Format: "0::/system.slice/httpd.service"
        let line = path.lines().find(|l| l.starts_with("0::"))?;
        let cgroup = line.strip_prefix("0::")?;
        Self::from_cgroup_path(cgroup)
    }
}

impl fmt::Display for WorkloadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.unit_name)
    }
}

/// Network protocol for filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

impl Protocol {
    pub fn nft_name(&self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Icmp => "icmp",
        }
    }
}

/// A network destination (host or CIDR).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    /// IP address, CIDR, or hostname.
    pub address: String,
    /// Port(s) — empty means all ports.
    pub ports: Vec<u16>,
}

/// Action for a network rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkAction {
    Accept,
    Drop,
    Reject,
}

/// One nftables rule for a specific workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkRule {
    /// The workload this rule applies to (cgroup match).
    pub workload: WorkloadId,
    /// Protocol (tcp, udp, icmp).
    pub protocol: Protocol,
    /// Destination.
    pub destination: Destination,
    /// Action.
    pub action: NetworkAction,
}

impl NetworkRule {
    /// Generates the nftables rule string.
    ///
    /// Example output:
    /// ```text
    /// meta cgroup "system.slice/httpd.service" ip daddr 10.0.0.1 tcp dport 443 accept
    /// ```
    pub fn to_nft_rule(&self) -> String {
        let mut parts = Vec::new();

        // Match on cgroup v2 path.
        parts.push(format!("meta cgroup \"{}\"", self.workload.cgroup_path));

        // Match on destination address.
        parts.push(format!("ip daddr {}", self.destination.address));

        // Match on protocol and ports.
        if !self.destination.ports.is_empty() {
            let port_list = self
                .destination
                .ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            parts.push(format!(
                "{} dport {{ {} }}",
                self.protocol.nft_name(),
                port_list
            ));
        } else {
            parts.push(self.protocol.nft_name().to_string());
        }

        // Action.
        let action = match self.action {
            NetworkAction::Accept => "accept",
            NetworkAction::Drop => "drop",
            NetworkAction::Reject => "reject",
        };
        parts.push(action.to_string());

        parts.join(" ")
    }
}

/// A complete nftables table for Vigile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NftablesConfig {
    /// Table name.
    pub table_name: String,
    /// Chain name (usually "filter").
    pub chain_name: String,
    /// Chain type (filter, nat, etc.).
    pub chain_type: String,
    /// Hook (input, output, forward).
    pub hook: String,
    /// Priority (lower = earlier).
    pub priority: i32,
    /// Default policy (accept, drop).
    pub policy: String,
    /// Rules.
    pub rules: Vec<NetworkRule>,
}

impl NftablesConfig {
    /// Generates a complete nftables ruleset.
    pub fn to_nft_script(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "# Vigile nftables configuration\n\
             # Generated ruleset — apply with: nft -f <file>\n\n\
             table {} {} {{\n\
             \tchain {} {{\n\
             \t\ttype {} hook {} priority {}; policy {};\n",
            self.chain_type,
            self.table_name,
            self.chain_name,
            self.chain_type,
            self.hook,
            self.priority,
            self.policy,
        ));

        for rule in &self.rules {
            out.push_str(&format!("\t\t{}\n", rule.to_nft_rule()));
        }

        out.push_str("\t}\n}\n");
        out
    }
}

/// Creates a default Vigile nftables configuration (output chain, default
/// accept — Phase 7 starts in audit mode, not blocking).
pub fn default_config() -> NftablesConfig {
    NftablesConfig {
        table_name: "vigile_filter".to_string(),
        chain_name: "output".to_string(),
        chain_type: "filter".to_string(),
        hook: "output".to_string(),
        priority: 0,
        policy: "accept".to_string(), // Phase 7: observe first
        rules: Vec::new(),
    }
}

/// Lists all workloads with cgroup v2 paths on the system.
pub fn list_workloads() -> Vec<WorkloadId> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/sys/fs/cgroup/system.slice") {
        for entry in entries.filter_map(|e| e.ok()) {
            let name = entry.file_name().to_string_lossy().to_string();
            let path = format!("/system.slice/{name}");
            if let Some(id) = WorkloadId::from_cgroup_path(&path) {
                out.push(id);
            }
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    #[test]
    fn workload_id_from_path() {
        let id = WorkloadId::from_cgroup_path("/system.slice/httpd.service").unwrap();
        assert_eq!(id.unit_name, "httpd.service");
        assert_eq!(id.cgroup_path, "/system.slice/httpd.service");

        // Invalid paths.
        assert!(WorkloadId::from_cgroup_path("").is_none());
        assert!(WorkloadId::from_cgroup_path("no-slash").is_none());
    }

    #[test]
    fn workload_id_display() {
        let id = WorkloadId::from_cgroup_path("/system.slice/vigile-agent.service").unwrap();
        assert_eq!(id.to_string(), "vigile-agent.service");
    }

    #[test]
    fn nft_rule_generation() {
        let workload = WorkloadId::from_cgroup_path("/system.slice/firefox.service").unwrap();
        let rule = NetworkRule {
            workload,
            protocol: Protocol::Tcp,
            destination: Destination {
                address: "10.0.0.1".to_string(),
                ports: vec![443],
            },
            action: NetworkAction::Accept,
        };
        let nft = rule.to_nft_rule();
        assert!(nft.contains("meta cgroup \"/system.slice/firefox.service\""));
        assert!(nft.contains("ip daddr 10.0.0.1"));
        assert!(nft.contains("tcp dport { 443 }"));
        assert!(nft.contains("accept"));
    }

    #[test]
    fn nft_rule_no_ports() {
        let workload = WorkloadId::from_cgroup_path("/system.slice/app.service").unwrap();
        let rule = NetworkRule {
            workload,
            protocol: Protocol::Udp,
            destination: Destination {
                address: "192.168.1.0/24".to_string(),
                ports: vec![],
            },
            action: NetworkAction::Drop,
        };
        let nft = rule.to_nft_rule();
        assert!(nft.contains("ip daddr 192.168.1.0/24"));
        assert!(nft.contains("udp"));
        assert!(nft.contains("drop"));
        assert!(!nft.contains("dport"));
    }

    #[test]
    fn nft_config_generation() {
        let mut config = default_config();
        let workload = WorkloadId::from_cgroup_path("/system.slice/httpd.service").unwrap();
        config.rules.push(NetworkRule {
            workload,
            protocol: Protocol::Tcp,
            destination: Destination {
                address: "0.0.0.0/0".to_string(),
                ports: vec![80, 443],
            },
            action: NetworkAction::Accept,
        });
        let script = config.to_nft_script();
        assert!(script.contains("table filter vigile_filter"));
        assert!(script.contains("chain output"));
        assert!(script.contains("policy accept"));
        assert!(script.contains("dport { 80, 443 }"));
    }

    #[test]
    fn default_config_is_audit_mode() {
        let config = default_config();
        assert_eq!(config.policy, "accept"); // not "drop"
        assert!(config.rules.is_empty());
    }
}
