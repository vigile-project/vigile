// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vigile AppArmor backend (Phase 5): profile types, generator,
//! and aa-status parser.
//!
//! AppArmor profile format (from apparmor.d(5)):
//! ```text
//! /path/to/binary {
//!   /path/to/file r,
//!   /path/to/dir/** rw,
//!   network tcp,
//!   deny /path/to/file w,
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::process::Command;

/// AppArmor profile modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileMode {
    /// Profile is loaded but only logs (no enforcement).
    Complain,
    /// Profile is loaded and enforcing.
    Enforce,
}

impl ProfileMode {
    pub fn as_flag(&self) -> &'static str {
        match self {
            ProfileMode::Complain => "C",
            ProfileMode::Enforce => "E",
        }
    }
}

/// One AppArmor rule entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Rule {
    File { path: String, access: FileAccess },
    Network { protocol: String },
    Capability { name: String },
    Deny { path: String, access: FileAccess },
}

/// AppArmor file access modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileAccess {
    Read,
    Write,
    ReadWrite,
    Execute,
    ReadExecute,
    All,
}

impl FileAccess {
    pub fn as_str(&self) -> &'static str {
        match self {
            FileAccess::Read => "r",
            FileAccess::Write => "w",
            FileAccess::ReadWrite => "rw",
            FileAccess::Execute => "x",
            FileAccess::ReadExecute => "rx",
            FileAccess::All => "rwklx",
        }
    }
}

/// A complete AppArmor profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// The binary or path this profile applies to.
    pub path: String,
    /// Profile name (defaults to the path).
    pub name: String,
    /// Loaded mode (complain or enforce).
    pub mode: ProfileMode,
    /// Rules within the profile.
    pub rules: Vec<Rule>,
}

impl Profile {
    /// Generates the AppArmor profile text.
    pub fn to_profile_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("# Vigile-generated profile for {}\n", self.path));
        out.push_str(&format!("# Mode: {:?}\n\n", self.mode));
        out.push_str(&format!("{} {{\n", self.name));

        for rule in &self.rules {
            match rule {
                Rule::File { path, access } => {
                    out.push_str(&format!("  {} {},\n", path, access.as_str()));
                }
                Rule::Network { protocol } => {
                    out.push_str(&format!("  network {},\n", protocol));
                }
                Rule::Capability { name } => {
                    out.push_str(&format!("  capability {},\n", name));
                }
                Rule::Deny { path, access } => {
                    out.push_str(&format!("  deny {} {},\n", path, access.as_str()));
                }
            }
        }

        out.push_str("}\n");
        out
    }
}

/// Generates a minimal complain-mode profile for a binary.
pub fn generate_complain_profile(binary_path: &str) -> Profile {
    Profile {
        path: binary_path.to_string(),
        name: binary_path.to_string(),
        mode: ProfileMode::Complain,
        rules: vec![Rule::File {
            path: "/**".to_string(),
            access: FileAccess::All,
        }],
    }
}

/// Generates an enforcing profile from a policy model's filesystem rules.
pub fn generate_enforce_profile(
    binary_path: &str,
    read_allow: &[String],
    write_allow: &[String],
    deny: &[String],
) -> Profile {
    let mut rules = Vec::new();

    for path in read_allow {
        rules.push(Rule::File {
            path: path.clone(),
            access: FileAccess::Read,
        });
    }
    for path in write_allow {
        rules.push(Rule::File {
            path: path.clone(),
            access: FileAccess::ReadWrite,
        });
    }
    for path in deny {
        rules.push(Rule::Deny {
            path: path.clone(),
            access: FileAccess::All,
        });
    }

    Profile {
        path: binary_path.to_string(),
        name: binary_path.to_string(),
        mode: ProfileMode::Enforce,
        rules,
    }
}

/// Status entry from `aa-status --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AaStatusEntry {
    pub mode: String,
    pub pid: Option<u32>,
}

/// Parses `aa-status --json` output.
pub fn parse_aa_status(json: &str) -> Result<Vec<(String, AaStatusEntry)>, String> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("invalid JSON: {e}"))?;

    let profiles = value
        .get("profiles")
        .and_then(|p| p.as_object())
        .ok_or("missing 'profiles' key")?;

    let mut out = Vec::new();
    for (name, info) in profiles {
        let mode = info
            .get("mode")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown")
            .to_string();
        let pid = info.get("pid").and_then(|p| p.as_u64()).map(|p| p as u32);
        out.push((name.clone(), AaStatusEntry { mode, pid }));
    }
    Ok(out)
}

/// Runs `aa-status --json` and parses the result.
pub fn run_aa_status() -> Result<Vec<(String, AaStatusEntry)>, std::io::Error> {
    let output = Command::new("aa-status")
        .arg("--json")
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                std::io::Error::other("aa-status not found (install apparmor-utils)")
            } else {
                e
            }
        })?;
    parse_aa_status(&String::from_utf8_lossy(&output.stdout)).map_err(std::io::Error::other)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    #[test]
    fn complain_profile_generation() {
        let profile = generate_complain_profile("/usr/bin/firefox");
        let text = profile.to_profile_text();
        assert!(text.contains("/usr/bin/firefox {"));
        assert!(text.contains("  /** rwklx,"));
        assert!(text.contains("}"));
    }

    #[test]
    fn enforce_profile_generation() {
        let profile = generate_enforce_profile(
            "/usr/bin/myapp",
            &["/etc/myapp/**".to_string()],
            &["/var/lib/myapp/**".to_string()],
            &["/home/**".to_string()],
        );
        let text = profile.to_profile_text();
        assert!(text.contains("/etc/myapp/** r,"));
        assert!(text.contains("/var/lib/myapp/** rw,"));
        assert!(text.contains("deny /home/** rwklx,"));
    }

    #[test]
    fn aa_status_parsing() {
        let json = r#"{
            "version": "4",
            "profiles": {
                "/usr/sbin/ntpd": {"mode": "enforce", "pid": 1234},
                "/usr/bin/evince": {"mode": "complain", "pid": null},
                "/usr/bin/man": {"mode": "enforce", "pid": null}
            }
        }"#;
        let entries = parse_aa_status(json).expect("parse");
        assert_eq!(entries.len(), 3);
        // JSON objects don't guarantee order — look up by name.
        let ntpd = entries.iter().find(|(n, _)| n == "/usr/sbin/ntpd").unwrap();
        assert_eq!(ntpd.1.mode, "enforce");
        assert_eq!(ntpd.1.pid, Some(1234));
        let evince = entries
            .iter()
            .find(|(n, _)| n == "/usr/bin/evince")
            .unwrap();
        assert_eq!(evince.1.mode, "complain");
        assert_eq!(evince.1.pid, None);
    }

    #[test]
    fn aa_status_hostile() {
        assert!(parse_aa_status("").is_err());
        assert!(parse_aa_status("not json").is_err());
        assert!(parse_aa_status("{}").is_err()); // missing profiles key
    }

    #[test]
    fn file_access_modes() {
        assert_eq!(FileAccess::Read.as_str(), "r");
        assert_eq!(FileAccess::ReadWrite.as_str(), "rw");
        assert_eq!(FileAccess::All.as_str(), "rwklx");
    }
}
