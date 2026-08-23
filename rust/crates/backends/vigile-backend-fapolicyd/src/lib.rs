// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vigile fapolicyd backend (ISS-035/036, phases 2-3).
//!
//! ISS-035: native validation, deployment and reload via fapolicyd-cli.
//! ISS-036: denial collection from journald + inventory correlation.
//!
//! Capacities verified by spike ISS-008 (docs/spikes/ISS-008-fapolicyd.md):
//! - `fapolicyd-cli --check-rules <file> [--lint]` validates offline.
//! - `fapolicyd-cli --reload-rules` reloads via the FIFO.
//! - Rules go in /etc/fapolicyd/rules.d/*.rules (natural sort).
//! - Audit events appear in journald (FANOTIFY) when auditd is active.

use serde::Serialize;
use std::path::Path;
use std::process::Command;

/// Backend identifier used in capability manifests.
pub const BACKEND_ID: &str = "fapolicyd";

/// Standard paths managed by this backend.
pub const RULES_DIR: &str = "/etc/fapolicyd/rules.d";
pub const VIGILE_RULES_SUBDIR: &str = "vigile";
pub const FIFO_PATH: &str = "/run/fapolicyd/fapolicyd.fifo";

// ---------------------------------------------------------------------
// Validation (ISS-035)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// fapolicyd-cli is not installed or not in PATH.
    CliNotFound,
    /// fapolicyd-cli returned a non-zero exit code.
    Invalid(String),
    /// I/O error running the command.
    Io(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::CliNotFound => write!(f, "fapolicyd-cli not found"),
            ValidationError::Invalid(d) => write!(f, "rules invalid: {d}"),
            ValidationError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for ValidationError {}

/// Validates a single rules file with `fapolicyd-cli --check-rules`.
/// This is the OFFLINE validator — it parses the file without loading
/// it into the running daemon (SEC-501: native validation before
/// activation).
pub fn check_rules(file: &Path) -> Result<(), ValidationError> {
    let output = Command::new("fapolicyd-cli")
        .arg("--check-rules")
        .arg(file)
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ValidationError::CliNotFound
            } else {
                ValidationError::Io(e.to_string())
            }
        })?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        Err(ValidationError::Invalid(format!(
            "exit {}: {} {}",
            output.status.code().unwrap_or(-1),
            stdout.trim(),
            stderr.trim()
        )))
    }
}

/// Validates all .rules files in a directory.
pub fn check_rules_dir(dir: &Path) -> Result<Vec<String>, ValidationError> {
    let mut errors = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|e| ValidationError::Io(e.to_string()))?;

    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("rules") {
            if let Err(e) = check_rules(&path) {
                // Propagate CliNotFound immediately (it applies to all
                // files — no point checking the rest).
                if matches!(e, ValidationError::CliNotFound) {
                    return Err(e);
                }
                errors.push(format!("{}: {e}", path.display()));
            }
        }
    }

    if errors.is_empty() {
        Ok(Vec::new())
    } else {
        Err(ValidationError::Invalid(errors.join("; ")))
    }
}

// ---------------------------------------------------------------------
// Deployment (ISS-035)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeployError {
    Validation(String),
    Io(String),
    ReloadFailed(String),
}

impl std::fmt::Display for DeployError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeployError::Validation(e) => write!(f, "validation failed: {e}"),
            DeployError::Io(e) => write!(f, "I/O: {e}"),
            DeployError::ReloadFailed(e) => write!(f, "reload failed: {e}"),
        }
    }
}

impl std::error::Error for DeployError {}

/// Deploys rules files from `source_dir` to `/etc/fapolicyd/rules.d/vigile/`
/// and reloads fapolicyd. The validation step MUST have passed before
/// calling this (the caller — the executor — enforces this ordering).
pub fn deploy_rules(source_dir: &Path) -> Result<(), DeployError> {
    let target_dir = Path::new(RULES_DIR).join(VIGILE_RULES_SUBDIR);

    // Create the target directory (0755, root-owned — the executor runs
    // as root).
    std::fs::create_dir_all(&target_dir)
        .map_err(|e| DeployError::Io(format!("mkdir {}: {e}", target_dir.display())))?;

    // Clear old Vigile rules in the target.
    if target_dir.exists() {
        for entry in std::fs::read_dir(&target_dir).map_err(|e| DeployError::Io(e.to_string()))? {
            let entry = entry.map_err(|e| DeployError::Io(e.to_string()))?;
            let path = entry.path();
            if path.is_file() {
                std::fs::remove_file(&path)
                    .map_err(|e| DeployError::Io(format!("rm {}: {e}", path.display())))?;
            }
        }
    }

    // Copy all .rules files from source to target.
    let entries = std::fs::read_dir(source_dir).map_err(|e| DeployError::Io(e.to_string()))?;
    let mut copied = 0;
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("rules") {
            let dest = target_dir.join(entry.file_name());
            std::fs::copy(&path, &dest).map_err(|e| {
                DeployError::Io(format!("copy {}→{}: {e}", path.display(), dest.display()))
            })?;
            copied += 1;
        }
    }

    if copied == 0 {
        return Err(DeployError::Io("no .rules files to deploy".into()));
    }

    // Reload fapolicyd rules.
    reload_rules()?;

    Ok(())
}

/// Triggers a hot reload of fapolicyd rules via `fapolicyd-cli --reload-rules`.
/// This writes to the FIFO, which the daemon reads without restart.
pub fn reload_rules() -> Result<(), DeployError> {
    let output = Command::new("fapolicyd-cli")
        .arg("--reload-rules")
        .output()
        .map_err(|e| DeployError::ReloadFailed(format!("fapolicyd-cli: {e}")))?;

    if !output.status.success() {
        return Err(DeployError::ReloadFailed(format!(
            "exit {}: {} {}",
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------
// Denial collection (ISS-036)
// ---------------------------------------------------------------------

/// A fapolicyd denial event (would-have-blocked in audit mode).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DenialEvent {
    /// Unix microseconds from journald.
    pub realtime_us: u64,
    /// The executable that was denied.
    pub exe: String,
    /// The file that was denied (path).
    pub path: String,
    /// The rule decision (deny_audit, deny, etc.).
    pub decision: String,
    /// Whether the file is in a known package (from inventory).
    pub package: Option<String>,
    /// SHA-256 of the file (from inventory), if known.
    pub sha256: Option<String>,
    /// File type (from fapolicyd).
    pub ftype: Option<String>,
}

/// Parses a fapolicyd denial from a journald JSON record.
/// The journal record format (from journalctl -o json) has:
/// - MESSAGE: the human-readable denial text
/// - _SYSTEMD_UNIT: fapolicyd.service
/// - __REALTIME_TIMESTAMP: microseconds
pub fn parse_denial(record: &str) -> Option<DenialEvent> {
    let value: serde_json::Value = serde_json::from_str(record).ok()?;

    let message = value.get("MESSAGE")?.as_str()?;
    let realtime = value.get("__REALTIME_TIMESTAMP")?.as_str()?.parse().ok()?;

    // fapolicyd audit messages have a structured format. The exact
    // format depends on the fapolicyd version; the common pattern is:
    // ".... deny_audit perm=execute exe=/path/to/exe : path=/path/to/file ..."
    // We parse the key fields from the message text.
    let exe = extract_field(message, "exe=")?;
    let path = extract_field(message, "path=").or_else(|| extract_field(message, ": "))?;
    let decision = extract_decision(message)?;

    Some(DenialEvent {
        realtime_us: realtime,
        exe,
        path,
        decision,
        package: None, // filled by correlation
        sha256: None,  // filled by correlation
        ftype: extract_field(message, "ftype="),
    })
}

fn extract_field(message: &str, prefix: &str) -> Option<String> {
    let pos = message.find(prefix)?;
    let rest = &message[pos + prefix.len()..];
    let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
    Some(rest[..end].trim_matches('"').to_string())
}

fn extract_decision(message: &str) -> Option<String> {
    // Look for allow_audit, deny_audit, allow, deny at the start of
    // the rule part.
    for decision in [
        "deny_audit",
        "allow_audit",
        "deny_syslog",
        "allow_syslog",
        "deny_log",
        "allow_log",
        "deny",
        "allow",
    ] {
        if message.contains(decision) {
            return Some(decision.to_string());
        }
    }
    None
}

/// Correlates a denial with the executable inventory.
pub fn correlate_denial(
    denial: &mut DenialEvent,
    inventory: &std::collections::BTreeMap<String, vigile_backend_inventory::ExecutableEntry>,
) {
    // Try to find the denied path in the inventory.
    if let Some(entry) = inventory.get(&denial.path) {
        denial.sha256 = Some(entry.sha256.clone());
    }

    // Try to find the executing binary.
    if let Some(entry) = inventory.get(&denial.exe) {
        denial.sha256 = Some(entry.sha256.clone());
    }

    // Package correlation would require the package inventory; the
    // agent fills this in when it has both inventories available.
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    #[test]
    fn denial_parsing() {
        let record = r#"{
            "__REALTIME_TIMESTAMP": "1755859200000000",
            "MESSAGE": "rule=1 dec=deny_audit perm=execute auid=1000 pid=1234 exe=/usr/bin/bash : path=/home/user/script.sh ftype=text/x-shellscript",
            "_SYSTEMD_UNIT": "fapolicyd.service"
        }"#;
        let denial = parse_denial(record).expect("must parse");
        assert_eq!(denial.exe, "/usr/bin/bash");
        assert_eq!(denial.path, "/home/user/script.sh");
        assert_eq!(denial.decision, "deny_audit");
        assert_eq!(denial.realtime_us, 1755859200000000);
    }

    #[test]
    fn denial_parsing_hostile() {
        assert_eq!(parse_denial("not json"), None);
        assert_eq!(parse_denial("{}"), None);
        assert_eq!(parse_denial(r#"{"MESSAGE":"no timestamp"}"#), None);
        assert_eq!(
            parse_denial(r#"{"__REALTIME_TIMESTAMP":"1","MESSAGE":"no exe or path"}"#),
            None
        );
    }

    #[test]
    fn field_extraction() {
        assert_eq!(
            extract_field("exe=/usr/bin/bash : path=/x", "exe="),
            Some("/usr/bin/bash".to_string())
        );
        assert_eq!(extract_field("no match here", "exe="), None);
        // Quoted values are trimmed.
        assert_eq!(
            extract_field("exe=\"/usr/bin/bash\" rest", "exe="),
            Some("/usr/bin/bash".to_string())
        );
    }

    #[test]
    fn decision_extraction() {
        assert_eq!(
            extract_decision("dec=deny_audit perm=x"),
            Some("deny_audit".to_string())
        );
        assert_eq!(
            extract_decision("dec=allow perm=x"),
            Some("allow".to_string())
        );
        assert_eq!(extract_decision("nothing relevant"), None);
    }

    #[test]
    fn check_rules_reports_not_found() {
        let result = check_rules(Path::new("/nonexistent"));
        // On a system without fapolicyd-cli, this returns CliNotFound.
        // On a system with it, it returns Invalid (file not found).
        assert!(matches!(
            result,
            Err(ValidationError::CliNotFound) | Err(ValidationError::Invalid(_))
        ));
    }
}
