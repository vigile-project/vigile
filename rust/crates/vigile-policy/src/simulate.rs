// SPDX-License-Identifier: AGPL-3.0-or-later
//! Simulation and diff (ISS-026): replay events against the GENERATED
//! ruleset with fapolicyd's first-match semantics, and produce a
//! readable source-level diff between two policies (SEC-802 — no
//! blocking rollout without simulation and diff).

use crate::compiler::Compiled;
use crate::model::Policy;
use serde::{Deserialize, Serialize};

/// One simulated execution attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimEvent {
    /// Subject executable path (`exe=`), when known.
    #[serde(default)]
    pub exe: Option<String>,
    /// Hash of the object being executed.
    #[serde(default)]
    pub hash: Option<String>,
    /// Whether the object is in the trust database (rpmdb/trust files).
    #[serde(default)]
    pub trusted: Option<bool>,
}

/// The decision a ruleset would take (mirrors the `_audit` distinction).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SimDecision {
    Allow,
    AllowAudit,
    Deny,
    DenyAudit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SimResult {
    pub decision: SimDecision,
    /// 1-based line number of the matched rule in the rules file
    /// (comments counted — points at the exact artifact line).
    pub matched_line: usize,
}

/// A parsed rule (the shapes `crate::compiler` emits — deliberately
/// minimal; fapolicyd's full grammar is validated by
/// `fapolicyd-cli --check-rules`, not re-implemented here).
struct Rule {
    decision: String,
    exe: Option<String>,
    file_hash: Option<String>,
    trust: Option<bool>,
}

fn parse_rules(content: &str) -> Vec<(usize, Rule)> {
    let mut rules = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // <decision> perm=execute [exe=<path>] : all [FILE_HASH=<h> | trust=1]
        let Some((head, object)) = line.split_once(" : ") else {
            continue;
        };
        let mut parts = head.split_whitespace();
        let Some(decision) = parts.next() else {
            continue;
        };
        let mut exe = None;
        for part in parts {
            if let Some(path) = part.strip_prefix("exe=") {
                exe = Some(path.to_string());
            }
        }
        let mut file_hash = None;
        let mut trust = None;
        for part in object.split_whitespace() {
            if let Some(h) = part.strip_prefix("FILE_HASH=") {
                file_hash = Some(h.to_string());
            } else if part == "trust=1" {
                trust = Some(true);
            }
        }
        rules.push((
            idx + 1,
            Rule {
                decision: decision.to_string(),
                exe,
                file_hash,
                trust,
            },
        ));
    }
    rules
}

/// Simulates one event: FIRST matching rule wins (fapolicyd semantics).
pub fn simulate(compiled: &Compiled, event: &SimEvent) -> Result<SimResult, String> {
    let artifact = compiled
        .artifacts
        .first()
        .ok_or_else(|| "no rules artifact".to_string())?;
    for (line, rule) in parse_rules(&artifact.content) {
        if let Some(exe) = &rule.exe {
            if event.exe.as_deref() != Some(exe.as_str()) {
                continue;
            }
        }
        if let Some(hash) = &rule.file_hash {
            if event.hash.as_deref() != Some(hash.as_str()) {
                continue;
            }
        }
        if let Some(required) = &rule.trust {
            if *required && event.trusted != Some(true) {
                continue;
            }
        }
        let decision = match rule.decision.as_str() {
            "allow" => SimDecision::Allow,
            "allow_audit" => SimDecision::AllowAudit,
            "deny" => SimDecision::Deny,
            "deny_audit" => SimDecision::DenyAudit,
            other => return Err(format!("unhandled decision '{other}'")),
        };
        return Ok(SimResult {
            decision,
            matched_line: line,
        });
    }
    // Our rulesets always end with a terminal rule; reaching here means
    // the artifact was tampered with — fail closed.
    Err("no rule matched (terminal rule missing?)".into())
}

/// Readable source-level diff between two policies (SEC-802). Paths use
/// JSON dotted notation; arrays are diffed element-wise with index.
pub fn policy_diff(previous: &Policy, current: &Policy) -> Vec<String> {
    let mut out = Vec::new();
    let prev = serde_json::to_value(previous).unwrap_or(serde_json::Value::Null);
    let cur = serde_json::to_value(current).unwrap_or(serde_json::Value::Null);
    diff_value("", &prev, &cur, &mut out);
    out
}

fn diff_value(path: &str, a: &serde_json::Value, b: &serde_json::Value, out: &mut Vec<String>) {
    match (a, b) {
        (serde_json::Value::Object(ma), serde_json::Value::Object(mb)) => {
            let mut keys: Vec<&String> = ma.keys().chain(mb.keys()).collect();
            keys.sort();
            keys.dedup();
            for key in keys {
                let child = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                match (ma.get(key), mb.get(key)) {
                    (Some(va), Some(vb)) => diff_value(&child, va, vb, out),
                    (Some(va), None) => out.push(format!("{child}: {va} → (supprimé)")),
                    (None, Some(vb)) => out.push(format!("{child}: (absent) → {vb}")),
                    (None, None) => {}
                }
            }
        }
        (serde_json::Value::Array(va), serde_json::Value::Array(vb)) => {
            for (i, (xa, xb)) in va.iter().zip(vb.iter()).enumerate() {
                diff_value(&format!("{path}[{i}]"), xa, xb, out);
            }
            for (i, xa) in va.iter().enumerate().skip(vb.len()) {
                out.push(format!("{path}[{i}]: {xa} → (supprimé)"));
            }
            for (i, xb) in vb.iter().enumerate().skip(va.len()) {
                out.push(format!("{path}[{i}]: (absent) → {xb}"));
            }
        }
        _ => {
            if a != b {
                out.push(format!("{path}: {a} → {b}"));
            }
        }
    }
}
