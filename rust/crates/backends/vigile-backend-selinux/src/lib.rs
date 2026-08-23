// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vigile SELinux backend (Phase 6): AVC denial parsing, context types,
//! and module generation stub.
//!
//! AVC (Access Vector Cache) denial format in audit logs:
//! ```text
//! type=AVC msg=audit(1234567890.123:456): avc: denied { read } for
//!   pid=1234 comm="httpd" name="file.txt" dev=sda1 ino=12345
//!   scontext=system_u:system_r:httpd_t:s0
//!   tcontext=system_u:object_r:var_lib_t:s0
//!   tclass=file permissive=1
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One SELinux security context (4 colon-separated fields).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct SecurityContext {
    pub user: String,
    pub role: String,
    pub type_name: String,
    /// MLS/MCS level (e.g. "s0", "s0:c0.c1023").
    pub level: String,
}

impl SecurityContext {
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() < 3 {
            return None;
        }
        Some(Self {
            user: parts[0].to_string(),
            role: parts[1].to_string(),
            type_name: parts[2].to_string(),
            level: parts.get(3).unwrap_or(&"s0").to_string(),
        })
    }

    pub fn to_context_string(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.user, self.role, self.type_name, self.level
        )
    }
}

/// SELinux object class (file, dir, socket, process, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObjectClass {
    File,
    Dir,
    Socket,
    Process,
    TcpSocket,
    UdpSocket,
    ChrFile,
    BlkFile,
    FifoFile,
    LnkFile,
    Other(String),
}

impl ObjectClass {
    pub fn parse(s: &str) -> Self {
        match s {
            "file" => ObjectClass::File,
            "dir" => ObjectClass::Dir,
            "socket" => ObjectClass::Socket,
            "process" => ObjectClass::Process,
            "tcp_socket" => ObjectClass::TcpSocket,
            "udp_socket" => ObjectClass::UdpSocket,
            "chr_file" => ObjectClass::ChrFile,
            "blk_file" => ObjectClass::BlkFile,
            "fifo_file" => ObjectClass::FifoFile,
            "lnk_file" => ObjectClass::LnkFile,
            other => ObjectClass::Other(other.to_string()),
        }
    }
}

/// One AVC denial event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AvcDenial {
    /// Audit timestamp (seconds.microseconds).
    pub timestamp: String,
    /// Serial number within the audit event.
    pub serial: u32,
    /// Denied permissions (e.g. "read", "write", "open").
    pub permissions: Vec<String>,
    /// Denying process PID.
    pub pid: u32,
    /// Process command name.
    pub comm: String,
    /// Target file/object name (if applicable).
    pub name: Option<String>,
    /// Source context (the process).
    pub scontext: SecurityContext,
    /// Target context (the object).
    pub tcontext: SecurityContext,
    /// Object class.
    pub tclass: ObjectClass,
    /// True if SELinux is in permissive mode (denied but allowed).
    pub permissive: bool,
}

/// Parses a single AVC denial line from the audit log.
pub fn parse_avc_line(line: &str) -> Option<AvcDenial> {
    if !line.contains("type=AVC") || !line.contains("avc:  denied") {
        return None;
    }

    let extract = |pattern: &str| -> Option<String> {
        let pos = line.find(pattern)?;
        let rest = &line[pos + pattern.len()..];
        let end = rest
            .find(|c: char| c.is_whitespace() || c == '\'')
            .unwrap_or(rest.len());
        Some(rest[..end].trim_matches('"').trim_matches('\'').to_string())
    };

    let timestamp_raw = extract("msg=audit(")?;
    // "1755859200.123:456):" → strip trailing "):" → "1755859200.123:456"
    let timestamp = timestamp_raw.trim_end_matches("):");
    let (ts, serial_str) = timestamp.rsplit_once(':')?;
    let serial: u32 = serial_str.parse().ok()?;

    let perms_str = line
        .split("{")
        .nth(1)?
        .split("}")
        .next()?
        .trim()
        .to_string();
    let permissions: Vec<String> = perms_str.split_whitespace().map(String::from).collect();

    let pid = extract("pid=")?.parse().ok()?;
    let comm = extract("comm=")?;
    let name = extract("name=");
    let scontext_str = extract("scontext=")?;
    let tcontext_str = extract("tcontext=")?;
    let tclass_str = extract("tclass=")?;
    let permissive = line.contains("permissive=1");

    Some(AvcDenial {
        timestamp: ts.to_string(),
        serial,
        permissions,
        pid,
        comm,
        name,
        scontext: SecurityContext::parse(&scontext_str)?,
        tcontext: SecurityContext::parse(&tcontext_str)?,
        tclass: ObjectClass::parse(&tclass_str),
        permissive,
    })
}

/// Parses multiple AVC lines from audit log output.
pub fn parse_audit_output(output: &str) -> Vec<AvcDenial> {
    output.lines().filter_map(parse_avc_line).collect()
}

/// Aggregates AVC denials by (scontext, tcontext, tclass, permissions).
/// Returns a map suitable for generating SELinux policy modules.
pub fn aggregate_denials(denials: &[AvcDenial]) -> BTreeMap<String, Vec<String>> {
    let mut map = BTreeMap::new();
    for d in denials {
        let key = format!(
            "{} → {} ({})",
            d.scontext.type_name,
            d.tcontext.type_name,
            match &d.tclass {
                ObjectClass::Other(s) => s.clone(),
                oc => format!("{oc:?}").to_lowercase(),
            }
        );
        let perms = d.permissions.join(",");
        map.entry(key).or_insert_with(Vec::new).push(perms);
    }
    // Deduplicate permission lists.
    for perms in map.values_mut() {
        perms.sort();
        perms.dedup();
    }
    map
}

/// Generates a minimal SELinux policy module (.te) from aggregated denials.
/// NOTE: This is a STUB — real module generation requires careful analysis
/// (Phase 6 gate: never generate an overly permissive policy from observed
/// events — docs/ROADMAP.md phase 6).
pub fn generate_module_stub(aggregated: &BTreeMap<String, Vec<String>>) -> String {
    let mut out = String::new();
    out.push_str("# Vigile SELinux module (STUB — phase 6)\n");
    out.push_str("# DO NOT USE IN PRODUCTION without manual review.\n\n");
    out.push_str("module vigile 1.0;\n\n");
    out.push_str("require {\n");
    let mut types: BTreeMap<&str, ()> = BTreeMap::new();
    for key in aggregated.keys() {
        // Extract type names from "src → dst (class)" format.
        let parts: Vec<&str> = key.split_whitespace().collect();
        if parts.len() >= 3 {
            types.insert(parts[0], ());
            types.insert(parts[2], ());
        }
    }
    for ty in types.keys() {
        out.push_str(&format!("\ttype {ty};\n"));
    }
    out.push_str("}\n\n");

    for (key, perms) in aggregated {
        out.push_str(&format!("# {key}\n"));
        for p in perms {
            out.push_str(&format!("# allow: {p}\n"));
        }
    }
    out
}

/// Gets the current SELinux mode (enforcing, permissive, disabled).
pub fn get_selinux_mode() -> Result<String, std::io::Error> {
    let mode = std::fs::read_to_string("/sys/fs/selinux/enforce")
        .or_else(|_| std::fs::read_to_string("/sys/module/apparmor/parameters/enabled"))
        .map(|s| s.trim().to_string())?;
    match mode.as_str() {
        "1" => Ok("enforcing".to_string()),
        "0" => Ok("permissive".to_string()),
        _ => Ok("disabled".to_string()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    const AVC_LINE: &str = "type=AVC msg=audit(1755859200.123:456): avc:  denied { read } for pid=1234 comm=\"httpd\" name=\"config.xml\" dev=\"sda1\" ino=12345 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:var_lib_t:s0 tclass=file permissive=1";

    #[test]
    fn parse_single_avc() {
        let d = parse_avc_line(AVC_LINE).expect("must parse");
        assert_eq!(d.pid, 1234);
        assert_eq!(d.comm, "httpd");
        assert_eq!(d.name, Some("config.xml".to_string()));
        assert_eq!(d.permissions, vec!["read"]);
        assert_eq!(d.scontext.type_name, "httpd_t");
        assert_eq!(d.tcontext.type_name, "var_lib_t");
        assert!(d.permissive);
    }

    #[test]
    fn parse_multiple_permissions() {
        let line = AVC_LINE.replace("{ read }", "{ read write open }");
        let d = parse_avc_line(&line).expect("must parse");
        assert_eq!(d.permissions.len(), 3);
        assert!(d.permissions.contains(&"read".to_string()));
        assert!(d.permissions.contains(&"write".to_string()));
    }

    #[test]
    fn parse_hostile_lines() {
        assert!(parse_avc_line("").is_none());
        assert!(parse_avc_line("not avc").is_none());
        assert!(parse_avc_line("type=AVC msg=audit(no denied here)").is_none());
        assert!(parse_avc_line("random garbage").is_none());
    }

    #[test]
    fn context_parsing() {
        let ctx = SecurityContext::parse("system_u:system_r:httpd_t:s0").expect("ctx");
        assert_eq!(ctx.user, "system_u");
        assert_eq!(ctx.role, "system_r");
        assert_eq!(ctx.type_name, "httpd_t");
        assert_eq!(ctx.level, "s0");
        assert_eq!(ctx.to_context_string(), "system_u:system_r:httpd_t:s0");

        assert!(SecurityContext::parse("bad").is_none());
        assert!(SecurityContext::parse("").is_none());
    }

    #[test]
    fn aggregation() {
        let d1 = parse_avc_line(AVC_LINE).unwrap();
        let d2 = parse_avc_line(&AVC_LINE.replace("pid=1234", "pid=5678")).unwrap();
        let aggregated = aggregate_denials(&[d1, d2]);
        // Same scontext → tcontext → single entry.
        assert_eq!(aggregated.len(), 1);
        let (key, perms) = aggregated.iter().next().unwrap();
        assert!(key.contains("httpd_t → var_lib_t"));
        assert_eq!(perms.len(), 1); // deduplicated
    }

    #[test]
    fn module_stub_generation() {
        let d = parse_avc_line(AVC_LINE).unwrap();
        let aggregated = aggregate_denials(&[d]);
        let module = generate_module_stub(&aggregated);
        assert!(module.contains("module vigile 1.0;"));
        assert!(module.contains("STUB"));
        assert!(module.contains("DO NOT USE"));
    }

    #[test]
    fn audit_output_parsing() {
        let output = format!(
            "type=SYSCALL msg=audit(1:1): syscall\n{}\ntype=SYSCALL msg=audit(2:2)\n",
            AVC_LINE
        );
        let denials = parse_audit_output(&output);
        assert_eq!(denials.len(), 1);
    }
}
