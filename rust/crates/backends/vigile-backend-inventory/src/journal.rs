// SPDX-License-Identifier: AGPL-3.0-or-later
//! journald collection (ISS-021, FR-601): parse `journalctl -o json`
//! NDJSON output. Pure parser, hostile-input safe; the runner is a thin
//! unprivileged subprocess wrapper covered by the lab VM.

use serde::{Deserialize, Serialize};

/// One journal record (subset used by Vigile).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalRecord {
    /// Unix microseconds (`__REALTIME_TIMESTAMP`).
    pub realtime_us: u64,
    pub message: String,
    /// `_SYSTEMD_UNIT` or `SYSLOG_IDENTIFIER`, when present.
    pub unit: Option<String>,
    /// syslog priority, when present.
    pub priority: Option<u8>,
}

#[derive(Deserialize)]
struct RawRecord {
    #[serde(rename = "__REALTIME_TIMESTAMP")]
    realtime_us: serde_json::Value,
    #[serde(rename = "MESSAGE")]
    message: serde_json::Value,
    #[serde(rename = "_SYSTEMD_UNIT")]
    system_unit: Option<serde_json::Value>,
    #[serde(rename = "SYSLOG_IDENTIFIER")]
    syslog_identifier: Option<serde_json::Value>,
    #[serde(rename = "PRIORITY")]
    priority: Option<serde_json::Value>,
}

/// Values in journal JSON can be strings or arrays of bytes (non-UTF8
/// fields); normalize both to Option<String>.
fn value_to_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Array(bytes) => {
            // Array of byte numbers (journald's representation of
            // non-UTF8 data) — keep it lossless as a decimal list.
            let parts: Vec<String> = bytes.iter().map(|b| b.to_string()).collect();
            Some(format!("[{}]", parts.join(",")))
        }
        _ => None,
    }
}

fn value_to_u64(v: &serde_json::Value) -> Option<u64> {
    match v {
        serde_json::Value::String(s) => s.parse().ok(),
        serde_json::Value::Number(n) => n.as_u64(),
        _ => None,
    }
}

/// Parses one NDJSON line. Returns None for records without a usable
/// timestamp or message.
pub fn parse_record(line: &str) -> Option<JournalRecord> {
    let raw: RawRecord = serde_json::from_str(line).ok()?;
    let realtime_us = value_to_u64(&raw.realtime_us)?;
    let message = value_to_string(&raw.message)?;
    if message.is_empty() {
        return None;
    }
    let unit = raw
        .system_unit
        .as_ref()
        .and_then(value_to_string)
        .or_else(|| raw.syslog_identifier.as_ref().and_then(value_to_string));
    let priority = raw
        .priority
        .as_ref()
        .and_then(value_to_u64)
        .and_then(|p| u8::try_from(p).ok());
    Some(JournalRecord {
        realtime_us,
        message,
        unit,
        priority,
    })
}

/// Parses a full `journalctl -o json` output. Invalid lines are counted,
/// never fatal — an event stream must keep flowing (FM-17).
pub fn parse_output(output: &str) -> (Vec<JournalRecord>, usize) {
    let mut records = Vec::new();
    let mut invalid = 0usize;
    for line in output.lines() {
        if line.is_empty() {
            continue;
        }
        match parse_record(line) {
            Some(record) => records.push(record),
            None => invalid += 1,
        }
    }
    (records, invalid)
}

/// Thin runner: `journalctl -o json <extra args>` (unprivileged, read
/// from the system journal the agent user can see).
pub fn run_journalctl(extra_args: &[&str]) -> Result<String, std::io::Error> {
    let mut cmd = std::process::Command::new("journalctl");
    cmd.arg("-o").arg("json").args(extra_args);
    let output = cmd.output()?;
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "journalctl failed with status {}",
            output.status.code().unwrap_or(-1)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    fn line(ts: &str, msg: &str, unit: Option<&str>) -> String {
        let unit_json = match unit {
            Some(u) => format!(r#","_SYSTEMD_UNIT":"{u}""#),
            None => String::new(),
        };
        format!(r#"{{"__REALTIME_TIMESTAMP":"{ts}","MESSAGE":"{msg}"{unit_json}}}"#)
    }

    #[test]
    fn parses_nominal_records() {
        let out = format!(
            "{}\n{}\n",
            line(
                "1755859200000000",
                "fapolicyd denial",
                Some("fapolicyd.service")
            ),
            line("1755859201000000", "unit started", Some("sshd.service")),
        );
        let (records, invalid) = parse_output(&out);
        assert_eq!(invalid, 0);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].message, "fapolicyd denial");
        assert_eq!(records[0].unit.as_deref(), Some("fapolicyd.service"));
        assert_eq!(records[0].realtime_us, 1_755_859_200_000_000);
    }

    #[test]
    fn syslog_identifier_used_when_no_unit() {
        let rec = parse_record(
            r#"{"__REALTIME_TIMESTAMP":"1","MESSAGE":"m","SYSLOG_IDENTIFIER":"sshd"}"#,
        )
        .unwrap();
        assert_eq!(rec.unit.as_deref(), Some("sshd"));
    }

    #[test]
    fn priority_parsed() {
        let rec =
            parse_record(r#"{"__REALTIME_TIMESTAMP":"1","MESSAGE":"m","PRIORITY":"3"}"#).unwrap();
        assert_eq!(rec.priority, Some(3));
    }

    #[test]
    fn hostile_lines_counted_not_fatal() {
        let out = "not json\n{\"MESSAGE\":\"no ts\"}\n\n[]\n{}\n";
        let (records, invalid) = parse_output(out);
        assert!(records.is_empty());
        assert_eq!(invalid, 4);
    }

    #[test]
    fn byte_array_message_is_kept_lossless() {
        let rec = parse_record(r#"{"__REALTIME_TIMESTAMP":"7","MESSAGE":[104,105]}"#).unwrap();
        assert_eq!(rec.message, "[104,105]");
    }
}
