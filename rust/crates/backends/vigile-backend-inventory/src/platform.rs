// SPDX-License-Identifier: AGPL-3.0-or-later
//! Platform detection (ISS-017): `/etc/os-release` parsing (spec at
//! https://www.freedesktop.org/software/systemd/man/os-release.html) and
//! distribution-family resolution.
//!
//! Pure and testable: parsing works on any string, reading works under a
//! virtual root (tests build fake filesystems).

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Parsed `/etc/os-release` (subset of the spec used by Vigile).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsRelease {
    pub id: String,
    pub id_like: Vec<String>,
    pub version_id: String,
    pub name: String,
}

/// Parses the content of an os-release file. Unknown keys are ignored;
/// malformed lines are ignored (the spec allows future keys); values may
/// be quoted with `"` or `'`.
pub fn parse_os_release(content: &str) -> OsRelease {
    let mut out = OsRelease::default();
    for line in content.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.is_empty() || key.contains(char::is_whitespace) {
            continue;
        }
        let value = unquote(value.trim());
        match key {
            "ID" => out.id = value.to_lowercase(),
            "ID_LIKE" => out.id_like = value.split_whitespace().map(|s| s.to_lowercase()).collect(),
            "VERSION_ID" => out.version_id = value,
            "NAME" => out.name = value,
            _ => {}
        }
    }
    out
}

fn unquote(v: &str) -> String {
    let bytes = v.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return v[1..v.len() - 1].to_string();
        }
    }
    v.to_string()
}

/// Reads `<root>/etc/os-release` (falling back to `/usr/lib/os-release`
/// per the spec).
pub fn read_os_release(root: &Path) -> Result<OsRelease, std::io::Error> {
    let primary = root.join("etc/os-release");
    let fallback = root.join("usr/lib/os-release");
    let path = if primary.exists() { primary } else { fallback };
    let content = std::fs::read_to_string(path)?;
    Ok(parse_os_release(&content))
}

/// Distribution families used by the capability matrix. Matching is by
/// `ID` then `ID_LIKE`, most specific first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DistroFamily {
    Fedora,
    RhelFamily,
    Debian,
    Ubuntu,
    NixOs,
    Unknown,
}

pub fn resolve_family(os: &OsRelease) -> DistroFamily {
    let ids: Vec<&str> = std::iter::once(os.id.as_str())
        .chain(os.id_like.iter().map(String::as_str))
        .collect();
    // Order matters: ubuntu before debian (Ubuntu declares ID_LIKE=debian).
    for id in &ids {
        match *id {
            "ubuntu" => return DistroFamily::Ubuntu,
            "fedora" => return DistroFamily::Fedora,
            "rhel" | "centos" | "rocky" | "almalinux" | "rhel_like" => {
                return DistroFamily::RhelFamily
            }
            "debian" => return DistroFamily::Debian,
            "nixos" => return DistroFamily::NixOs,
            _ => {}
        }
    }
    DistroFamily::Unknown
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    const FEDORA_44: &str = r#"
NAME="Fedora Linux"
VERSION="44 (Forty Four)"
ID=fedora
VERSION_ID=44
ID_LIKE="rhel fedora"
"#;

    #[test]
    fn parses_fedora() {
        let os = parse_os_release(FEDORA_44);
        assert_eq!(os.id, "fedora");
        assert_eq!(os.version_id, "44");
        assert_eq!(os.id_like, vec!["rhel", "fedora"]);
        assert_eq!(os.name, "Fedora Linux");
    }

    #[test]
    fn ignores_malformed_lines_and_unknown_keys() {
        let os = parse_os_release("not-a-pair\n=empty\nID=debian\nFUTURE_KEY=x\nANOTHER");
        assert_eq!(os.id, "debian");
        assert_eq!(os.version_id, "");
    }

    #[test]
    fn unquotes_single_and_double() {
        let os = parse_os_release("NAME='Debian GNU/Linux'\nVERSION_ID=\"13\"");
        assert_eq!(os.name, "Debian GNU/Linux");
        assert_eq!(os.version_id, "13");
    }

    #[test]
    fn families() {
        let mk = |id: &str, like: &str| parse_os_release(&format!("ID={id}\nID_LIKE={like}"));
        assert_eq!(resolve_family(&mk("fedora", "")), DistroFamily::Fedora);
        assert_eq!(
            resolve_family(&mk("rocky", "rhel centos fedora")),
            DistroFamily::RhelFamily
        );
        assert_eq!(
            resolve_family(&mk("ubuntu", "debian")),
            DistroFamily::Ubuntu
        );
        assert_eq!(resolve_family(&mk("debian", "")), DistroFamily::Debian);
        assert_eq!(resolve_family(&mk("nixos", "")), DistroFamily::NixOs);
        assert_eq!(resolve_family(&mk("arch", "")), DistroFamily::Unknown);
    }
}
