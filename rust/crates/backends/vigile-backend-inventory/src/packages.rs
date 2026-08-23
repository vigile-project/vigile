// SPDX-License-Identifier: AGPL-3.0-or-later
//! Package inventory adapter — dnf/rpm family (ISS-018, FR-102).
//!
//! Strategy: the unprivileged agent shells out to `rpm -qa` (read-only,
//! no dnf metadata downloads — repo provenance via dnf is a later,
//! optional pass). The parser is pure and unit-tested; the runner is a
//! thin `std::process::Command` wrapper (not exercised by unit tests —
//! the lab VM covers it).

/// One installed RPM package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpmPackage {
    pub name: String,
    /// Epoch:Version-Release.
    pub evr: String,
    pub arch: String,
    pub packager: String,
    /// Signature summary, e.g. `RSA/SHA256, …, Key ID 1234567890abcdef`.
    pub signature: String,
}

/// PGP key id extracted from the signature summary, when present.
pub fn signer_key_id(signature: &str) -> Option<String> {
    signature
        .split("Key ID")
        .nth(1)?
        .split_whitespace()
        .next()
        .map(str::to_string)
        .filter(|id| !id.is_empty())
}

/// Field separator: ASCII unit separator, absent from rpm metadata
/// fields (tabs can appear in some packager strings).
const SEP: char = '\x1f';

/// `rpm -qa` query format matching [`RpmPackage`] fields.
pub const RPM_QA_QUERY_FORMAT: &str =
    "%{NAME}\u{1f}%{EVR}\u{1f}%{ARCH}\u{1f}%{PACKAGER}\u{1f}%{SIGPGP:pgpsig}\n";

/// Parses `rpm -qa --qf <RPM_QA_QUERY_FORMAT>` output. Malformed lines
/// (wrong field count) are skipped, never fatal — inventory must stay
/// complete even if one package prints odd metadata.
pub fn parse_rpm_qa(output: &str) -> Vec<RpmPackage> {
    let mut packages = Vec::new();
    for line in output.lines() {
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split(SEP).collect();
        // Name and EVR are mandatory on any real package; everything
        // else may legitimately be "(none)".
        if fields.len() != 5 || fields[0].is_empty() || fields[1].is_empty() {
            continue;
        }
        packages.push(RpmPackage {
            name: fields[0].to_string(),
            evr: fields[1].to_string(),
            arch: fields[2].to_string(),
            packager: fields[3].to_string(),
            signature: fields[4].to_string(),
        });
    }
    packages
}

/// Runs `rpm -qa` on the live system. Returns the raw output for
/// [`parse_rpm_qa`].
pub fn run_rpm_qa() -> Result<String, std::io::Error> {
    let output = std::process::Command::new("rpm")
        .args(["-qa", "--qf", RPM_QA_QUERY_FORMAT])
        .output()?;
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "rpm -qa failed with status {}",
            output.status.code().unwrap_or(-1)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    fn line(name: &str, evr: &str, arch: &str, packager: &str, sig: &str) -> String {
        format!("{name}{SEP}{evr}{SEP}{arch}{SEP}{packager}{SEP}{sig}\n")
    }

    #[test]
    fn parses_nominal_output() {
        let out = line(
            "bash",
            "5.2.26-3.fc44",
            "x86_64",
            "Fedora Project",
            "RSA/SHA256, Tue Apr 1 00:00:00 2026, Key ID eb10b4643f3f544d",
        ) + &line(
            "python3",
            "3.13.1-1.fc44",
            "x86_64",
            "Fedora Project",
            "RSA/SHA256, Tue Apr 2 00:00:00 2026, Key ID eb10b4643f3f544d",
        );
        let packages = parse_rpm_qa(&out);
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "bash");
        assert_eq!(packages[0].evr, "5.2.26-3.fc44");
        assert_eq!(
            signer_key_id(&packages[0].signature).as_deref(),
            Some("eb10b4643f3f544d")
        );
    }

    #[test]
    fn unsigned_package_has_empty_signature() {
        let out = line("local-thing", "1.0-1", "noarch", "Nobody", "(none)");
        let packages = parse_rpm_qa(&out);
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].signature, "(none)");
        assert_eq!(signer_key_id("(none)"), None);
    }

    #[test]
    fn hostile_output_never_panics() {
        // Wrong field counts, empty lines, junk.
        let out = "onlyonefield\n\na\x1fb\x1fc\n\x1f\x1f\x1f\x1f\ntrailing";
        let packages = parse_rpm_qa(out);
        assert!(packages.is_empty());
    }

    #[test]
    fn query_format_has_five_fields() {
        assert_eq!(RPM_QA_QUERY_FORMAT.matches(SEP).count(), 4);
        assert!(RPM_QA_QUERY_FORMAT.ends_with('\n'));
    }
}
