// SPDX-License-Identifier: AGPL-3.0-or-later
//! Package inventory adapter — dnf/rpm family (ISS-018, FR-102).
//!
//! Two signature generations coexist:
//! - legacy `%{SIGPGP:pgpsig}` (rpm < 6): human-readable
//!   `RSA/SHA256, …, Key ID <hex>`;
//! - `%{OPENPGP}` (rpm >= 6, e.g. Fedora 44 / rpm 6.0.2): a base64
//!   OpenPGP signature packet whose issuer Key ID lives in the issuer
//!   subpacket (type 16) — extracted by a minimal packet parser.
//!
//! The parser is pure and unit-tested (including a real rpm 6 sample);
//! the runner is a thin unprivileged `rpm -qa` wrapper (read-only, no
//! dnf metadata downloads — repo provenance via dnf is a later,
//! optional pass).

use serde::{Deserialize, Serialize};

/// One installed RPM package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpmPackage {
    pub name: String,
    /// Epoch:Version-Release.
    pub evr: String,
    pub arch: String,
    pub packager: String,
    /// Legacy signature summary (empty on rpm >= 6).
    pub signature: String,
    /// Base64 OpenPGP signature packet (empty on rpm < 6).
    pub openpgp: String,
}

impl RpmPackage {
    pub fn signed(&self) -> bool {
        self.signer().is_some()
    }

    /// The signing key id from either signature generation.
    pub fn signer(&self) -> Option<String> {
        legacy_key_id(&self.signature).or_else(|| openpgp_issuer_key_id(&self.openpgp))
    }
}

/// Field separator: ASCII unit separator, absent from rpm metadata
/// fields (tabs can appear in some packager strings).
const SEP: char = '\x1f';

/// `rpm -qa` query format matching [`RpmPackage`] fields (6 columns).
pub const RPM_QA_QUERY_FORMAT: &str = concat!(
    "%{NAME}\u{1f}%{EVR}\u{1f}%{ARCH}\u{1f}%{PACKAGER}\u{1f}",
    "%{SIGPGP:pgpsig}\u{1f}%{OPENPGP}\n"
);

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
        // Name and EVR are mandatory on any real package; signature
        // fields may legitimately be "(none)" or empty.
        if fields.len() != 6 || fields[0].is_empty() || fields[1].is_empty() {
            continue;
        }
        packages.push(RpmPackage {
            name: fields[0].to_string(),
            evr: fields[1].to_string(),
            arch: fields[2].to_string(),
            packager: fields[3].to_string(),
            signature: fields[4].to_string(),
            openpgp: fields[5].to_string(),
        });
    }
    packages
}

/// Key ID from a legacy `pgpsig` summary (`…, Key ID <hex>`).
pub fn legacy_key_id(signature: &str) -> Option<String> {
    signature
        .split("Key ID")
        .nth(1)?
        .split_whitespace()
        .next()
        .map(str::to_string)
        .filter(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Minimal base64 (standard alphabet, padded) decoder — enough for rpm's
/// OPENPGP tag; rejects invalid characters and wrong padding.
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bytes: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if bytes.is_empty() || bytes.len() % 4 == 1 {
        return None;
    }
    // rpm may emit unpadded base64 — pad to the next multiple of 4.
    while !bytes.len().is_multiple_of(4) {
        bytes.push(b'=');
    }
    let pad = bytes.iter().filter(|b| **b == b'=').count();
    if pad > 2 {
        return None;
    }
    if bytes[..bytes.len() - pad].contains(&b'=') {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let mut acc: u32 = 0;
        for (i, b) in chunk.iter().enumerate() {
            let v = if *b == b'=' {
                if i < 2 {
                    return None;
                }
                0
            } else {
                ALPHABET.iter().position(|a| a == b)? as u32
            };
            acc = (acc << 6) | v;
        }
        out.push((acc >> 16) as u8);
        if chunk[2] != b'=' {
            out.push((acc >> 8) as u8);
        }
        if chunk[3] != b'=' {
            out.push(acc as u8);
        }
    }
    Some(out)
}

/// Extracts the issuer Key ID (hex, 16 chars) from a base64 OpenPGP
/// signature packet as emitted by rpm's `%{OPENPGP}` tag (v4 packets,
/// old-format framing). Anything unexpected → `None` (fail-closed:
/// an unparseable signature is NOT treated as a known signer).
pub fn openpgp_issuer_key_id(b64: &str) -> Option<String> {
    if b64.is_empty() || b64 == "(none)" {
        return None;
    }
    let raw = base64_decode(b64)?;
    if raw.len() < 6 {
        return None;
    }
    // Old-format packet header: tag 2 (signature). Support length types
    // 0 (1 byte) and 1 (2 bytes) — rpm emits type 1.
    let (b0, rest) = (raw[0], &raw[1..]);
    if b0 & 0x40 != 0 {
        return None; // new-format framing: not what rpm emits
    }
    if (b0 >> 2) & 0x0f != 2 {
        return None;
    }
    let body: &[u8] = match b0 & 0x03 {
        0 => {
            let len = *rest.first()? as usize;
            &rest[1..][..len.min(rest.len().saturating_sub(1))]
        }
        1 => {
            if rest.len() < 2 {
                return None;
            }
            let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
            &rest[2..][..len.min(rest.len().saturating_sub(2))]
        }
        _ => return None,
    };
    // v4 signature body: ver, type, pkalgo, hashalgo, hashed_len(2),
    // hashed…, unhashed_len(2), unhashed…
    if body.len() < 6 || body[0] != 4 {
        return None;
    }
    let hashed_len = u16::from_be_bytes([body[4], body[5]]) as usize;
    let unhashed_at = 6 + hashed_len;
    if body.len() < unhashed_at + 2 {
        return None;
    }
    let unhashed_len = u16::from_be_bytes([body[unhashed_at], body[unhashed_at + 1]]) as usize;
    let subpackets_end = (unhashed_at + 2 + unhashed_len).min(body.len());
    let mut p = unhashed_at + 2;
    while p < subpackets_end {
        let len = body[p] as usize;
        p += 1;
        if len == 0 || p + len > subpackets_end {
            return None;
        }
        let stype = body[p] & 0x7f;
        if stype == 16 && len == 9 {
            let key_id: String = body[p + 1..p + 9]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            return Some(key_id);
        }
        p += len;
    }
    None
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

    fn line(name: &str, evr: &str, arch: &str, packager: &str, sig: &str, pgp: &str) -> String {
        format!("{name}{SEP}{evr}{SEP}{arch}{SEP}{packager}{SEP}{sig}{SEP}{pgp}\n")
    }

    #[test]
    fn parses_legacy_output() {
        let out = line(
            "bash",
            "5.2.26-3.fc44",
            "x86_64",
            "Fedora Project",
            "RSA/SHA256, Tue Apr 1 00:00:00 2026, Key ID eb10b4643f3f544d",
            "",
        );
        let packages = parse_rpm_qa(&out);
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "bash");
        assert!(packages[0].signed());
        assert_eq!(packages[0].signer().as_deref(), Some("eb10b4643f3f544d"));
    }

    #[test]
    fn unsigned_package_has_no_signer() {
        let out = line(
            "local-thing",
            "1.0-1",
            "noarch",
            "Nobody",
            "(none)",
            "(none)",
        );
        let packages = parse_rpm_qa(&out);
        assert_eq!(packages.len(), 1);
        assert!(!packages[0].signed());
        assert_eq!(packages[0].signer(), None);
    }

    // Real rpm 6.0.2 sample (Fedora 44, bash package) captured on
    // 2026-08-22 — expected issuer: the Fedora 44 primary key
    // (cross-checked with the GPG signature of the F44 image CHECKSUM).
    const RPM6_OPENPGP: &str = "iQIzBAABCAAdFiEENvYS3PJ/fRpIqDXk2/z3HG2fkKYFAmlvOzMACgkQ2/z3HG2fkKZEQQ/9G+RqIiKrRl/WaKnxkBqBNlcIosg2+M8KAfkCda87Jfqu1MTAKOrQlwlZ0n5Uq6JHExBq8I7o9KC0uaabR1oFaR3tG5+P90NO2+Kv0oLuIPtrzZp8kIq20QMvF3SoRyWK98SCcBH6pEaW+LxXScrNjO3lMpLRZbVJVzwp2JVlTiSvZsOGkFge9QegZ7o41D9GJILmffQ9JppnKU0nKD3Y9xVqDpdXFfMhj90gw5jwSgtUHlV6fJn/5CCQsMvs7z/sEfD7UN9bgOlRjGLSBn4jMdKyFM69jC6qPtlscKV0hGtnvcnVbIbVQGscCxN3I+RZR/AJp03zHUE1WaNtos8LJvnYHjBaW5+zDnMJF4Kq4mHogCGpTUqmMBcU05etDFQyDtZQEo77IE1TAPYe2DQHKvzxOh5hN7dYSoOVZIklTY8VEZzmkcVEnA630nDpS530REAxqdDjmfiDZ6cWiwiQUPJ//oKVz1CaHHcVQ90SBXUAafeAuSh+zPn4FLAf5ogO+RayD3FWYdchPE7yBwW9SqqWdUz8Yu9/5kdmCcMN6qPeQ4R1dUWe9HYBvSPs5U0laEwzRhcaT5xvhDaHvj+AI8UY+mJ3ZpUHrZLLgQI8ESpH74q6hmW2S/LaW8qtBA3SmnUxSyTNf2C/cldAdgbh5A45+WchoDiVHJxLRSjLzsM=";

    #[test]
    fn rpm6_openpgp_issuer_extracted() {
        assert_eq!(
            openpgp_issuer_key_id(RPM6_OPENPGP).as_deref(),
            Some("dbfcf71c6d9f90a6")
        );
        // Through the package API too.
        let out = line(
            "bash",
            "5.2.26-3.fc44",
            "x86_64",
            "Fedora Project",
            "",
            RPM6_OPENPGP,
        );
        let packages = parse_rpm_qa(&out);
        assert!(packages[0].signed());
        assert_eq!(packages[0].signer().as_deref(), Some("dbfcf71c6d9f90a6"));
    }

    #[test]
    fn hostile_openpgp_inputs_return_none() {
        assert_eq!(openpgp_issuer_key_id(""), None);
        assert_eq!(openpgp_issuer_key_id("(none)"), None);
        assert_eq!(openpgp_issuer_key_id("!!!not-base64!!!"), None);
        assert_eq!(openpgp_issuer_key_id("AAAA"), None); // too short packet
                                                         // Valid base64 of junk ("hello world!") — not a v4 signature.
        assert_eq!(openpgp_issuer_key_id("aGVsbG8gd29ybGQh"), None);
    }

    #[test]
    fn hostile_output_never_panics() {
        // Wrong field counts, empty lines, junk, all-empty fields.
        let out = "onlyonefield\n\na\x1fb\x1fc\n\x1f\x1f\x1f\x1f\x1f\x1f\ntrailing";
        let packages = parse_rpm_qa(out);
        assert!(packages.is_empty());
    }

    #[test]
    fn query_format_has_six_fields() {
        assert_eq!(RPM_QA_QUERY_FORMAT.matches(SEP).count(), 5);
        assert!(RPM_QA_QUERY_FORMAT.ends_with('\n'));
    }

    #[test]
    fn base64_decoder_accepts_unpadded_input() {
        // 3-char groups are valid unpadded base64 ("QUJ" == "QUJ=").
        assert_eq!(base64_decode("QUJD").as_deref(), Some(b"ABC".as_slice()));
        assert_eq!(base64_decode("QUJ").as_deref(), Some(b"AB".as_slice()));
        assert_eq!(base64_decode("QQ").as_deref(), Some(b"A".as_slice()));
        // mod 4 == 1 is structurally impossible in base64.
        assert_eq!(base64_decode("QUJDA"), None);
    }

    #[test]
    fn base64_decoder_basics() {
        assert_eq!(base64_decode("QQ==").as_deref(), Some(b"A".as_slice()));
        assert_eq!(base64_decode("QUI=").as_deref(), Some(b"AB".as_slice()));
        assert_eq!(base64_decode("QUJD").as_deref(), Some(b"ABC".as_slice()));
        assert_eq!(base64_decode("===="), None);
        assert_eq!(base64_decode("A==="), None);
    }
}
