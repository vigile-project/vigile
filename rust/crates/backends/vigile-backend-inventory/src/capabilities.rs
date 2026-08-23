// SPDX-License-Identifier: AGPL-3.0-or-later
//! Capability detection (ISS-017, FR-101): the embedded matrix mirrors
//! `docs/DISTRIBUTION_COMPATIBILITY.md`. The matrix will become a signed
//! artifact loaded from the policy channel (phase 2); until then it is
//! compiled in and every level it declares is cross-checked against
//! local presence — a backend declared `supported` but absent locally is
//! reported `unavailable`, never assumed (SEC-603).

use crate::platform::{resolve_family, DistroFamily, OsRelease};
use crate::SupportLevel;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// One row of the capability matrix + how to probe local presence.
pub struct CapabilitySpec {
    pub backend: &'static str,
    pub fedora: SupportLevel,
    pub rhel_family: SupportLevel,
    pub debian: SupportLevel,
    pub ubuntu: SupportLevel,
    pub nixos: SupportLevel,
    /// Presence is reported if ANY of these paths exists (heuristics,
    /// refined by the lab VM as backends land).
    pub probe_paths: &'static [&'static str],
}

const S: SupportLevel = SupportLevel::Supported;
const S_LIM: SupportLevel = SupportLevel::SupportedWithLimitations;
const EXP: SupportLevel = SupportLevel::Experimental;
const UNAVAIL: SupportLevel = SupportLevel::Unavailable;
const UNSAFE: SupportLevel = SupportLevel::UnsafeToEnable;

/// Embedded matrix — mirror of docs/DISTRIBUTION_COMPATIBILITY.md §2.
pub const CAPABILITY_MATRIX: &[CapabilitySpec] = &[
    CapabilitySpec {
        backend: "fapolicyd",
        fedora: S,
        rhel_family: S_LIM,
        debian: S_LIM,
        ubuntu: S_LIM,
        nixos: UNAVAIL,
        probe_paths: &["usr/sbin/fapolicyd", "usr/bin/fapolicyd", "etc/fapolicyd"],
    },
    CapabilitySpec {
        backend: "selinux",
        fedora: S,
        rhel_family: S,
        debian: UNSAFE,
        ubuntu: UNSAFE,
        nixos: UNAVAIL,
        probe_paths: &["sys/fs/selinux", "usr/sbin/selinuxenabled"],
    },
    CapabilitySpec {
        backend: "apparmor",
        fedora: EXP,
        rhel_family: EXP,
        debian: S_LIM,
        ubuntu: S,
        nixos: UNAVAIL,
        probe_paths: &["sys/module/apparmor/parameters/enabled"],
    },
    CapabilitySpec {
        backend: "nftables",
        fedora: S,
        rhel_family: S,
        debian: S,
        ubuntu: S_LIM,
        nixos: S,
        probe_paths: &["usr/sbin/nft", "usr/bin/nft"],
    },
    CapabilitySpec {
        backend: "usbguard",
        fedora: S_LIM,
        rhel_family: S_LIM,
        debian: S_LIM,
        ubuntu: S_LIM,
        nixos: EXP,
        probe_paths: &["usr/sbin/usbguard-daemon", "usr/bin/usbguard-daemon"],
    },
    CapabilitySpec {
        backend: "ima-evm",
        fedora: EXP,
        rhel_family: EXP,
        debian: EXP,
        ubuntu: EXP,
        nixos: EXP,
        probe_paths: &["sys/kernel/security/ima"],
    },
    CapabilitySpec {
        backend: "fs-verity",
        fedora: S_LIM,
        rhel_family: S_LIM,
        debian: S_LIM,
        ubuntu: S_LIM,
        nixos: S_LIM,
        probe_paths: &["proc/sys/fs/verity"],
    },
    CapabilitySpec {
        backend: "tpm2",
        fedora: S_LIM,
        rhel_family: S_LIM,
        debian: S_LIM,
        ubuntu: S_LIM,
        nixos: S_LIM,
        probe_paths: &["dev/tpm0", "dev/tpmrm0"],
    },
];

/// A detected capability: what the matrix declares for the running
/// family, whether the backend is present locally, and the effective
/// level actually used (declared ∧ present).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedCapability {
    pub backend: String,
    pub declared: SupportLevel,
    pub present_locally: bool,
    pub effective: SupportLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityReport {
    pub os: OsRelease,
    pub family: DistroFamily,
    pub capabilities: Vec<DetectedCapability>,
}

impl CapabilitySpec {
    pub fn level_for(&self, family: DistroFamily) -> SupportLevel {
        match family {
            DistroFamily::Fedora => self.fedora,
            DistroFamily::RhelFamily => self.rhel_family,
            DistroFamily::Debian => self.debian,
            DistroFamily::Ubuntu => self.ubuntu,
            DistroFamily::NixOs => self.nixos,
            DistroFamily::Unknown => SupportLevel::Unavailable,
        }
    }
}

/// Detects capabilities under `root` (pass `/` on a real system, a fake
/// tree in tests). An unknown family yields everything `unavailable` —
/// clean refusal, never simulation (ADR-0009).
pub fn detect_capabilities(root: &Path, os: &OsRelease) -> CapabilityReport {
    let family = resolve_family(os);
    let capabilities = CAPABILITY_MATRIX
        .iter()
        .map(|spec| {
            let declared = spec.level_for(family);
            let present_locally = spec.probe_paths.iter().any(|rel| root.join(rel).exists());
            let effective = if present_locally {
                declared
            } else {
                SupportLevel::Unavailable
            };
            DetectedCapability {
                backend: spec.backend.to_string(),
                declared,
                present_locally,
                effective,
            }
        })
        .collect();
    CapabilityReport {
        os: os.clone(),
        family,
        capabilities,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;
    use crate::platform::parse_os_release;

    const FEDORA: &str = "ID=fedora\nVERSION_ID=44\n";

    #[test]
    fn matrix_is_non_empty_and_unique() {
        assert!(CAPABILITY_MATRIX.len() >= 8);
        for (i, spec) in CAPABILITY_MATRIX.iter().enumerate() {
            assert!(
                CAPABILITY_MATRIX[i + 1..]
                    .iter()
                    .all(|other| other.backend != spec.backend),
                "duplicate backend {}",
                spec.backend
            );
        }
    }

    #[test]
    fn declared_supported_but_absent_reports_unavailable() {
        let os = parse_os_release(FEDORA);
        // Empty root: nothing exists locally.
        let root = std::env::temp_dir().join(format!("vigile-cap-empty-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let report = detect_capabilities(&root, &os);
        let fapolicyd = report
            .capabilities
            .iter()
            .find(|c| c.backend == "fapolicyd")
            .unwrap();
        assert_eq!(fapolicyd.declared, SupportLevel::Supported);
        assert!(!fapolicyd.present_locally);
        assert_eq!(fapolicyd.effective, SupportLevel::Unavailable);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn present_backend_keeps_declared_level() {
        let os = parse_os_release(FEDORA);
        let root = std::env::temp_dir().join(format!("vigile-cap-f44-{}", std::process::id()));
        std::fs::create_dir_all(root.join("etc/fapolicyd")).unwrap();
        std::fs::create_dir_all(root.join("usr/sbin")).unwrap();
        std::fs::write(root.join("usr/sbin/fapolicyd"), b"#!/bin/sh\n").unwrap();
        std::fs::create_dir_all(root.join("sys/fs/selinux")).unwrap();

        let report = detect_capabilities(&root, &os);
        let fapolicyd = report
            .capabilities
            .iter()
            .find(|c| c.backend == "fapolicyd")
            .unwrap();
        assert!(fapolicyd.present_locally);
        assert_eq!(fapolicyd.effective, SupportLevel::Supported);
        let selinux = report
            .capabilities
            .iter()
            .find(|c| c.backend == "selinux")
            .unwrap();
        assert_eq!(selinux.effective, SupportLevel::Supported);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn debian_selinux_stays_unsafe_to_enable_even_if_present() {
        let os = parse_os_release("ID=debian\nVERSION_ID=13\n");
        let root = std::env::temp_dir().join(format!("vigile-cap-deb-{}", std::process::id()));
        std::fs::create_dir_all(root.join("sys/fs/selinux")).unwrap();
        let report = detect_capabilities(&root, &os);
        let selinux = report
            .capabilities
            .iter()
            .find(|c| c.backend == "selinux")
            .unwrap();
        assert_eq!(selinux.declared, SupportLevel::UnsafeToEnable);
        assert!(selinux.present_locally);
        assert_eq!(selinux.effective, SupportLevel::UnsafeToEnable);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn unknown_family_refuses_everything() {
        let os = parse_os_release("ID=arch\n");
        let report = detect_capabilities(Path::new("/"), &os);
        assert_eq!(report.family, DistroFamily::Unknown);
        assert!(report
            .capabilities
            .iter()
            .all(|c| c.effective == SupportLevel::Unavailable));
    }
}
