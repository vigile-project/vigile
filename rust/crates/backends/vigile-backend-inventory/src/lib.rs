// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vigile inventory backend (M2, ISS-017..022): platform and capability
//! detection, package/executable/script inventory, bounded event spool.
//! Metadata only — never file contents (SEC-1001).

pub mod capabilities;
pub mod exec_detection;
pub mod packages;
pub mod platform;

pub use capabilities::{
    detect_capabilities, CapabilityReport, CapabilitySpec, DetectedCapability, CAPABILITY_MATRIX,
};
pub use exec_detection::{
    classify, effective_interpreter, interpreter_family, is_elf, parse_shebang, FileKind,
    Interpreter, Shebang,
};
pub use packages::{parse_rpm_qa, run_rpm_qa, signer_key_id, RpmPackage, RPM_QA_QUERY_FORMAT};
pub use platform::{parse_os_release, read_os_release, resolve_family, DistroFamily, OsRelease};

/// Capability support levels, mirroring docs/DISTRIBUTION_COMPATIBILITY.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportLevel {
    Supported,
    SupportedWithLimitations,
    Experimental,
    Unavailable,
    UnsafeToEnable,
}
