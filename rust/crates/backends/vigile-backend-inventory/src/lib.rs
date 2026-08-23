// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vigile inventory backend (M2, ISS-017..022): platform and capability
//! detection, package/executable/script inventory, bounded event spool.
//! Metadata only — never file contents (SEC-1001).

pub mod capabilities;
pub mod exec_detection;
pub mod executables;
pub mod journal;
pub mod outbox;
pub mod packages;
pub mod platform;
pub mod spool;

pub use capabilities::{
    detect_capabilities, CapabilityReport, CapabilitySpec, DetectedCapability, CAPABILITY_MATRIX,
};
pub use exec_detection::{
    classify, effective_interpreter, interpreter_family, is_elf, parse_shebang, FileKind,
    Interpreter, Shebang,
};
pub use executables::{scan, ExecutableEntry, ScanReport, DEFAULT_SCAN_ROOTS, MAX_FILES};
pub use journal::{parse_output, parse_record, run_journalctl, JournalRecord};
pub use outbox::{backoff_with_jitter, InventoryDiff};
pub use packages::{
    base64_decode, legacy_key_id, openpgp_issuer_key_id, parse_rpm_qa, run_rpm_qa, RpmPackage,
    RPM_QA_QUERY_FORMAT,
};
pub use platform::{parse_os_release, read_os_release, resolve_family, DistroFamily, OsRelease};
pub use spool::{Priority, PrioritySpool, SpoolStats, SpooledEvent};

/// Capability support levels, mirroring docs/DISTRIBUTION_COMPATIBILITY.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupportLevel {
    Supported,
    SupportedWithLimitations,
    Experimental,
    Unavailable,
    UnsafeToEnable,
}
