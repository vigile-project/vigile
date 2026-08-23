// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vigile inventory backend — capability detection and asset inventory
//! (FR-101..108, issues ISS-017..022). Skeleton only.

/// Capability support levels, mirroring docs/DISTRIBUTION_COMPATIBILITY.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportLevel {
    Supported,
    SupportedWithLimitations,
    Experimental,
    Unavailable,
    UnsafeToEnable,
}
