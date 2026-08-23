// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vigile fapolicyd backend (phases 2–3).
//!
//! Skeleton only. Actual rule generation lands with ISS-023 (compiler) and
//! ISS-035 (audit-only application). Capacities of the real fapolicyd
//! (memfd, namespaces, interpreter coverage) MUST be measured by spike
//! ISS-008 before anything is claimed — currently NON VÉRIFIÉ
//! (RISK-04).

/// Backend identifier used in capability manifests.
pub const BACKEND_ID: &str = "fapolicyd";
