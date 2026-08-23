// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vigile executor — minimal privileged component (ADR-0002).
//!
//! Skeleton only (sprint 1, ISS-001). This binary must NEVER gain generic
//! capabilities: the action catalogue is closed and versioned
//! (`vigile-ipc`, docs/AGENT_PROTOCOL.md §6). No shell, no arbitrary paths,
//! no unsigned configuration — enforced by review and tests from ISS-038.

fn main() {
    println!(
        "vigile-executor {} (skeleton — performs nothing, holds no privileges)",
        env!("CARGO_PKG_VERSION")
    );
}
