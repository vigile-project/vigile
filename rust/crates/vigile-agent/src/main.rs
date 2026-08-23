// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vigile agent — unprivileged system service (ADR-0002).
//!
//! Skeleton only (sprint 1, ISS-001). No networking, no enrollment, no
//! policy handling yet: those land with ISS-011..022.

fn main() {
    println!(
        "vigile-agent {} (skeleton — no functionality yet)",
        env!("CARGO_PKG_VERSION")
    );
}
