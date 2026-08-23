// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vigile signer — isolated signing service (trust boundary TB-5).
//!
//! Skeleton only (sprint 1, ISS-001). Will never hold root keys, never run
//! unattended, and log every signature (ISS-028). Human-only operation per
//! the project charter §27.

fn main() {
    println!(
        "vigile-signer {} (skeleton — holds no keys, signs nothing)",
        env!("CARGO_PKG_VERSION")
    );
}
