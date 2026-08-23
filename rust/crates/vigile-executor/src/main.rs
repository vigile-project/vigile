// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vigile executor binary — the privileged component that applies
//! artifacts via the IPC protocol.

fn main() {
    println!(
        "vigile-executor {} (transactional executor — see lib.rs)",
        env!("CARGO_PKG_VERSION")
    );
    println!("The binary entry point (socket listener) arrives with ISS-041.");
}
