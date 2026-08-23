// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vigile server binary entry point (ISS-030).

fn main() {
    println!(
        "vigile-server {} (skeleton + HTTP/mTLS — see lib.rs for the real server)",
        env!("CARGO_PKG_VERSION")
    );
    println!("Use the library API to start the server programmatically.");
    println!("A proper CLI/config parser arrives with ISS-031.");
}
