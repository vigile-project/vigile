// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vigile agent binary.
//!
//! Subcommands:
//!   inventory  — full system inventory report (JSON)
//!   sync <url> — connect to server, get policy (stub)
//!   status     — show local state

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("inventory") => cmd_inventory(),
        Some("sync") => cmd_sync(args.get(1)),
        Some("status") => cmd_status(),
        _ => {
            eprintln!(
                "vigile-agent {}\n\
                 usage:\n  vigile-agent inventory\n  vigile-agent sync <server-url>\n  vigile-agent status",
                env!("CARGO_PKG_VERSION")
            );
            std::process::exit(2);
        }
    }
}

fn cmd_inventory() {
    let root = std::path::Path::new("/");
    let os = match vigile_backend_inventory::read_os_release(root) {
        Ok(os) => os,
        Err(e) => {
            eprintln!("cannot read /etc/os-release: {e}");
            std::process::exit(1);
        }
    };
    let cap_report = vigile_backend_inventory::detect_capabilities(root, &os);
    let home: Option<std::path::PathBuf> = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let exec_report = vigile_backend_inventory::scan(
        root,
        vigile_backend_inventory::DEFAULT_SCAN_ROOTS,
        home.as_deref(),
    );
    let pkgs = match vigile_backend_inventory::run_rpm_qa() {
        Ok(out) => {
            let list = vigile_backend_inventory::parse_rpm_qa(&out);
            (list.len(), list.iter().filter(|p| p.signed()).count())
        }
        Err(_) => (0, 0),
    };

    eprintln!("Platform    : {} {}", os.id, os.version_id);
    eprintln!("Packages    : {} ({} signed)", pkgs.0, pkgs.1);
    eprintln!("Executables : {} (non-RPM)", exec_report.entries.len());
    eprintln!("Skipped     : {} symlinks", exec_report.skipped_symlinks);

    let caps: Vec<serde_json::Value> = cap_report
        .capabilities
        .iter()
        .map(|c| {
            serde_json::json!({
                "backend": c.backend,
                "present": c.present_locally,
                "effective": format!("{:?}", c.effective).to_lowercase(),
            })
        })
        .collect();

    let report = serde_json::json!({
        "platform": {"id": os.id, "version": os.version_id},
        "packages": {"total": pkgs.0, "signed": pkgs.1},
        "executables": {"total": exec_report.entries.len()},
        "capabilities": caps,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

fn cmd_sync(server_url: Option<&String>) {
    let Some(url) = server_url else {
        eprintln!("sync requires a server URL");
        std::process::exit(2);
    };
    let clean = url
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let addr = if clean.contains(':') {
        clean.to_string()
    } else {
        format!("{clean}:8443")
    };

    eprintln!("Connecting to {addr}...");
    match TcpStream::connect(&addr) {
        Ok(mut stream) => {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
            let req = format!(
                "GET /agent/v1/policy HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
            );
            if stream.write_all(req.as_bytes()).is_err() {
                eprintln!("failed to send request");
                std::process::exit(1);
            }
            let mut response = String::new();
            let _ = stream.read_to_string(&mut response);
            let status_line = response.lines().next().unwrap_or("(empty)");
            eprintln!("Server response: {status_line}");
            eprintln!("Body: {} bytes", response.len());
        }
        Err(e) => {
            eprintln!("cannot connect to {addr}: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_status() {
    eprintln!("vigile-agent {}", env!("CARGO_PKG_VERSION"));
    eprintln!("State: stub (no persistent state)");
}
