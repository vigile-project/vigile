// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vigile agent binary.
//!
//! Subcommands:
//!   inventory         — full system inventory report (JSON)
//!   sync <url>        — check for policy updates from server
//!   deploy <url>      — download + validate + deploy policy to fapolicyd
//!   status            — show local state

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("inventory") => cmd_inventory(),
        Some("sync") => cmd_sync(args.get(1)),
        Some("deploy") => cmd_deploy(args.get(1)),
        Some("status") => cmd_status(),
        _ => {
            eprintln!(
                "vigile-agent {}\n\
                 usage:\n  vigile-agent inventory\n  vigile-agent sync <url>\n  vigile-agent deploy <url>\n  vigile-agent status",
                env!("CARGO_PKG_VERSION")
            );
            std::process::exit(2);
        }
    }
}

fn http_get(url: &str, path: &str) -> Result<String, String> {
    let clean = url.trim_start_matches("http://").trim_start_matches("https://");
    let addr = if clean.contains(':') { clean.to_string() } else { format!("{clean}:8443") };
    let mut stream = TcpStream::connect(&addr).map_err(|e| format!("connect {addr}: {e}"))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).map_err(|e| format!("send: {e}"))?;
    let mut response = String::new();
    stream.read_to_string(&mut response).map_err(|e| format!("read: {e}"))?;
    Ok(response)
}

fn extract_json_body(response: &str) -> Option<&str> {
    response.split("\r\n\r\n").nth(1)
}

fn cmd_inventory() {
    let root = Path::new("/");
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
    println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
}

fn cmd_sync(server_url: Option<&String>) {
    let Some(url) = server_url else {
        eprintln!("sync requires a server URL");
        std::process::exit(2);
    };
    eprintln!("Checking {url} for policy updates...");
    match http_get(url, "/agent/v1/policy") {
        Ok(response) => {
            let status_line = response.lines().next().unwrap_or("(empty)");
            eprintln!("  Server: {status_line}");
            if let Some(body) = extract_json_body(&response) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                    if json.get("available").and_then(|a| a.as_bool()).unwrap_or(false) {
                        eprintln!("  Policy available: v{}", json.get("version").and_then(|v| v.as_u64()).unwrap_or(0));
                        eprintln!("  Run 'vigile-agent deploy {url}' to apply.");
                    } else {
                        eprintln!("  No policy deployed yet.");
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("  Error: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_deploy(server_url: Option<&String>) {
    let Some(url) = server_url else {
        eprintln!("deploy requires a server URL");
        std::process::exit(2);
    };

    eprintln!("[1/5] Fetching policy from {url}...");
    let response = match http_get(url, "/agent/v1/policy") {
        Ok(r) => r,
        Err(e) => {
            eprintln!("  FAILED: {e}");
            std::process::exit(1);
        }
    };

    let body = extract_json_body(&response).unwrap_or("{}");
    let policy: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("  FAILED to parse response: {e}");
            std::process::exit(1);
        }
    };

    if !policy.get("available").and_then(|a| a.as_bool()).unwrap_or(false) {
        eprintln!("  No policy deployed on server.");
        eprintln!("  Compile a policy first via the web portal.");
        std::process::exit(1);
    }

    let rules = policy.get("rules").and_then(|r| r.as_str()).unwrap_or("");
    if rules.is_empty() {
        eprintln!("  Policy has no rules.");
        std::process::exit(1);
    }
    eprintln!("  Got {} bytes of rules", rules.len());

    // [2] Write to staging
    eprintln!("[2/5] Staging rules...");
    let staging_dir = std::env::temp_dir().join(format!("vigile-deploy-{}", std::process::id()));
    if let Err(e) = std::fs::create_dir_all(&staging_dir) {
        eprintln!("  FAILED to create staging dir: {e}");
        std::process::exit(1);
    }
    let staging_file = staging_dir.join("90-vigile.rules");
    if let Err(e) = std::fs::write(&staging_file, rules) {
        eprintln!("  FAILED to write staging file: {e}");
        std::process::exit(1);
    }
    eprintln!("  Staged: {}", staging_file.display());

    // [3] Validate with fapolicyd-cli
    eprintln!("[3/5] Validating with fapolicyd-cli...");
    let validation = Command::new("fapolicyd-cli")
        .arg("--check-rules")
        .arg(&staging_file)
        .output();

    match validation {
        Ok(output) if output.status.success() => {
            eprintln!("  {}", String::from_utf8_lossy(&output.stdout).trim());
        }
        Ok(output) => {
            eprintln!("  VALIDATION FAILED:");
            eprintln!("    {}", String::from_utf8_lossy(&output.stderr).trim());
            eprintln!("    {}", String::from_utf8_lossy(&output.stdout).trim());
            let _ = std::fs::remove_dir_all(&staging_dir);
            std::process::exit(1);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("  WARNING: fapolicyd-cli not found, skipping validation");
        }
        Err(e) => {
            eprintln!("  Validation error: {e}");
            let _ = std::fs::remove_dir_all(&staging_dir);
            std::process::exit(1);
        }
    }

    // [4] Deploy flat into /etc/fapolicyd/rules.d/
    // fagenrules uses `find -maxdepth 1 -name '*.rules'`: subdirectories are
    // never traversed, so the file MUST sit directly in rules.d/.
    eprintln!("[4/5] Deploying to /etc/fapolicyd/rules.d/...");
    let deploy_dir = Path::new("/etc/fapolicyd/rules.d");
    if !deploy_dir.is_dir() {
        eprintln!("  FAILED: {} does not exist (fapolicyd installed?)", deploy_dir.display());
        let _ = std::fs::remove_dir_all(&staging_dir);
        std::process::exit(1);
    }
    let deploy_file = deploy_dir.join("90-vigile.rules");
    if let Err(e) = std::fs::copy(&staging_file, &deploy_file) {
        eprintln!("  FAILED to deploy (need root?): {e}");
        eprintln!("  Run as root or use sudo.");
        let _ = std::fs::remove_dir_all(&staging_dir);
        std::process::exit(1);
    }
    eprintln!("  Deployed: {}", deploy_file.display());

    // Migrate away from the legacy subdirectory layout (never loaded by fagenrules)
    let legacy_dir = Path::new("/etc/fapolicyd/rules.d/vigile");
    if legacy_dir.is_dir() {
        let _ = std::fs::remove_dir_all(legacy_dir);
        eprintln!("  Removed legacy directory: {}", legacy_dir.display());
    }

    // Clean staging
    let _ = std::fs::remove_dir_all(&staging_dir);

    // [5] Reload fapolicyd
    eprintln!("[5/5] Reloading fapolicyd...");
    match Command::new("fapolicyd-cli").arg("--reload-rules").output() {
        Ok(output) if output.status.success() => {
            eprintln!("  fapolicyd rules reloaded.");
        }
        Ok(output) => {
            // FIFO missing or daemon not listening: check systemd before guessing.
            let active = Command::new("systemctl")
                .args(["is-active", "--quiet", "fapolicyd"])
                .output()
                .is_ok_and(|o| o.status.success());
            if active {
                eprintln!("  WARNING: reload returned non-zero while daemon is active:");
                eprintln!("    {}", String::from_utf8_lossy(&output.stderr).trim());
                eprintln!("  Try: sudo systemctl restart fapolicyd");
            } else {
                eprintln!("  fapolicyd daemon is NOT running (rules deployed, not enforced).");
                eprintln!("  Start it with: sudo systemctl enable --now fapolicyd");
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("  WARNING: fapolicyd-cli not found (rules deployed but not reloaded)");
        }
        Err(e) => {
            eprintln!("  WARNING: reload error: {e}");
        }
    }

    eprintln!();
    eprintln!("  DONE. Policy deployed to fapolicyd.");
    eprintln!("  Verify: ls -la /etc/fapolicyd/rules.d/");
    eprintln!("  Loaded:  sudo fapolicyd-cli --list | tail -5");
    eprintln!("  Observe: sudo grep FANOTIFY /var/log/audit/audit.log | tail -5");
}

fn cmd_status() {
    eprintln!("vigile-agent {}", env!("CARGO_PKG_VERSION"));
    let rules_file = Path::new("/etc/fapolicyd/rules.d/90-vigile.rules");
    if rules_file.exists() {
        let meta = std::fs::metadata(rules_file).ok();
        let size = meta.as_ref().map(std::fs::Metadata::len).unwrap_or(0);
        eprintln!("Deployed rules: {} ({} bytes)", rules_file.display(), size);
    } else {
        eprintln!("No rules deployed.");
    }
    match Command::new("systemctl").args(["is-active", "fapolicyd"]).output() {
        Ok(o) => {
            let state = String::from_utf8_lossy(&o.stdout).trim().to_string();
            eprintln!("fapolicyd: {state}");
        }
        Err(_) => eprintln!("fapolicyd: unknown (systemctl not available)"),
    }
}
