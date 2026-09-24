// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vigile agent binary.
//!
//! Subcommands:
//!   inventory         — full system inventory report (JSON)
//!   sync <url>        — check for policy updates from server
//!   deploy <url>      — download + validate + deploy policy to fapolicyd
//!   status            — show local state

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
    use std::io::{Read, Write};
    use std::sync::Arc;

    let clean = url.trim_start_matches("http://").trim_start_matches("https://");
    let addr = if clean.contains(':') { clean.to_string() } else { format!("{clean}:8443") };
    let sock = TcpStream::connect(&addr).map_err(|e| format!("connect {addr}: {e}"))?;
    let _ = sock.set_read_timeout(Some(Duration::from_secs(10)));

    // mTLS identity. Lab provisioning: the server exports /tmp/vigile-lab at
    // startup (VIGILE_IDENTITY_DIR overrides). Real enrollment: ISS-089.
    let dir = std::env::var_os("VIGILE_IDENTITY_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp/vigile-lab"));
    let read_file = |name: &str| {
        std::fs::read(dir.join(name))
            .map_err(|e| format!("identity file {name}: {e} — is vigile-server running?"))
    };
    let leaf = rustls::pki_types::CertificateDer::from(read_file("agent-leaf.der")?);
    let intermediate =
        rustls::pki_types::CertificateDer::from(read_file("ca-inter.der")?);
    let key = rustls::pki_types::PrivateKeyDer::try_from(read_file("agent-key.der")?)
        .map_err(|e| format!("agent key: {e}"))?;
    let mut roots = rustls::RootCertStore::empty();
    for name in ["ca-root.der", "ca-inter.der"] {
        let der = rustls::pki_types::CertificateDer::from(read_file(name)?);
        roots.add(der).map_err(|e| format!("trust {name}: {e}"))?;
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(vec![leaf, intermediate], key)
        .map_err(|e| format!("agent certificate rejected: {e}"))?;

    // Lab convention: the server certificate carries SAN "localhost" even
    // when dialing 127.0.0.1, so the TLS name stays "localhost".
    let name = rustls::pki_types::ServerName::try_from("localhost")
        .map_err(|e| format!("server name: {e}"))?;
    let conn = rustls::ClientConnection::new(Arc::new(config), name)
        .map_err(|e| format!("TLS setup: {e}"))?;
    let mut tls = rustls::StreamOwned { conn, sock };

    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    tls.write_all(req.as_bytes()).map_err(|e| format!("send: {e}"))?;
    let mut response = String::new();
    // Connection: close — tolerate EOF with or without TLS close_notify.
    match tls.read_to_string(&mut response) {
        Ok(_) => Ok(response),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(response),
        Err(e) => Err(format!("read: {e}")),
    }
}

fn extract_json_body(response: &str) -> Option<&str> {
    response.split("\r\n\r\n").nth(1)
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Ed25519 verification of the served rules against the deployment-signing
/// public key (hex). Any mismatch => false (ISS-088, fail-closed).
fn verify_rules_signature(rules: &str, sig_hex: &str, pub_hex: &str) -> bool {
    let Some(sig_bytes) = hex_decode(sig_hex) else { return false };
    let Some(pub_bytes) = hex_decode(pub_hex) else { return false };
    let Ok(pub_arr) = <[u8; 32]>::try_from(pub_bytes.as_slice()) else { return false };
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pub_arr) else { return false };
    let Ok(sig) = ed25519_dalek::Signature::from_slice(&sig_bytes) else { return false };
    // verify_strict is inherent (no `signature` trait import needed) and
    // rejects malleable signatures.
    vk.verify_strict(rules.as_bytes(), &sig).is_ok()
}

/// SHA-256 of the rules must match the first artifact hash in the manifest.
fn verify_rules_sha256(rules: &str, manifest: &serde_json::Value) -> bool {
    use sha2::{Digest, Sha256};
    let Some(expected) = manifest
        .get("artifacts")
        .and_then(|a| a.get(0))
        .and_then(|a| a.get("sha256"))
        .and_then(|h| h.as_str())
        .map(str::trim)
    else {
        return false;
    };
    let digest = Sha256::digest(rules.as_bytes());
    expected == hex_encode(&digest)
}

fn identity_dir() -> std::path::PathBuf {
    std::env::var_os("VIGILE_IDENTITY_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp/vigile-lab"))
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

    eprintln!("[1/7] Fetching policy from {url}...");
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

    // [2] Verify the deployment signature (Ed25519) and the manifest SHA-256.
    // Fail-closed: nothing is written to disk before both checks pass.
    eprintln!("[2/7] Verifying rules signature...");
    let sig_hex = policy.get("rules_signature").and_then(|s| s.as_str()).unwrap_or("");
    let pub_hex = match std::fs::read_to_string(identity_dir().join("signing-pub.hex")) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("  REFUSED: cannot read signing public key: {e}");
            eprintln!("  (is vigile-server running? key exported to the identity dir)");
            std::process::exit(1);
        }
    };
    if !verify_rules_signature(rules, sig_hex, &pub_hex) {
        eprintln!("  REFUSED: rules signature is INVALID — refusing to deploy.");
        eprintln!("  The policy may have been tampered with in transit or on the server.");
        std::process::exit(1);
    }
    eprintln!("  Signature valid.");

    eprintln!("[3/7] Verifying manifest SHA-256...");
    let manifest = policy.get("manifest").cloned().unwrap_or(serde_json::json!({}));
    if !verify_rules_sha256(rules, &manifest) {
        eprintln!("  REFUSED: SHA-256 of rules does not match the manifest.");
        std::process::exit(1);
    }
    eprintln!("  Manifest hash matches.");

    // [2] Write to staging
    eprintln!("[4/7] Staging rules...");
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
    eprintln!("[5/7] Validating with fapolicyd-cli...");
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
    eprintln!("[6/7] Deploying to /etc/fapolicyd/rules.d/...");
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
    eprintln!("[7/7] Reloading fapolicyd...");
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn tampered_rules_fail_signature() {
        // A signature computed over other bytes must not verify.
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        // RFC 8032 Ed25519: signature = R || S over (A, M). Produce it via
        // the raw API: expand the seed, then sign manually is complex —
        // instead use dalek's re-exported Signer if available; otherwise
        // this test still exercises the negative paths below.
        use ed25519_dalek::Signer as _;
        let sig: ed25519_dalek::Signature = sk.sign(b"original rules");
        let sig_hex = hex_encode(&sig.to_bytes());
        let pub_hex = hex_encode(sk.verifying_key().as_bytes());
        assert!(verify_rules_signature("original rules", &sig_hex, &pub_hex));
        assert!(!verify_rules_signature("tampered rules", &sig_hex, &pub_hex));
    }

    #[test]
    fn garbage_inputs_fail_closed() {
        assert!(!verify_rules_signature("rules", "zz", "pub"));
        assert!(!verify_rules_signature("rules", "", ""));
        assert!(!hex_decode("abc").is_some());
    }

    #[test]
    fn sha256_must_match_manifest() {
        use sha2::Digest as _;
        let manifest = serde_json::json!({
            "artifacts": [{"sha256": hex_encode(&sha2::Sha256::digest(b"rules"))}]
        });
        assert!(verify_rules_sha256("rules", &manifest));
        assert!(!verify_rules_sha256("other", &manifest));
        assert!(!verify_rules_sha256("rules", &serde_json::json!({})));
    }
}
