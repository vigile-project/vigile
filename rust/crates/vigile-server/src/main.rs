// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vigile server binary — serves the admin API, web portal, and agent API.
//!
//! Run: vigile-server [port] (default 8443)
//! Portal: https://127.0.0.1:<port>/  (self-signed lab CA — browser warning expected)
//! Admin API: https://127.0.0.1:<port>/admin/v1/*
//! Agent API: https://127.0.0.1:<port>/agent/v1/* (client certificate REQUIRED)

use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(8443);

    let state = match vigile_server::ServerState::lab() {
        Ok(s) => Arc::new(Mutex::new(s)),
        Err(e) => {
            eprintln!("vigile-server: failed to initialize: {e}");
            std::process::exit(1);
        }
    };

    // Lab PKI: fresh hierarchy per run until ISS-089 persists it on disk.
    let (tls_config, ca) = {
        let ca = match vigile_pki::CaHierarchy::generate("Vigile Lab Root", "Vigile Lab Issuer") {
            Ok(c) => c,
            Err(e) => {
                eprintln!("vigile-server: cannot generate lab PKI: {e}");
                std::process::exit(1);
            }
        };
        let server_cert = match ca.issue_server_certificate("localhost") {
            Ok(c) => c,
            Err(e) => {
                eprintln!("vigile-server: cannot issue server certificate: {e}");
                std::process::exit(1);
            }
        };
        match vigile_pki::mtls::server_config_optional_client(&server_cert, &ca) {
            Ok(cfg) => (cfg, ca),
            Err(e) => {
                eprintln!("vigile-server: cannot build TLS config: {e}");
                std::process::exit(1);
            }
        }
    };

    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).unwrap_or_else(|e| {
        eprintln!("vigile-server: cannot bind 127.0.0.1:{port}: {e}");
        std::process::exit(1);
    });

    eprintln!();
    eprintln!("  Vigile  https://127.0.0.1:{port}/");
    eprintln!("  Agent enrolment (lab): issue an agent certificate with the");
    eprintln!("  in-memory CA and present it — /agent/v1/* requires mTLS.");
    eprintln!();
    eprintln!("  Press Ctrl+C to stop.");
    eprintln!();

    // Keep the CA alive for the lifetime of the process (agent enrolment
    // helper reads it); the TLS config already holds what it needs.
    let _ca_anchor = &ca;

    for stream in listener.incoming() {
        let Ok(sock) = stream else { continue };
        let _ = sock.set_read_timeout(Some(Duration::from_secs(10)));
        let conn = match rustls::ServerConnection::new(tls_config.clone()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let mut tls = rustls::StreamOwned { conn, sock };

        let agent_authenticated = tls.conn.peer_certificates().is_some();

        let Ok(mut st) = state.lock() else { continue };

        match vigile_server::http::parse_request(&mut tls) {
            Ok(request) => {
                let path = request.path.as_str();
                let method = request.method.as_str();

                if method == "GET" && (path == "/" || path == "/index.html") {
                    serve_portal(&mut tls);
                } else if let Some(rest) = path.strip_prefix("/admin/v1/") {
                    handle_admin(&mut tls, &request, &mut st, rest, method);
                } else if method == "GET" && path == "/agent/v1/policy" {
                    serve_policy(&mut tls, &mut st, agent_authenticated);
                } else {
                    let _ = vigile_server::routes::route(&mut tls, &request, &mut st, None);
                }
            }
            Err(e) => {
                let _ = vigile_server::http::error_response(&mut tls, &e);
            }
        }
    }
}

fn serve_portal(stream: &mut dyn vigile_server::http::Stream) {
    let html = std::fs::read_to_string("web/index.html")
        .or_else(|_| std::fs::read_to_string("../web/index.html"))
        .or_else(|_| std::fs::read_to_string("/usr/share/vigile/web/index.html"))
        .unwrap_or_else(|_| {
            "<html><body><h1>Vigile</h1><p>Portal file not found.</p></body></html>".to_string()
        });
    let _ = vigile_server::http::write_response(
        stream,
        200,
        "OK",
        "text/html; charset=utf-8",
        html.as_bytes(),
    );
}

fn serve_policy(
    stream: &mut dyn vigile_server::http::Stream,
    state: &mut vigile_server::ServerState,
    agent_authenticated: bool,
) {
    use vigile_server::http::write_json;
    if !agent_authenticated {
        state
            .audit
            .append("anonymous", "agent.policy-denied", "agent-api", "unauthenticated");
        let _ = write_json(
            stream,
            401,
            "Unauthorized",
            "{\"error\":\"agent authentication required (mTLS)\"}",
        );
        return;
    }
    match &state.deployed_policy {
        Some(p) => {
            let response = serde_json::json!({
                "available": true,
                "policy_id": p.policy_id,
                "version": p.version,
                "rules": p.rules,
                "manifest": serde_json::from_str::<serde_json::Value>(&p.manifest_json)
                    .unwrap_or(serde_json::json!({})),
                "deployed_at": p.deployed_at_unix,
            });
            let _ = write_json(stream, 200, "OK", &serde_json::to_string(&response).unwrap_or_default());
        }
        None => {
            let _ = write_json(stream, 200, "OK", "{\"available\":false}");
        }
    }
}

fn handle_admin(
    stream: &mut dyn vigile_server::http::Stream,
    request: &vigile_server::http::Request,
    state: &mut vigile_server::ServerState,
    path: &str,
    method: &str,
) {
    use vigile_server::http::write_json;

    // Check auth
    let bearer = request.headers.get("authorization").cloned();
    let role = bearer.and_then(|b| state.admin_auth.validate(&b));

    let Some(_role) = role else {
        let _ = write_json(stream, 401, "Unauthorized", "{\"error\":\"invalid token\"}");
        return;
    };

    match (method, path) {
        // Status (includes system info)
        ("GET", "status") => {
            let info = get_system_info();
            let response = serde_json::json!({
                "status": "ok",
                "audit_entries": state.audit.entries().len(),
                "audit_head": state.audit.head_hash(),
                "system": info,
            });
            let _ = write_json(
                stream,
                200,
                "OK",
                &serde_json::to_string(&response).unwrap_or_default(),
            );
        }

        // Audit journal
        ("GET", "audit") => {
            let entries: Vec<vigile_server::audit::AuditEntry> = state.audit.entries().to_vec();
            let response = serde_json::json!({
                "count": entries.len(),
                "head_hash": state.audit.head_hash(),
                "entries": entries,
            });
            let _ = write_json(
                stream,
                200,
                "OK",
                &serde_json::to_string(&response).unwrap_or_default(),
            );
        }

        ("GET", "audit/verify") => match state.audit.verify_chain() {
            Ok(count) => {
                state
                    .audit
                    .append("admin", "audit.verified", "journal", "ok");
                let _ = write_json(
                    stream,
                    200,
                    "OK",
                    &serde_json::json!({"valid": true, "verified_entries": count}).to_string(),
                );
            }
            Err((seq, detail)) => {
                let _ = write_json(
                    stream,
                    200,
                    "OK",
                    &serde_json::json!({"valid": false, "broken_at": seq, "detail": detail})
                        .to_string(),
                );
            }
        },

        // System inventory (real data)
        ("GET", "inventory") => {
            let inv = get_inventory_summary();
            let _ = write_json(
                stream,
                200,
                "OK",
                &serde_json::to_string(&inv).unwrap_or_default(),
            );
        }

        // fapolicyd observation
        ("GET", "fapolicyd") => {
            let events = get_fapolicyd_events();
            let untrusted = events
                .iter()
                .filter(|e| e.get("obj_trust").and_then(|v| v.as_str()) == Some("0"))
                .count();
            let response = serde_json::json!({
                "events": events,
                "count": events.len(),
                "untrusted": untrusted,
            });
            let _ = write_json(
                stream,
                200,
                "OK",
                &serde_json::to_string(&response).unwrap_or_default(),
            );
        }

        // Compile a policy (POST with policy JSON in body)
        ("POST", "policies/compile") => {
            let body = String::from_utf8_lossy(&request.body);
            match compile_policy(&body) {
                Ok(result) => {
                    state
                        .audit
                        .append("admin", "policy.compiled", "policy", "ok");
                    // Store the compiled policy for agent download
                    if let Some(rules) = result.get("rules").and_then(|r| r.as_str()) {
                        let manifest = result
                            .get("manifest")
                            .cloned()
                            .unwrap_or(serde_json::json!({}));
                        state.deployed_policy =
                            Some(vigile_server::state::DeployedPolicy {
                                policy_id: "current".to_string(),
                                version: 1,
                                rules: rules.to_string(),
                                manifest_json: serde_json::to_string(&manifest)
                                    .unwrap_or_default(),
                                deployed_at_unix: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_secs() as i64)
                                    .unwrap_or(0),
                            });
                    }
                    let _ = write_json(
                        stream,
                        200,
                        "OK",
                        &serde_json::to_string(&result).unwrap_or_default(),
                    );
                }
                Err(e) => {
                    state.audit.append(
                        "admin",
                        "policy.compile-failed",
                        "policy",
                        &format!("error:{e}"),
                    );
                    let _ = write_json(
                        stream,
                        400,
                        "Bad Request",
                        &serde_json::json!({"error": e}).to_string(),
                    );
                }
            }
        }

        // Issue enrollment token
        ("POST", "enrollment-tokens") => {
            match state
                .enrollment_issuer
                .issue("default", None, 3600, std::time::SystemTime::now())
            {
                Ok(token) => {
                    state
                        .audit
                        .append("admin", "enrollment-token.issued", "default", "ok");
                    let _ = write_json(
                        stream,
                        201,
                        "Created",
                        &serde_json::json!({"token": token, "ttl_secs": 3600}).to_string(),
                    );
                }
                Err(e) => {
                    let _ = write_json(
                        stream,
                        500,
                        "Internal Server Error",
                        &serde_json::json!({"error": e.to_string()}).to_string(),
                    );
                }
            }
        }

        _ => {
            let _ = write_json(
                stream,
                404,
                "Not Found",
                &serde_json::json!({"error": format!("not found: {method} /admin/v1/{path}")})
                    .to_string(),
            );
        }
    }
}

fn get_system_info() -> serde_json::Value {
    let mut info = serde_json::Map::new();

    // fapolicyd
    info.insert(
        "fapolicyd".into(),
        serde_json::json!(std::path::Path::new("/usr/sbin/fapolicyd").exists()),
    );

    // SELinux
    let selinux = std::fs::read_to_string("/sys/fs/selinux/enforce")
        .map(|s| s.trim() == "1")
        .unwrap_or(false);
    info.insert("selinux_enforcing".into(), serde_json::json!(selinux));

    // Package count
    let pkg_count = std::process::Command::new("rpm")
        .arg("-qa")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().count())
        .unwrap_or(0);
    info.insert("packages".into(), serde_json::json!(pkg_count));

    serde_json::Value::Object(info)
}

fn get_inventory_summary() -> serde_json::Value {
    let root = std::path::Path::new("/");

    // Platform
    let os = vigile_backend_inventory::read_os_release(root).ok();
    let os_json = match &os {
        Some(o) => serde_json::json!({"id": o.id, "version": o.version_id, "name": o.name}),
        None => serde_json::json!({"id": "unknown"}),
    };

    // Capabilities
    let caps = if let Some(ref o) = os {
        let report = vigile_backend_inventory::detect_capabilities(root, o);
        report
            .capabilities
            .iter()
            .map(|c| {
                serde_json::json!({
                    "backend": c.backend,
                    "present": c.present_locally,
                    "effective": format!("{:?}", c.effective).to_lowercase(),
                })
            })
            .collect::<Vec<_>>()
    } else {
        vec![]
    };

    // Executables (quick scan of /usr/local and /opt only for speed)
    let quick_scan = vigile_backend_inventory::scan(root, &["usr/local", "opt"], None);
    let exec_count = quick_scan.entries.len();

    serde_json::json!({
        "platform": os_json,
        "capabilities": caps,
        "executables_non_rpm": exec_count,
    })
}

fn get_fapolicyd_events() -> Vec<serde_json::Value> {
    let mut events = Vec::new();
    if let Ok(content) = std::fs::read_to_string("/var/log/audit/audit.log") {
        for line in content.lines().rev().take(20) {
            if !line.contains("type=FANOTIFY") {
                continue;
            }
            let mut ev = serde_json::Map::new();
            for kv in line.split_whitespace() {
                if let Some((k, v)) = kv.split_once('=') {
                    ev.insert(k.to_string(), serde_json::json!(v));
                }
            }
            events.push(serde_json::Value::Object(ev));
            if events.len() >= 20 {
                break;
            }
        }
    }
    events
}

fn compile_policy(policy_json: &str) -> Result<serde_json::Value, String> {
    // Validate + parse
    let value = vigile_policy::parse_and_validate(policy_json)
        .map_err(|e| format!("invalid policy: {e}"))?;

    let doc: vigile_policy::model::PolicyDocument =
        serde_json::from_value(value).map_err(|e| format!("model mismatch: {e}"))?;

    // Check contradictions
    vigile_policy::check_contradictions(&doc.policy).map_err(|e| format!("contradiction: {e}"))?;

    // Compile
    let compiled =
        vigile_policy::compile(&doc.policy).map_err(|e| format!("compilation failed: {e}"))?;

    // Build result
    let rules = compiled
        .artifacts
        .first()
        .map(|a| a.content.clone())
        .unwrap_or_default();

    Ok(serde_json::json!({
        "success": true,
        "rules": rules,
        "manifest": compiled.manifest,
    }))
}
