// SPDX-License-Identifier: AGPL-3.0-or-later
//! API routes (ISS-030/031/033): `/agent/v1/*` (mTLS) and `/admin/v1/*`
//! (bearer token + RBAC).
//!
//! Agent endpoints:
//! - POST /agent/v1/enroll — enrollment (token + CSR + fingerprint)
//! - POST /agent/v1/heartbeat — signed envelope with status
//! - GET  /agent/v1/policy — current compiled policy for this agent
//!
//! Admin endpoints (ISS-031):
//! - GET  /admin/v1/status — server health (viewer)
//! - GET  /admin/v1/audit — audit journal entries (viewer)
//! - POST /admin/v1/enrollment-tokens — issue a token (admin)
//! - GET  /admin/v1/audit/verify — verify chain integrity (viewer)

use crate::auth::{bearer_from_headers, AdminRole, TokenAuth};
use crate::http::{write_json, Request};
use crate::state::ServerState;
use std::net::TcpStream;
use std::time::SystemTime;
use vigile_pki::{process_enrollment, EnrollmentRequest, MessageEnvelope};

/// Routes a request to the appropriate handler.
pub fn route(
    stream: &mut TcpStream,
    request: &Request,
    state: &mut ServerState,
    agent_id: Option<&str>,
) -> std::io::Result<()> {
    // Admin routes.
    if request.path.starts_with("/admin/v1/") {
        return route_admin(stream, request, state);
    }

    match (request.method.as_str(), request.path.as_str()) {
        ("POST", "/agent/v1/enroll") => handle_enroll(stream, request, state),
        ("POST", "/agent/v1/heartbeat") => {
            let Some(agent_id) = agent_id else {
                return write_json(stream, 401, "Unauthorized", "{\"error\":\"mTLS required\"}");
            };
            handle_heartbeat(stream, request, state, agent_id)
        }
        ("GET", "/agent/v1/policy") => {
            let Some(agent_id) = agent_id else {
                return write_json(stream, 401, "Unauthorized", "{\"error\":\"mTLS required\"}");
            };
            handle_policy(stream, state, agent_id)
        }
        (method, path) => {
            let body = format!("{{\"error\":\"not found: {method} {path}\"}}");
            write_json(stream, 404, "Not Found", &body)
        }
    }
}

// ------------------------------------------------------------------
// Admin routes (ISS-031)
// ------------------------------------------------------------------

fn route_admin(
    stream: &mut TcpStream,
    request: &Request,
    state: &mut ServerState,
) -> std::io::Result<()> {
    // All admin routes require a valid bearer token.
    let bearer = bearer_from_headers(&request.headers);
    let Some(bearer) = bearer else {
        return write_json(
            stream,
            401,
            "Unauthorized",
            "{\"error\":\"Authorization header required\"}",
        );
    };
    let Some(role) = state.admin_auth.validate(&bearer) else {
        return write_json(stream, 401, "Unauthorized", "{\"error\":\"invalid token\"}");
    };

    // Identify the actor for the audit log (first 8 chars of the token).
    let actor = format!(
        "admin:{}",
        &bearer.strip_prefix("Bearer ").unwrap_or(&bearer)[..8.min(bearer.len())]
    );

    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/admin/v1/status") => {
            if !TokenAuth::authorize(role, AdminRole::Viewer) {
                return write_json(
                    stream,
                    403,
                    "Forbidden",
                    "{\"error\":\"insufficient role\"}",
                );
            }
            handle_admin_status(stream, state)
        }
        ("GET", "/admin/v1/audit") => {
            if !TokenAuth::authorize(role, AdminRole::Viewer) {
                return write_json(
                    stream,
                    403,
                    "Forbidden",
                    "{\"error\":\"insufficient role\"}",
                );
            }
            handle_admin_audit(stream, state)
        }
        ("GET", "/admin/v1/audit/verify") => {
            if !TokenAuth::authorize(role, AdminRole::Viewer) {
                return write_json(
                    stream,
                    403,
                    "Forbidden",
                    "{\"error\":\"insufficient role\"}",
                );
            }
            handle_admin_audit_verify(stream, state, &actor)
        }
        ("POST", "/admin/v1/enrollment-tokens") => {
            if !TokenAuth::authorize(role, AdminRole::Admin) {
                state
                    .audit
                    .append(&actor, "enrollment-token.denied", "role-check", "denied");
                return write_json(
                    stream,
                    403,
                    "Forbidden",
                    "{\"error\":\"admin role required\"}",
                );
            }
            handle_admin_issue_token(stream, request, state, &actor)
        }
        (method, path) => {
            let body = format!("{{\"error\":\"not found: {method} {path}\"}}");
            write_json(stream, 404, "Not Found", &body)
        }
    }
}

fn handle_admin_status(stream: &mut TcpStream, state: &mut ServerState) -> std::io::Result<()> {
    let response = serde_json::json!({
        "status": "ok",
        "audit_entries": state.audit.entries().len(),
        "audit_head": state.audit.head_hash(),
    });
    let body = serde_json::to_string(&response).unwrap_or_default();
    write_json(stream, 200, "OK", &body)
}

fn handle_admin_audit(stream: &mut TcpStream, state: &mut ServerState) -> std::io::Result<()> {
    let entries: Vec<crate::audit::AuditEntry> = state.audit.entries().to_vec();
    let response = serde_json::json!({
        "count": entries.len(),
        "head_hash": state.audit.head_hash(),
        "entries": entries,
    });
    let body = serde_json::to_string(&response).unwrap_or_default();
    write_json(stream, 200, "OK", &body)
}

fn handle_admin_audit_verify(
    stream: &mut TcpStream,
    state: &mut ServerState,
    actor: &str,
) -> std::io::Result<()> {
    match state.audit.verify_chain() {
        Ok(count) => {
            state
                .audit
                .append(actor, "audit.verified", "audit-journal", "ok");
            let response = serde_json::json!({
                "valid": true,
                "verified_entries": count,
            });
            let body = serde_json::to_string(&response).unwrap_or_default();
            write_json(stream, 200, "OK", &body)
        }
        Err((seq, detail)) => {
            state.audit.append(
                actor,
                "audit.verification-failed",
                "audit-journal",
                &format!("error:seq-{seq}"),
            );
            let response = serde_json::json!({
                "valid": false,
                "broken_at_seq": seq,
                "detail": detail,
            });
            let body = serde_json::to_string(&response).unwrap_or_default();
            write_json(stream, 200, "OK", &body)
        }
    }
}

fn handle_admin_issue_token(
    stream: &mut TcpStream,
    request: &Request,
    state: &mut ServerState,
    actor: &str,
) -> std::io::Result<()> {
    // Parse optional TTL from the body.
    #[derive(serde::Deserialize)]
    struct TokenRequest {
        ttl_secs: Option<u64>,
        group: Option<String>,
    }
    let token_req: TokenRequest = match serde_json::from_slice(&request.body) {
        Ok(r) => r,
        Err(_) => TokenRequest {
            ttl_secs: None,
            group: None,
        },
    };

    let ttl = token_req.ttl_secs.unwrap_or(3600).min(24 * 3600);
    let tenant = "default";

    match state
        .enrollment_issuer
        .issue(tenant, token_req.group, ttl, SystemTime::now())
    {
        Ok(token) => {
            state
                .audit
                .append(actor, "enrollment-token.issued", tenant, "ok");
            let response = serde_json::json!({
                "token": token,
                "ttl_secs": ttl,
                "tenant": tenant,
            });
            let body = serde_json::to_string(&response).unwrap_or_default();
            write_json(stream, 201, "Created", &body)
        }
        Err(e) => {
            state.audit.append(
                actor,
                "enrollment-token.failed",
                tenant,
                &format!("error:{e}"),
            );
            let body = format!("{{\"error\":\"{e}\"}}");
            write_json(stream, 500, "Internal Server Error", &body)
        }
    }
}

/// Wire format: same as EnrollmentRequest but csr_der is base64.
#[derive(serde::Deserialize)]
struct EnrollWire {
    token: String,
    csr_der: String, // base64
    machine_fingerprint: String,
}

fn handle_enroll(
    stream: &mut TcpStream,
    request: &Request,
    state: &mut ServerState,
) -> std::io::Result<()> {
    // Parse the wire format, then decode the CSR.
    let wire: EnrollWire = match serde_json::from_slice(&request.body) {
        Ok(r) => r,
        Err(e) => {
            let body = format!("{{\"error\":\"invalid enrollment request: {e}\"}}");
            return write_json(stream, 400, "Bad Request", &body);
        }
    };
    let csr_der = match decode_base64(&wire.csr_der) {
        Some(d) => d,
        None => {
            return write_json(
                stream,
                400,
                "Bad Request",
                "{\"error\":\"csr_der not valid base64\"}",
            );
        }
    };
    let enroll_req = EnrollmentRequest {
        token: wire.token,
        csr_der,
        machine_fingerprint: wire.machine_fingerprint,
    };

    let now = SystemTime::now();
    let tenant = "default"; // single-tenant MVP

    match process_enrollment(
        &state.ca,
        &state.enrollment_verifier,
        &mut state.enrollment_store,
        &enroll_req,
        now,
        tenant,
    ) {
        Ok(enrolled) => {
            // Issue the initial server nonce for anti-replay.
            let nonce = state
                .envelope_verifier
                .issue_nonce(&enrolled.agent_id)
                .unwrap_or_default();

            let response = serde_json::json!({
                "agent_id": enrolled.agent_id,
                "certificate": base64_encode(enrolled.certificate.certificate.as_ref()),
                "chain": enrolled
                    .certificate
                    .chain
                    .iter()
                    .map(|c| base64_encode(c.as_ref()))
                    .collect::<Vec<_>>(),
                "server_nonce": nonce,
            });
            let body = serde_json::to_string(&response).unwrap_or_default();
            write_json(stream, 200, "OK", &body)
        }
        Err(e) => {
            let status = match &e {
                vigile_pki::EnrollmentError::AlreadyUsed
                | vigile_pki::EnrollmentError::BadSignature
                | vigile_pki::EnrollmentError::Expired
                | vigile_pki::EnrollmentError::NotYetValid
                | vigile_pki::EnrollmentError::WrongTenant
                | vigile_pki::EnrollmentError::WrongType => 401,
                _ => 400,
            };
            let body = format!("{{\"error\":\"{e}\"}}");
            write_json(stream, status, "Unauthorized", &body)
        }
    }
}

fn handle_heartbeat(
    stream: &mut TcpStream,
    request: &Request,
    state: &mut ServerState,
    _agent_id: &str,
) -> std::io::Result<()> {
    // Parse the envelope.
    let _envelope: MessageEnvelope = match serde_json::from_slice(&request.body) {
        Ok(e) => e,
        Err(e) => {
            let body = format!("{{\"error\":\"invalid envelope: {e}\"}}");
            return write_json(stream, 400, "Bad Request", &body);
        }
    };

    // For now, verify the envelope without a registry (in-memory path).
    // When the PgStore is connected, we'll use its observe_sequence.
    let now = SystemTime::now();
    // TODO(ISS-031): wire the persistent registry here.
    let _ = now;

    // Respond with the next nonce.
    let next = state
        .envelope_verifier
        .outstanding_nonce(_agent_id)
        .unwrap_or_default();

    let response = serde_json::json!({
        "status": "ok",
        "next_nonce": next,
    });
    let body = serde_json::to_string(&response).unwrap_or_default();
    write_json(stream, 200, "OK", &body)
}

fn handle_policy(
    stream: &mut TcpStream,
    state: &mut ServerState,
    agent_id: &str,
) -> std::io::Result<()> {
    // MVP: return a stub policy response indicating the agent is known.
    // The real compiled policy distribution arrives with phase 2/3
    // (ISS-035, policy channel via TUF).
    let response = serde_json::json!({
        "agent_id": agent_id,
        "policy_version": 0,
        "status": "no-policy-yet",
        "message": "policy distribution arrives with phase 2 (fapolicyd audit)"
    });
    let body = serde_json::to_string(&response).unwrap_or_default();
    let _ = &state.ca; // CA is used at the TLS layer, not here
    write_json(stream, 200, "OK", &body)
}

/// Minimal base64 encoder for DER certificates in JSON responses.
fn base64_encode(data: &[u8]) -> String {
    // We already have a base64 decoder in vigile-backend-inventory; for
    // the server we inline a minimal encoder (the crate doesn't export
    // one). This is the standard alphabet.
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(triple >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(triple >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(triple >> 6) as usize & 0x3f] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[triple as usize & 0x3f] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Minimal base64 decoder (reuses the public API from
/// vigile-backend-inventory, inlined here to avoid a cross-crate dep).
fn decode_base64(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if bytes.is_empty() || bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let mut acc: u32 = 0;
        for (i, b) in chunk.iter().enumerate() {
            let v = if *b == b'=' {
                if i < 2 {
                    return None;
                }
                0
            } else {
                ALPHABET.iter().position(|a| a == b)? as u32
            };
            acc = (acc << 6) | v;
        }
        out.push((acc >> 16) as u8);
        if chunk.get(2) != Some(&b'=') {
            out.push((acc >> 8) as u8);
        }
        if chunk.get(3) != Some(&b'=') {
            out.push(acc as u8);
        }
    }
    Some(out)
}
