// SPDX-License-Identifier: AGPL-3.0-or-later
//! Server integration tests (ISS-030): HTTP routing + enrollment +
//! mTLS-certificate-based agent identification + hostile inputs.
//!
//! These tests use plain TCP (not TLS) to verify the HTTP routing and
//! business logic. TLS termination is tested separately via the mTLS
//! tests in vigile-pki.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use vigile_server::{http, routes, ServerState};

/// Starts a test server on an ephemeral port, returns (port, state).
fn start_test_server() -> (u16, std::sync::Arc<std::sync::Mutex<ServerState>>) {
    let state = std::sync::Arc::new(std::sync::Mutex::new(
        ServerState::lab().expect("server state"),
    ));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let s = std::sync::Arc::clone(&state);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let Ok(mut st) = s.lock() else { continue };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            match http::parse_request(&mut stream) {
                Ok(request) => {
                    let _ = routes::route(&mut stream, &request, &mut st, None);
                }
                Err(e) => {
                    let _ = http::error_response(&mut stream, &e);
                }
            }
        }
    });
    (port, state)
}

fn send_raw(port: u16, raw: &[u8]) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.write_all(raw).expect("write");
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap_or_default();
    response
}

fn send_json(port: u16, method: &str, path: &str, body: &str) -> String {
    let raw = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    send_raw(port, raw.as_bytes())
}

fn enrollment_request_body(token: &str, csr_der: &[u8], fingerprint: &str) -> String {
    // Inline JSON: token + base64 CSR + fingerprint.
    let csr_b64 = base64_encode(csr_der);
    serde_json::json!({
        "token": token,
        "csr_der": csr_b64,
        "machine_fingerprint": fingerprint,
    })
    .to_string()
}

fn base64_encode(data: &[u8]) -> String {
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

#[test]
fn t30_01_health_check_unknown_route() {
    let (port, _state) = start_test_server();
    let response = send_json(port, "GET", "/", "");
    assert!(response.starts_with("HTTP/1.1 404"), "{response}");
}

#[test]
fn t30_02_enroll_with_valid_token() {
    let (port, state) = start_test_server();

    // Issue a token.
    let token = {
        let st = state.lock().unwrap();
        st.enrollment_issuer
            .issue("default", None, 3600, std::time::SystemTime::now())
            .expect("token")
    };

    // Generate an agent CSR.
    let csr = vigile_pki::generate_agent_csr().expect("CSR");
    let body = enrollment_request_body(&token, &csr.csr_der, "machine-id:test-server-01");

    let response = send_json(port, "POST", "/agent/v1/enroll", &body);
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains("agent_id"), "{response}");
    assert!(response.contains("certificate"), "{response}");
    assert!(response.contains("server_nonce"), "{response}");
}

#[test]
fn t30_03_enroll_replay_rejected() {
    let (port, state) = start_test_server();

    let token = {
        let st = state.lock().unwrap();
        st.enrollment_issuer
            .issue("default", None, 3600, std::time::SystemTime::now())
            .expect("token")
    };

    let csr = vigile_pki::generate_agent_csr().expect("CSR");
    let body = enrollment_request_body(&token, &csr.csr_der, "machine-id:test-replay");

    // First enrollment: success.
    let response = send_json(port, "POST", "/agent/v1/enroll", &body);
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");

    // Same token: rejected.
    let csr2 = vigile_pki::generate_agent_csr().expect("CSR 2");
    let body2 = enrollment_request_body(&token, &csr2.csr_der, "machine-id:test-replay-2");
    let response = send_json(port, "POST", "/agent/v1/enroll", &body2);
    assert!(response.starts_with("HTTP/1.1 401"), "{response}");
    assert!(response.contains("already used"), "{response}");
}

#[test]
fn t30_04_enroll_with_expired_token() {
    let (port, state) = start_test_server();

    let token = {
        let st = state.lock().unwrap();
        st.enrollment_issuer
            .issue(
                "default",
                None,
                1,
                std::time::SystemTime::now() - Duration::from_secs(3600),
            )
            .expect("token")
    };

    let csr = vigile_pki::generate_agent_csr().expect("CSR");
    let body = enrollment_request_body(&token, &csr.csr_der, "machine-id:test-expired");
    let response = send_json(port, "POST", "/agent/v1/enroll", &body);
    assert!(response.starts_with("HTTP/1.1 401"), "{response}");
    assert!(response.contains("expired"), "{response}");
}

#[test]
fn t30_05_enroll_malformed_json() {
    let (port, _state) = start_test_server();
    let response = send_json(port, "POST", "/agent/v1/enroll", "not json");
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");
}

#[test]
fn t30_06_method_not_allowed() {
    let (port, _state) = start_test_server();
    let response = send_json(port, "DELETE", "/agent/v1/enroll", "");
    assert!(response.starts_with("HTTP/1.1 405"), "{response}");
}

#[test]
fn t30_07_http_version_rejected() {
    let (port, _state) = start_test_server();
    let raw = b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
    let response = send_raw(port, raw);
    assert!(response.starts_with("HTTP/1.1 505"), "{response}");
}

#[test]
fn t30_08_transfer_encoding_rejected() {
    let (port, _state) = start_test_server();
    let raw =
        b"POST /agent/v1/enroll HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n";
    let response = send_raw(port, raw);
    assert!(response.starts_with("HTTP/1.1 501"), "{response}");
}

#[test]
fn t30_09_oversized_headers_rejected() {
    let (port, _state) = start_test_server();
    // Send a request with a header line > 16 KiB.
    let huge_header = format!("X-Junk: {}\r\n", "A".repeat(20 * 1024));
    let raw = format!("GET / HTTP/1.1\r\nHost: localhost\r\n{huge_header}\r\n");
    let response = send_raw(port, raw.as_bytes());
    assert!(response.starts_with("HTTP/1.1 431"), "{response}");
}

#[test]
fn t30_10_connection_closed_mid_request() {
    let (port, _state) = start_test_server();
    // Connect and immediately close.
    let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    drop(stream);
    // Server should handle this without crashing (tested by the fact
    // that the test server thread is still alive).
    let response = send_json(port, "GET", "/", "");
    assert!(
        response.starts_with("HTTP/1.1 404"),
        "server still alive: {response}"
    );
}

#[test]
fn t30_11_heartbeat_without_mtls_rejected() {
    let (port, _state) = start_test_server();
    let response = send_json(port, "POST", "/agent/v1/heartbeat", "{}");
    assert!(response.starts_with("HTTP/1.1 401"), "{response}");
    assert!(response.contains("mTLS required"), "{response}");
}

#[test]
fn t30_12_policy_without_mtls_rejected() {
    let (port, _state) = start_test_server();
    let response = send_json(port, "GET", "/agent/v1/policy", "");
    assert!(response.starts_with("HTTP/1.1 401"), "{response}");
}

#[test]
fn t30_13_binary_garbage_rejected() {
    let (port, _state) = start_test_server();
    let garbage = [0xFFu8, 0x00, 0xDE, 0xAD, 0xBE, 0xEF].repeat(32);
    let response = send_raw(port, &garbage);
    // Should get a 400 (bad request line) or connection just closes.
    assert!(
        response.is_empty()
            || response.starts_with("HTTP/1.1 400")
            || response.starts_with("HTTP/1.1 405"),
        "unexpected response to binary garbage: {response}"
    );
}
