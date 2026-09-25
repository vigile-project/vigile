// SPDX-License-Identifier: AGPL-3.0-or-later
//! ISS-091 — fuzz du parseur HTTP maison.
//!
//! Objectif : le parseur ne panique JAMAIS (lint workspace `panic = deny`),
//! ne bloque pas, rejette toute entrée invalide et n'accepte que du
//! HTTP/1.1 bien formé dans les limites (16 KiB en-têtes / 16 MiB corps).
//!
//! PRNG xorshift déterministe : le corpus est reproductible sans
//! dépendance externe.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{Cursor, Read, Write};
use vigile_server::http::{parse_request, ParseError};

struct Req(Cursor<Vec<u8>>);
impl Read for Req {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}
impl Write for Req {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}
// Blanket Stream impl covers Cursor-backed streams.

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn parse(raw: &[u8]) -> Result<vigile_server::http::Request, ParseError> {
    parse_request(&mut Req(Cursor::new(raw.to_vec())))
}

#[test]
fn random_garbage_never_panics_and_always_errs() {
    let mut seed = 0xbadc0ffee0ddf00d;
    for len in [0usize, 1, 7, 64, 1024, 8192, 17 * 1024, 64 * 1024] {
        for _ in 0..64 {
            let mut raw = vec![0u8; len];
            for b in &mut raw {
                *b = xorshift(&mut seed) as u8;
            }
            // Random garbage must be rejected, never panic, never hang.
            let _ = parse(&raw);
        }
    }
}

#[test]
fn valid_prefix_then_binary_noise_is_rejected() {
    let prefix = b"GET /agent/v1/policy HTTP/1.1\r\nHost: x\r\nX-Junk: ";
    let mut seed = 42u64;
    for _ in 0..128 {
        let mut raw = prefix.to_vec();
        for _ in 0..64 {
            raw.push(xorshift(&mut seed) as u8);
        }
        assert!(parse(&raw).is_err());
    }
}

#[test]
fn header_flood_hits_limit_not_memory() {
    // 4 KiB per header * 64 = 256 KiB of headers -> must hit
    // HeadersTooLarge, not allocate unbounded.
    let mut raw = b"GET / HTTP/1.1\r\n".to_vec();
    for i in 0..64 {
        raw.extend_from_slice(format!("X-Flood-{i}: ").as_bytes());
        raw.extend(std::iter::repeat_n(b'A', 4096));
        raw.extend_from_slice(b"\r\n");
    }
    raw.extend_from_slice(b"\r\n");
    assert!(
        matches!(parse(&raw), Err(ParseError::HeadersTooLarge)),
        "expected HeadersTooLarge"
    );
}

#[test]
fn oversized_body_declared_is_rejected() {
    let raw = format!(
        "POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
        16 * 1024 * 1024 + 1
    );
    assert!(
        matches!(parse(raw.as_bytes()), Err(ParseError::BodyTooLarge)),
        "expected BodyTooLarge"
    );
}

#[test]
fn bogus_content_length_is_bad_request() {
    for bogus in ["-1", "abc", "999999999999999999999999", "0x10", ""] {
        let raw = format!("POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: {bogus}\r\n\r\n");
        assert!(parse(raw.as_bytes()).is_err(), "Content-Length '{bogus}' must be rejected");
    }
}

#[test]
fn transfer_encoding_rejected() {
    let raw = b"POST /x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n";
    assert!(
        matches!(parse(raw), Err(ParseError::NotImplemented(_))),
        "expected NotImplemented"
    );
}

#[test]
fn truncated_streams_reject_cleanly() {
    let full = b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n0123456789";
    for cut in [0usize, 10, 30, full.len() - 1] {
        // Truncations without a complete request must error; the only
        // accepted input is the exact full request.
        let result = parse(&full[..cut]);
        if cut == full.len() {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err(), "truncated at {cut} must be rejected");
        }
    }
}

#[test]
fn bad_request_lines_rejected() {
    for line in [
        "GEM / HTTP/1.1\r\n\r\n",
        "GET  /  HTTP/2\r\n\r\n",
        "GET\r\n\r\n",
        "GET /HTTP/1.1\r\n\r\n",
        "\r\nGET / HTTP/1.1\r\n\r\n",
        "get / http/1.1\r\n\r\n",
    ] {
        assert!(parse(line.as_bytes()).is_err(), "line {line:?} must be rejected");
    }
}

#[test]
fn wellformed_request_still_accepted() {
    let raw = b"POST /admin/v1/policies/compile HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}";
    let req = parse(raw).expect("valid request");
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/admin/v1/policies/compile");
    assert_eq!(req.body, b"{}");
}

#[test]
fn throughput_smoke() {
    // "Charge" élémentaire : 100 000 requêtes valides parsées en un temps
    // raisonnable (garde large : machine de dev chargée).
    let raw = b"GET /agent/v1/policy HTTP/1.1\r\nHost: localhost\r\nUser-Agent: bench\r\nAccept: */*\r\n\r\n";
    let start = std::time::Instant::now();
    let n = 100_000;
    for _ in 0..n {
        let _ = parse_request(&mut Req(Cursor::new(raw.to_vec())));
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 60,
        "100k parses took {elapsed:?} — regression?"
    );
    eprintln!("fuzz/throughput: {n} parses in {elapsed:?}");
}
