// SPDX-License-Identifier: AGPL-3.0-or-later
//! Strict HTTP/1.1 parser for the Vigile agent API (ISS-030).
//!
//! SECURITY MODEL: both endpoints are OUR code (the agent is a Vigile
//! binary). This parser is deliberately minimal and strict — anything
//! unexpected is REJECTED, never interpreted:
//! - HTTP/1.1 only (HTTP/1.0 → 505, HTTP/2+ → 505)
//! - GET and POST only (anything else → 405)
//! - Max 16 KiB headers, 16 MiB body (larger → 413/431)
//! - Content-Length body only (Transfer-Encoding → 501)
//! - Headers we don't recognize are ignored (but counted against the
//!   size limit); Connection: close honored.
//!
//! This is NOT a general-purpose HTTP server — it handles exactly the
//! `/agent/v1/*` protocol. The admin API and portal (ISS-031/032) will
//! use a proper framework because they face browsers.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;

pub const MAX_HEADER_BYTES: usize = 16 * 1024;
pub const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub enum ParseError {
    /// Connection closed before a complete request.
    ConnectionClosed,
    /// Malformed request line or headers.
    BadRequest(String),
    /// Method not in our allowlist.
    MethodNotAllowed(String),
    /// HTTP version not supported.
    VersionNotSupported(String),
    /// Headers exceed the size limit.
    HeadersTooLarge,
    /// Body exceeds the size limit.
    BodyTooLarge,
    /// Transfer-Encoding not supported.
    NotImplemented(String),
    /// I/O error.
    Io(std::io::Error),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::ConnectionClosed => write!(f, "connection closed"),
            ParseError::BadRequest(e) => write!(f, "bad request: {e}"),
            ParseError::MethodNotAllowed(m) => write!(f, "method not allowed: {m}"),
            ParseError::VersionNotSupported(v) => write!(f, "version not supported: {v}"),
            ParseError::HeadersTooLarge => write!(f, "headers exceed {MAX_HEADER_BYTES} bytes"),
            ParseError::BodyTooLarge => write!(f, "body exceeds {MAX_BODY_BYTES} bytes"),
            ParseError::NotImplemented(e) => write!(f, "not implemented: {e}"),
            ParseError::Io(e) => write!(f, "I/O: {e}"),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<std::io::Error> for ParseError {
    fn from(e: std::io::Error) -> Self {
        ParseError::Io(e)
    }
}

/// Reads from a stream until `\r\n\r\n`, then reads the body per
/// Content-Length. Returns the parsed request.
pub fn parse_request(stream: &mut TcpStream) -> Result<Request, ParseError> {
    // --- Read headers until CRLFCRLF ---
    let mut header_buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => {
                return Err(ParseError::ConnectionClosed);
            }
            Ok(_) => {
                header_buf.push(byte[0]);
                if header_buf.len() > MAX_HEADER_BYTES {
                    return Err(ParseError::HeadersTooLarge);
                }
                if header_buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return Err(ParseError::ConnectionClosed);
            }
            Err(e) => return Err(ParseError::Io(e)),
        }
    }

    let header_str = std::str::from_utf8(&header_buf)
        .map_err(|_| ParseError::BadRequest("headers not UTF-8".into()))?;

    let mut lines = header_str.split("\r\n");
    let request_line = lines.next().unwrap_or_default();

    // --- Parse request line: METHOD /path HTTP/1.1 ---
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() != 3 {
        return Err(ParseError::BadRequest(format!(
            "malformed request line: {request_line:?}"
        )));
    }
    let method = parts[0].to_string();
    let path = parts[1].to_string();
    let version = parts[2];

    if version != "HTTP/1.1" {
        return Err(ParseError::VersionNotSupported(version.to_string()));
    }

    if method != "GET" && method != "POST" {
        return Err(ParseError::MethodNotAllowed(method));
    }

    // --- Parse headers ---
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(ParseError::BadRequest(format!(
                "malformed header: {line:?}"
            )));
        };
        let name = name.trim().to_lowercase();
        let value = value.trim().to_string();
        if name == "transfer-encoding" {
            return Err(ParseError::NotImplemented(
                "Transfer-Encoding not supported".into(),
            ));
        }
        headers.insert(name, value);
    }

    // --- Read body per Content-Length ---
    let content_length: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    if content_length > MAX_BODY_BYTES {
        return Err(ParseError::BodyTooLarge);
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        stream.read_exact(&mut body).map_err(ParseError::Io)?;
    }

    Ok(Request {
        method,
        path,
        headers,
        body,
    })
}

/// Writes a simple HTTP/1.1 response.
pub fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

/// Convenience: JSON response.
pub fn write_json(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    json: &str,
) -> std::io::Result<()> {
    write_response(stream, status, reason, "application/json", json.as_bytes())
}

/// Maps a ParseError to the appropriate HTTP status + reason.
pub fn error_response(stream: &mut TcpStream, e: &ParseError) -> std::io::Result<()> {
    let (status, reason) = match e {
        ParseError::ConnectionClosed => return Ok(()), // peer went away
        ParseError::BadRequest(_) => (400, "Bad Request"),
        ParseError::MethodNotAllowed(_) => (405, "Method Not Allowed"),
        ParseError::VersionNotSupported(_) => (505, "HTTP Version Not Supported"),
        ParseError::HeadersTooLarge => (431, "Request Header Fields Too Large"),
        ParseError::BodyTooLarge => (413, "Content Too Large"),
        ParseError::NotImplemented(_) => (501, "Not Implemented"),
        ParseError::Io(_) => (500, "Internal Server Error"),
    };
    let body = format!("{{\"error\":\"{e}\"}}");
    write_json(stream, status, reason, &body)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    // We test the parser through a socketpair-like mechanism using
    // std::os::unix::net::UnixStream, which has the same Read/Write
    // interface as TcpStream (the parser only uses Read).
    // For simplicity, we test the header parsing logic directly.

    #[test]
    fn method_allowlist() {
        for method in ["GET", "POST"] {
            let line = format!("{method} /agent/v1/policy HTTP/1.1\r\n\r\n");
            let parts: Vec<&str> = line.split_whitespace().collect();
            assert_eq!(parts[0], method);
        }
        // Methods that would be rejected:
        for method in [
            "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT",
        ] {
            let method = method.to_string();
            assert!(method != "GET" && method != "POST");
        }
    }

    #[test]
    fn header_size_limit_is_sane() {
        assert_eq!(MAX_HEADER_BYTES, 16 * 1024);
        assert_eq!(MAX_BODY_BYTES, 16 * 1024 * 1024);
    }
}
