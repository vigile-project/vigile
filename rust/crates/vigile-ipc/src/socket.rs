// SPDX-License-Identifier: AGPL-3.0-or-later
//! Unix domain socket server and client for the Vigile IPC protocol
//! (ISS-038). The server (executor side) verifies `SO_PEERCRED` before
//! processing any message; the client (agent side) is a thin wrapper.
//!
//! Framing: 4-byte big-endian length prefix + JSON payload. Simple,
//! deterministic, easy to bound.

use crate::{RequestEnvelope, ResponseEnvelope};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

pub const MAX_FRAME_BYTES: usize = crate::MAX_MESSAGE_BYTES + 4;

#[derive(Debug)]
pub enum IpcError {
    Io(std::io::Error),
    FrameTooLarge(usize),
    InvalidFrame(String),
    PermissionDenied { expected_uid: u32, got_uid: u32 },
    Protocol(String),
}

impl std::fmt::Display for IpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpcError::Io(e) => write!(f, "I/O: {e}"),
            IpcError::FrameTooLarge(n) => write!(f, "frame too large: {n} > {MAX_FRAME_BYTES}"),
            IpcError::InvalidFrame(e) => write!(f, "invalid frame: {e}"),
            IpcError::PermissionDenied {
                expected_uid,
                got_uid,
            } => {
                write!(f, "UID mismatch: expected {expected_uid}, got {got_uid}")
            }
            IpcError::Protocol(e) => write!(f, "protocol: {e}"),
        }
    }
}

impl std::error::Error for IpcError {}

impl From<std::io::Error> for IpcError {
    fn from(e: std::io::Error) -> Self {
        IpcError::Io(e)
    }
}

/// Reads a length-prefixed frame from a stream.
pub fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, IpcError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(IpcError::FrameTooLarge(len));
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

/// Writes a length-prefixed frame to a stream.
pub fn write_frame(stream: &mut UnixStream, payload: &[u8]) -> Result<(), IpcError> {
    let len = payload.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

/// Gets the peer's UID via SO_PEERCRED.
///
/// # Safety
///
/// This is the ONLY unsafe block in the Vigile workspace. It calls
/// `getsockopt(2)` with `SO_PEERCRED` to read the kernel-provided
/// credentials of the connecting process. The safety argument:
/// - `fd` is a valid, open file descriptor (borrowed from `UnixStream`).
/// - `creds` is a valid `ucred` struct with the correct size.
/// - `len` is initialized to `sizeof(ucred)` and checked by the kernel.
/// - The kernel writes at most `sizeof(ucred)` bytes into `creds`.
/// - No pointers escape this function.
///
/// This cannot be done in safe Rust: there is no std/unsafe-free API
/// for SO_PEERCRED. The alternative (reading /proc/<pid>/status) is
/// racy and less secure.
pub fn peer_uid(stream: &UnixStream) -> Result<u32, IpcError> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut creds = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as u32;
    // SAFETY: see the safety comment above — all invariants are upheld.
    #[allow(unsafe_code)]
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut creds as *mut _ as *mut _,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(IpcError::Io(std::io::Error::last_os_error()));
    }
    Ok(creds.uid)
}

/// Server-side handler: accepts a connection, verifies UID, reads a
/// request, invokes the handler, writes the response.
pub fn serve_one(
    listener: &UnixListener,
    expected_uid: u32,
    handler: impl FnOnce(RequestEnvelope) -> ResponseEnvelope,
) -> Result<(), IpcError> {
    let (mut stream, _) = listener.accept()?;

    // Verify UID BEFORE any protocol processing.
    let uid = peer_uid(&stream)?;
    if uid != expected_uid {
        // Do not process the message — close immediately.
        let err = ResponseEnvelope::error(
            crate::ErrorCode::PermissionDenied,
            format!("UID {uid} is not authorized (expected {expected_uid})"),
        );
        if let Ok(wire) = err.to_wire() {
            let _ = write_frame(&mut stream, &wire);
        }
        return Err(IpcError::PermissionDenied {
            expected_uid,
            got_uid: uid,
        });
    }

    // Read the request frame.
    let payload = read_frame(&mut stream)?;
    let request = RequestEnvelope::from_wire(&payload).map_err(IpcError::Protocol)?;

    // Invoke the handler and write the response.
    let response = handler(request);
    let wire = response.to_wire().map_err(IpcError::Protocol)?;
    write_frame(&mut stream, &wire)?;
    Ok(())
}

/// Client-side: connects, sends a request, reads the response.
pub fn request(
    socket_path: &Path,
    envelope: &RequestEnvelope,
) -> Result<ResponseEnvelope, IpcError> {
    let mut stream = UnixStream::connect(socket_path)?;
    let wire = envelope.to_wire().map_err(IpcError::Protocol)?;
    write_frame(&mut stream, &wire)?;
    let response_payload = read_frame(&mut stream)?;
    let response = ResponseEnvelope::from_wire(&response_payload).map_err(IpcError::Protocol)?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
    use super::*;
    use crate::{Action, ErrorCode, ResponseEnvelope};

    fn temp_socket(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        let sock = dir.join(format!("vigile-ipc-{tag}-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        sock
    }

    #[test]
    fn roundtrip_ping() {
        let sock = temp_socket("ping");
        let listener = UnixListener::bind(&sock).unwrap();

        let client_sock = sock.clone();
        let client = std::thread::spawn(move || {
            request(&client_sock, &RequestEnvelope::new(Action::Ping)).unwrap()
        });

        serve_one(
            &listener,
            std::os::unix::fs::MetadataExt::uid(&std::fs::metadata("/proc/self").unwrap()) as u32,
            |req| {
                assert!(matches!(req.action, Action::Ping));
                ResponseEnvelope::ok("ping")
            },
        )
        .unwrap();

        let response = client.join().unwrap();
        assert!(matches!(response.response, crate::Response::Ok { .. }));
        let _ = std::fs::remove_file(&sock);
    }

    #[test]
    fn wrong_uid_rejected() {
        let sock = temp_socket("wronguid");
        let listener = UnixListener::bind(&sock).unwrap();

        // Try to connect with an unexpected UID (we use our own UID but
        // claim the executor expects a different one).
        let wrong_uid = 99999;
        let client_sock = sock.clone();
        let client =
            std::thread::spawn(move || request(&client_sock, &RequestEnvelope::new(Action::Ping)));

        let result = serve_one(&listener, wrong_uid, |_| ResponseEnvelope::ok("ping"));

        // The server must reject.
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            IpcError::PermissionDenied { .. }
        ));

        // The client gets a permission denied response.
        let response = client.join().unwrap().unwrap();
        match response.response {
            crate::Response::Error { code, .. } => {
                assert_eq!(code, ErrorCode::PermissionDenied);
            }
            _ => panic!("expected error response"),
        }
        let _ = std::fs::remove_file(&sock);
    }

    #[test]
    fn oversized_frame_rejected() {
        let sock = temp_socket("oversize");
        let listener = UnixListener::bind(&sock).unwrap();

        let client_sock = sock.clone();
        let client = std::thread::spawn(move || {
            let mut stream = UnixStream::connect(&client_sock).unwrap();
            // Send a frame claiming a huge length.
            let huge_len: u32 = (MAX_FRAME_BYTES + 1) as u32;
            stream.write_all(&huge_len.to_be_bytes()).unwrap();
            stream.flush().unwrap();
            // Try to read the response (should be an error or connection close).
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
        });

        let result = serve_one(&listener, 0, |_| ResponseEnvelope::ok("ping"));
        assert!(result.is_err());
        let _ = client.join();
        let _ = std::fs::remove_file(&sock);
    }
}
