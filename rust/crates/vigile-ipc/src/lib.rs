// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vigile IPC — narrow local protocol between the unprivileged agent and
//! the privileged executor (ADR-0002, trust boundary TB-2,
//! docs/AGENT_PROTOCOL.md §6).
//!
//! Skeleton (sprint 1): constants only. The closed action catalogue
//! (Ping, GetState, StageArtifacts, ValidateArtifacts, Commit, Rollback,
//! HealthCheck, AckGeneration), CBOR framing, SO_PEERCRED auth and fuzzing
//! land with ISS-038. Adding an action = major protocol version bump plus
//! a dedicated threat-analysis review.

/// Version of the local IPC protocol.
pub const IPC_PROTOCOL_VERSION: &str = "ipc/v1";

/// Maximum accepted message size (proposal — DEC-09).
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
