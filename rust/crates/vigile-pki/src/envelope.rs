// SPDX-License-Identifier: AGPL-3.0-or-later
//! Anti-replay message envelope (ISS-015, SEC-106) — the `agent/v1`
//! wire format of AGENT_PROTOCOL.md §3.
//!
//! Verification order (each failure is a distinct error):
//! protocol version → timestamp freshness (bounded clock drift) →
//! server nonce (single outstanding nonce per agent, rotated at every
//! accepted message) → monotonic sequence (delegated to the agent
//! registry, which quarantines on regression) → request-id format.
//!
//! Notes:
//! - a rejected message does NOT consume the outstanding nonce: a
//!   transient clock issue never desynchronizes agent and server;
//! - the request-id is validated for format; response idempotence
//!   deduplication belongs to the HTTP API layer (ISS-030);
//! - placement: these types live here for now (shared by agent and
//!   server, identity-adjacent); extraction into a dedicated
//!   `vigile-proto` crate may happen at ISS-030 without semantic change.

use crate::enrollment::hex_encode;
use crate::registry::{AgentRegistry, RegistryError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;

pub const PROTOCOL: &str = "agent/v1";
/// Bounded tolerated clock drift — proposal DEC-09 (± 10 minutes).
pub const DEFAULT_MAX_CLOCK_SKEW_SECS: i64 = 600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    Malformed(String),
    ProtocolMismatch {
        presented: String,
    },
    MalformedTimestamp(String),
    TimestampOutOfWindow {
        skew_secs: i64,
        delta_secs: i64,
    },
    UnknownAgentNonce {
        agent_id: String,
    },
    WrongNonce {
        agent_id: String,
    },
    BadRequestId,
    UnknownAgent {
        agent_id: String,
    },
    Quarantined {
        agent_id: String,
    },
    SequenceRegression {
        agent_id: String,
        presented: u64,
        last_seen: u64,
    },
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvelopeError::Malformed(e) => write!(f, "malformed envelope: {e}"),
            EnvelopeError::ProtocolMismatch { presented } => {
                write!(f, "protocol mismatch: {presented} (expected {PROTOCOL})")
            }
            EnvelopeError::MalformedTimestamp(t) => write!(f, "malformed RFC3339 timestamp: {t}"),
            EnvelopeError::TimestampOutOfWindow {
                skew_secs,
                delta_secs,
            } => write!(
                f,
                "timestamp out of window: |delta| = {delta_secs}s > skew {skew_secs}s"
            ),
            EnvelopeError::UnknownAgentNonce { agent_id } => {
                write!(f, "no outstanding server nonce for {agent_id}")
            }
            EnvelopeError::WrongNonce { agent_id } => {
                write!(f, "wrong server nonce for {agent_id}")
            }
            EnvelopeError::BadRequestId => write!(f, "request id must be 32 hex characters"),
            EnvelopeError::UnknownAgent { agent_id } => write!(f, "unknown agent: {agent_id}"),
            EnvelopeError::Quarantined { agent_id } => write!(f, "agent {agent_id} is quarantined"),
            EnvelopeError::SequenceRegression {
                agent_id,
                presented,
                last_seen,
            } => write!(
                f,
                "sequence regression for {agent_id}: {presented} <= {last_seen}"
            ),
        }
    }
}

impl std::error::Error for EnvelopeError {}

impl From<RegistryError> for EnvelopeError {
    fn from(e: RegistryError) -> Self {
        match e {
            RegistryError::UnknownAgent(id) => EnvelopeError::UnknownAgent { agent_id: id },
            RegistryError::Quarantined { agent_id, .. } => EnvelopeError::Quarantined { agent_id },
            RegistryError::SequenceRegression {
                agent_id,
                presented,
                last_seen,
            } => EnvelopeError::SequenceRegression {
                agent_id,
                presented,
                last_seen,
            },
            other => EnvelopeError::Malformed(other.to_string()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MessageKind {
    Heartbeat,
    Events,
    PolicyResult,
    ApprovalRequest,
}

/// The `agent/v1` message envelope (strict schema: unknown fields are
/// rejected — SEC-208).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageEnvelope {
    pub protocol: String,
    pub agent_id: String,
    pub sequence: u64,
    pub server_nonce: String,
    pub timestamp: String,
    pub request_id: String,
    pub kind: MessageKind,
    pub body: serde_json::Value,
}

/// Issued to an agent at enrollment/first heartbeat; every accepted
/// message rotates it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextRound {
    pub next_nonce: String,
}

/// Verifies envelopes: timestamp freshness + server nonce. The monotonic
/// sequence is enforced through the agent registry.
pub struct EnvelopeVerifier {
    max_clock_skew_secs: i64,
    /// One outstanding nonce per agent.
    outstanding: HashMap<String, String>,
}

impl Default for EnvelopeVerifier {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_CLOCK_SKEW_SECS)
    }
}

impl EnvelopeVerifier {
    pub fn new(max_clock_skew_secs: i64) -> Self {
        Self {
            max_clock_skew_secs,
            outstanding: HashMap::new(),
        }
    }

    /// Issues the initial nonce for an agent (enrollment / first contact).
    pub fn issue_nonce(&mut self, agent_id: &str) -> Result<String, EnvelopeError> {
        let nonce = random_hex()?;
        self.outstanding.insert(agent_id.to_string(), nonce.clone());
        Ok(nonce)
    }

    /// The nonce the given agent must present in its NEXT message. The
    /// server embeds it in every response (and at enrollment).
    pub fn outstanding_nonce(&self, agent_id: &str) -> Option<String> {
        self.outstanding.get(agent_id).cloned()
    }

    /// Full verification: nonce + freshness here, sequence via the
    /// registry. On success the nonce is rotated and returned.
    /// The registry side effects (quarantine on regression) happen even
    /// when this function returns an error from a LATER check.
    pub fn verify(
        &mut self,
        registry: &mut AgentRegistry,
        envelope: &MessageEnvelope,
        now: SystemTime,
    ) -> Result<NextRound, EnvelopeError> {
        if envelope.protocol != PROTOCOL {
            return Err(EnvelopeError::ProtocolMismatch {
                presented: envelope.protocol.clone(),
            });
        }

        let timestamp = time::OffsetDateTime::parse(
            &envelope.timestamp,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|e| EnvelopeError::MalformedTimestamp(e.to_string()))?;
        let delta = timestamp.unix_timestamp() - unix_secs(now);
        if delta.abs() > self.max_clock_skew_secs {
            return Err(EnvelopeError::TimestampOutOfWindow {
                skew_secs: self.max_clock_skew_secs,
                delta_secs: delta,
            });
        }

        // Nonce BEFORE sequence: a wrong nonce never touches the registry.
        let expected = self
            .outstanding
            .get(&envelope.agent_id)
            .ok_or_else(|| EnvelopeError::UnknownAgentNonce {
                agent_id: envelope.agent_id.clone(),
            })?
            .clone();
        if envelope.server_nonce != expected {
            return Err(EnvelopeError::WrongNonce {
                agent_id: envelope.agent_id.clone(),
            });
        }

        if !is_32_hex(&envelope.request_id) {
            return Err(EnvelopeError::BadRequestId);
        }

        registry.observe_sequence(&envelope.agent_id, envelope.sequence)?;

        // Everything accepted: rotate the nonce.
        let next_nonce = random_hex()?;
        self.outstanding
            .insert(envelope.agent_id.clone(), next_nonce.clone());
        Ok(NextRound { next_nonce })
    }
}

fn unix_secs(t: SystemTime) -> i64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn is_32_hex(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn random_hex() -> Result<String, EnvelopeError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|e| EnvelopeError::Malformed(format!("RNG unavailable: {e}")))?;
    Ok(hex_encode(&bytes))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    #[test]
    fn request_id_format() {
        assert!(is_32_hex("0123456789abcdef0123456789abcdef"));
        assert!(!is_32hex_bad());
    }

    fn is_32hex_bad() -> bool {
        is_32_hex("nope") || is_32_hex(&"a".repeat(33))
    }
}
