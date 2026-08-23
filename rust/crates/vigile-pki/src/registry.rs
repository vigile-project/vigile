// SPDX-License-Identifier: AGPL-3.0-or-later
//! Agent identity registry (ISS-014): clone detection, snapshot/replay
//! detection and the quarantine state machine.
//!
//! What this layer CAN catch (each mechanism maps to a threat):
//! - same agent id presenting a DIFFERENT machine fingerprint → cloned
//!   image whose machine-id changed (TM-038, SEC-107);
//! - monotonic sequence regression or exact replay → restored old
//!   snapshot or captured-message replay (TM-037/TM-016, SEC-106);
//! - the same machine fingerprint enrolling under a second agent id →
//!   cloned image that ran enrollment again (TM-038).
//!
//! What it CANNOT catch here (documented limit): a clone keeping the
//! exact same fingerprint and agent id, contacting the server
//! non-simultaneously, is indistinguishable from the original at this
//! layer — simultaneous-contact detection lives in the server's
//! connection tracking (ISS-030), and key-rotating renewal plus CRL
//! revocation of the old certificate kills the loser of a rotation race
//! (see tests/rotation.rs t03).
//!
//! Quarantine is STICKY: once quarantined (automatically or by an
//! administrator), every subsequent observation is refused until an
//! explicit `reinstate` (SEC-107: quarantaine automatique en cas
//! d'identité incohérente ; FAILURE_MODES `QUARANTINE`).

use crate::enrollment::EnrolledAgent;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentStatus {
    Active,
    Quarantined,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineReason {
    /// The agent id presented a fingerprint different from enrollment.
    CloneSuspected { expected: String, presented: String },
    /// Sequence went backwards or was replayed (snapshot / capture).
    SequenceRegression { presented: u64, last_seen: u64 },
    /// Administrator decision (e.g. suspected compromise).
    Manual { note: String },
}

#[derive(Debug, Clone)]
pub struct AgentRecord {
    pub agent_id: String,
    pub tenant: String,
    pub machine_fingerprint: String,
    pub certificate_serial: Vec<u8>,
    /// Last accepted monotonic sequence (strictly increasing).
    pub last_sequence: u64,
    pub status: AgentStatus,
    pub quarantine_reason: Option<QuarantineReason>,
    pub enrolled_at_unix: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    UnknownAgent(String),
    Quarantined {
        agent_id: String,
        reason: QuarantineReason,
    },
    CloneSuspected {
        agent_id: String,
        expected: String,
        presented: String,
    },
    SequenceRegression {
        agent_id: String,
        presented: u64,
        last_seen: u64,
    },
    FingerprintInUse {
        fingerprint: String,
        held_by: String,
    },
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryError::UnknownAgent(id) => write!(f, "unknown agent: {id}"),
            RegistryError::Quarantined { agent_id, reason } => {
                write!(f, "agent {agent_id} is quarantined: {reason:?}")
            }
            RegistryError::CloneSuspected {
                agent_id,
                expected,
                presented,
            } => write!(
                f,
                "clone suspected for {agent_id}: enrolled fingerprint {expected}, presented {presented}"
            ),
            RegistryError::SequenceRegression {
                agent_id,
                presented,
                last_seen,
            } => write!(
                f,
                "sequence regression for {agent_id}: presented {presented}, last seen {last_seen}"
            ),
            RegistryError::FingerprintInUse {
                fingerprint,
                held_by,
            } => write!(f, "fingerprint {fingerprint} already enrolled as {held_by}"),
        }
    }
}

impl std::error::Error for RegistryError {}

/// Security events, in order — the in-memory audit trail backing
/// SEC-106/107 tests (the persistent journal comes with ISS-016).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityEvent {
    pub at_unix: i64,
    pub kind: SecurityEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityEventKind {
    Enrolled {
        agent_id: String,
        fingerprint: String,
    },
    CloneRejected {
        agent_id: String,
        expected: String,
        presented: String,
    },
    SequenceRegressionRejected {
        agent_id: String,
        presented: u64,
        last_seen: u64,
    },
    FingerprintReuseRejected {
        fingerprint: String,
        new_agent_id: String,
        held_by: String,
    },
    Quarantined {
        agent_id: String,
        reason: QuarantineReason,
    },
    Reinstated {
        agent_id: String,
    },
}

/// In-memory agent registry. The production implementation persists to
/// PostgreSQL (ISS-016) behind the same semantics.
#[derive(Debug, Default)]
pub struct AgentRegistry {
    agents: HashMap<String, AgentRecord>,
    fingerprint_owners: HashMap<String, String>,
    events: Vec<SecurityEvent>,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl AgentRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a fresh enrollment. Rejects a machine fingerprint that
    /// is already enrolled under another agent id (cloned image that ran
    /// enrollment a second time).
    pub fn register_enrollment(
        &mut self,
        agent_id: &str,
        tenant: &str,
        machine_fingerprint: &str,
        certificate_serial: Vec<u8>,
    ) -> Result<(), RegistryError> {
        if let Some(held_by) = self.fingerprint_owners.get(machine_fingerprint) {
            let held_by = held_by.clone();
            self.record_event(SecurityEventKind::FingerprintReuseRejected {
                fingerprint: machine_fingerprint.to_string(),
                new_agent_id: agent_id.to_string(),
                held_by: held_by.clone(),
            });
            return Err(RegistryError::FingerprintInUse {
                fingerprint: machine_fingerprint.to_string(),
                held_by,
            });
        }
        self.fingerprint_owners
            .insert(machine_fingerprint.to_string(), agent_id.to_string());
        self.agents.insert(
            agent_id.to_string(),
            AgentRecord {
                agent_id: agent_id.to_string(),
                tenant: tenant.to_string(),
                machine_fingerprint: machine_fingerprint.to_string(),
                certificate_serial,
                last_sequence: 0,
                status: AgentStatus::Active,
                quarantine_reason: None,
                enrolled_at_unix: now_unix(),
            },
        );
        self.record_event(SecurityEventKind::Enrolled {
            agent_id: agent_id.to_string(),
            fingerprint: machine_fingerprint.to_string(),
        });
        Ok(())
    }

    /// Convenience wrapper over [`Self::register_enrollment`].
    pub fn register(
        &mut self,
        enrolled: &EnrolledAgent,
        tenant: &str,
    ) -> Result<(), RegistryError> {
        self.register_enrollment(
            &enrolled.agent_id,
            tenant,
            &enrolled.machine_fingerprint,
            enrolled.certificate.serial.clone(),
        )
    }

    /// Records a heartbeat/synchronization observation: checks the
    /// machine fingerprint, then the monotonic sequence.
    pub fn observe(
        &mut self,
        agent_id: &str,
        machine_fingerprint: &str,
        sequence: u64,
    ) -> Result<AgentStatus, RegistryError> {
        let enrolled_fingerprint = {
            let record = self
                .agents
                .get(agent_id)
                .ok_or_else(|| RegistryError::UnknownAgent(agent_id.to_string()))?;
            record.machine_fingerprint.clone()
        };

        if enrolled_fingerprint != machine_fingerprint {
            let reason = QuarantineReason::CloneSuspected {
                expected: enrolled_fingerprint.clone(),
                presented: machine_fingerprint.to_string(),
            };
            self.quarantine_with_event(agent_id, reason);
            return Err(RegistryError::CloneSuspected {
                agent_id: agent_id.to_string(),
                expected: enrolled_fingerprint,
                presented: machine_fingerprint.to_string(),
            });
        }

        self.observe_sequence(agent_id, sequence)
    }

    /// Sequence-only observation, used for authenticated messages whose
    /// identity is proven by the mTLS certificate rather than a
    /// fingerprint (ISS-015). Same strictly-increasing rule; regression
    /// quarantines the agent.
    pub fn observe_sequence(
        &mut self,
        agent_id: &str,
        sequence: u64,
    ) -> Result<AgentStatus, RegistryError> {
        let (last_sequence, quarantine_reason) = {
            let record = self
                .agents
                .get(agent_id)
                .ok_or_else(|| RegistryError::UnknownAgent(agent_id.to_string()))?;
            (
                record.last_sequence,
                if record.status == AgentStatus::Quarantined {
                    Some(
                        record
                            .quarantine_reason
                            .clone()
                            .unwrap_or(QuarantineReason::Manual {
                                note: "unknown".into(),
                            }),
                    )
                } else {
                    None
                },
            )
        };

        if let Some(reason) = quarantine_reason {
            return Err(RegistryError::Quarantined {
                agent_id: agent_id.to_string(),
                reason,
            });
        }

        if sequence <= last_sequence {
            self.quarantine_with_event(
                agent_id,
                QuarantineReason::SequenceRegression {
                    presented: sequence,
                    last_seen: last_sequence,
                },
            );
            return Err(RegistryError::SequenceRegression {
                agent_id: agent_id.to_string(),
                presented: sequence,
                last_seen: last_sequence,
            });
        }

        let record = self
            .agents
            .get_mut(agent_id)
            .ok_or_else(|| RegistryError::UnknownAgent(agent_id.to_string()))?;
        record.last_sequence = sequence;
        Ok(AgentStatus::Active)
    }

    /// Administrator quarantine (e.g. suspected compromise, break-glass
    /// follow-up). Explicit, audited.
    pub fn quarantine(&mut self, agent_id: &str, note: &str) -> Result<(), RegistryError> {
        self.quarantine_with_event(
            agent_id,
            QuarantineReason::Manual {
                note: note.to_string(),
            },
        );
        Ok(())
    }

    /// Administrator reinstatement after review. The monotonic sequence
    /// baseline is kept: the agent must continue above its history.
    pub fn reinstate(&mut self, agent_id: &str) -> Result<(), RegistryError> {
        let record = self
            .agents
            .get_mut(agent_id)
            .ok_or_else(|| RegistryError::UnknownAgent(agent_id.to_string()))?;
        record.status = AgentStatus::Active;
        record.quarantine_reason = None;
        self.record_event(SecurityEventKind::Reinstated {
            agent_id: agent_id.to_string(),
        });
        Ok(())
    }

    pub fn record(&self, agent_id: &str) -> Option<&AgentRecord> {
        self.agents.get(agent_id)
    }

    pub fn events(&self) -> &[SecurityEvent] {
        &self.events
    }

    fn quarantine_with_event(&mut self, agent_id: &str, reason: QuarantineReason) {
        if let Some(record) = self.agents.get_mut(agent_id) {
            record.status = AgentStatus::Quarantined;
            record.quarantine_reason = Some(reason.clone());
        }
        self.record_event(SecurityEventKind::Quarantined {
            agent_id: agent_id.to_string(),
            reason,
        });
    }

    fn record_event(&mut self, kind: SecurityEventKind) {
        self.events.push(SecurityEvent {
            at_unix: now_unix(),
            kind,
        });
    }
}
