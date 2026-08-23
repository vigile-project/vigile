// SPDX-License-Identifier: AGPL-3.0-or-later
//! Server-side audit journal (ISS-033): append-only with SHA-256 hash
//! chaining. Each entry's hash covers the previous hash + the entry
//! content, making any alteration detectable (SEC-702).
//!
//! In-memory for the MVP; the PostgreSQL implementation uses the
//! `agents.security_events` table (already append-only via trigger,
//! ISS-016) — this module provides the chaining layer on top.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditEntry {
    /// Monotonic sequence number.
    pub seq: u64,
    /// Unix seconds.
    pub at_unix: i64,
    /// Who performed the action (admin token id, "system", agent id…).
    pub actor: String,
    /// What was done (e.g., "enrollment.completed", "agent.quarantined").
    pub action: String,
    /// What it was done to (agent id, policy id…).
    pub target: String,
    /// Result: "ok" | "denied" | "error:<detail>".
    pub result: String,
    /// SHA-256 of (previous_hash || serialized_entry_without_hash).
    pub hash: String,
}

#[derive(Debug)]
pub struct AuditJournal {
    entries: Vec<AuditEntry>,
    /// Hash of the last entry (empty string for the genesis state).
    last_hash: String,
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Content that gets hashed (everything except the hash itself).
#[derive(Serialize)]
struct HashableEntry<'a> {
    seq: u64,
    at_unix: i64,
    actor: &'a str,
    action: &'a str,
    target: &'a str,
    result: &'a str,
}

impl AuditJournal {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            last_hash: String::new(),
        }
    }

    /// Appends an entry, computing the chained hash. Returns a reference
    /// to the stored entry.
    pub fn append(&mut self, actor: &str, action: &str, target: &str, result: &str) -> &AuditEntry {
        let seq = self.entries.len() as u64 + 1;
        let at_unix = now_unix();

        let hashable = HashableEntry {
            seq,
            at_unix,
            actor,
            action,
            target,
            result,
        };
        let content = serde_json::to_string(&hashable).unwrap_or_default();

        // hash = SHA-256(previous_hash || content)
        let mut hash_input = Vec::with_capacity(self.last_hash.len() + content.len());
        hash_input.extend_from_slice(self.last_hash.as_bytes());
        hash_input.extend_from_slice(content.as_bytes());
        let hash = sha256_hex(&hash_input);

        let entry = AuditEntry {
            seq,
            at_unix,
            actor: actor.to_string(),
            action: action.to_string(),
            target: target.to_string(),
            result: result.to_string(),
            hash: hash.clone(),
        };

        self.last_hash = hash;
        self.entries.push(entry);
        // `last()` ne peut pas échouer : nous venons de pousser.
        // Contournement du lint expect_used (interdit en production).
        match self.entries.last() {
            Some(entry) => entry,
            None => unreachable!("entries cannot be empty after push"),
        }
    }

    /// Returns all entries (read-only access for the admin API).
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Verifies the integrity of the entire chain: recomputes every hash
    /// and checks it matches. Returns the number of verified entries.
    /// Any mismatch returns an error with the sequence number.
    pub fn verify_chain(&self) -> Result<u64, (u64, String)> {
        let mut prev_hash = String::new();
        for entry in &self.entries {
            let hashable = HashableEntry {
                seq: entry.seq,
                at_unix: entry.at_unix,
                actor: &entry.actor,
                action: &entry.action,
                target: &entry.target,
                result: &entry.result,
            };
            let content = serde_json::to_string(&hashable).unwrap_or_default();
            let mut hash_input = Vec::with_capacity(prev_hash.len() + content.len());
            hash_input.extend_from_slice(prev_hash.as_bytes());
            hash_input.extend_from_slice(content.as_bytes());
            let expected = sha256_hex(&hash_input);

            if expected != entry.hash {
                return Err((
                    entry.seq,
                    format!(
                        "hash mismatch at seq {}: expected {expected}, got {}",
                        entry.seq, entry.hash
                    ),
                ));
            }
            prev_hash = entry.hash.clone();
        }
        Ok(self.entries.len() as u64)
    }

    /// Returns the head hash (empty string if no entries).
    pub fn head_hash(&self) -> &str {
        &self.last_hash
    }

    /// Mutable access to entries — visible for integration tests that
    /// simulate tampering. In production, the append-only property is
    /// enforced by the PostgreSQL trigger (ISS-016); this method exists
    /// because integration tests live outside `cfg(test)` of this crate.
    /// Do NOT call outside of tests.
    #[doc(hidden)]
    pub fn entries_mut_for_test(&mut self) -> &mut Vec<AuditEntry> {
        &mut self.entries
    }
}

impl Default for AuditJournal {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    #[test]
    fn chain_is_valid_after_appends() {
        let mut journal = AuditJournal::new();
        journal.append("system", "startup", "server", "ok");
        journal.append("admin-token-1", "enrollment.completed", "agent-001", "ok");
        journal.append("admin-token-1", "agent.quarantined", "agent-002", "ok");

        assert_eq!(journal.verify_chain().unwrap(), 3);
        assert!(!journal.head_hash().is_empty());
    }

    #[test]
    fn chain_detects_tampering() {
        let mut journal = AuditJournal::new();
        journal.append("system", "startup", "server", "ok");
        journal.append("admin-1", "action", "target", "ok");

        // Simulate tampering: modify an entry in place.
        // (In production this would require a memory-safety bug or a
        // database compromise — the chain makes it DETECTABLE either way.)
        let original = journal.entries[1].result.clone();
        journal.entries[1].result = "tampered".to_string();

        let err = journal.verify_chain().unwrap_err();
        assert_eq!(err.0, 2, "tampering detected at the modified entry");

        // Restore and verify again.
        journal.entries[1].result = original;
        assert!(journal.verify_chain().is_ok());
    }

    #[test]
    fn chain_detects_deletion() {
        let mut journal = AuditJournal::new();
        journal.append("system", "startup", "server", "ok");
        journal.append("admin-1", "action-1", "target-1", "ok");
        journal.append("admin-1", "action-2", "target-2", "ok");

        // Simulate deletion of a middle entry.
        journal.entries.remove(1);

        // The chain is now broken: entry 3's hash references entry 2's
        // hash which no longer exists.
        let result = journal.verify_chain();
        assert!(result.is_err(), "deletion must be detected");
    }

    #[test]
    fn empty_journal_verifies() {
        let journal = AuditJournal::new();
        assert_eq!(journal.verify_chain().unwrap(), 0);
        assert_eq!(journal.head_hash(), "");
    }

    #[test]
    fn sequence_numbers_are_monotonic() {
        let mut journal = AuditJournal::new();
        for i in 0..10 {
            journal.append("test", &format!("action-{i}"), "target", "ok");
        }
        for (i, entry) in journal.entries.iter().enumerate() {
            assert_eq!(entry.seq, (i + 1) as u64);
        }
    }
}
