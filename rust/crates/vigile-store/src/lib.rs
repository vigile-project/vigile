// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vigile persistent store (ISS-016, ADR-0007): PostgreSQL schemas,
//! embedded ordered migrations, and `PgStore` — the persistent twin of
//! `vigile_pki::AgentRegistry` (same semantics: fingerprint check,
//! strictly increasing sequence, sticky quarantine, append-only event
//! journal enforced by a database trigger).
//!
//! The sync `postgres` client is used on purpose: there is no async
//! runtime in the workspace yet; ISS-030 will decide the final shape
//! (the SQL stays identical).

use postgres::error::SqlState;
use postgres::types::Json;
use postgres::{Client, NoTls, Transaction};
use vigile_pki::{QuarantineReason, RegistryError, SecurityEventKind};

/// Ordered migrations, applied inside one transaction each.
/// TODO(ISS-016 follow-up): store a checksum per applied migration to
/// detect local edits of already-applied files.
const MIGRATIONS: &[(&str, &str)] = &[("0001_init", include_str!("../migrations/0001_init.sql"))];

#[derive(Debug)]
pub enum StoreError {
    /// Registry semantics (same meanings as the in-memory registry).
    Registry(RegistryError),
    /// Infrastructure failure (connection, SQL, constraint unexpected).
    Pg(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Registry(e) => write!(f, "{e}"),
            StoreError::Pg(e) => write!(f, "postgres failure: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<RegistryError> for StoreError {
    fn from(e: RegistryError) -> Self {
        StoreError::Registry(e)
    }
}

/// Applies every pending migration (each in its own transaction).
pub fn apply_migrations(client: &mut Client) -> Result<(), StoreError> {
    for (name, sql) in MIGRATIONS {
        let mut tx = client.transaction().map_err(pg)?;
        // ALL schema DDL happens under an advisory lock so concurrent
        // migrators (parallel test processes, rolling deployments) are
        // fully serialized — including the bookkeeping table bootstrap,
        // otherwise CREATE TABLE IF NOT EXISTS races in pg_type.
        tx.execute("SELECT pg_advisory_xact_lock(1396912705)", &[])
            .map_err(pg)?;
        tx.batch_execute(
            "CREATE TABLE IF NOT EXISTS _vigile_migrations (
                 name TEXT PRIMARY KEY,
                 applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
             )",
        )
        .map_err(pg)?;
        let already = tx
            .query_opt(
                "SELECT name FROM _vigile_migrations WHERE name = $1",
                &[name],
            )
            .map_err(pg)?;
        if already.is_some() {
            tx.rollback().map_err(pg)?;
            continue;
        }
        tx.batch_execute(sql).map_err(pg)?;
        tx.execute("INSERT INTO _vigile_migrations (name) VALUES ($1)", &[name])
            .map_err(pg)?;
        tx.commit().map_err(pg)?;
    }
    Ok(())
}

fn pg(e: postgres::Error) -> StoreError {
    // postgres::Error's Display is terse ("db error"); surface the server
    // message, SQLSTATE and constraint for actionable failures.
    match e.as_db_error() {
        Some(db) => StoreError::Pg(format!(
            "{} (code {}, constraint {:?})",
            db.message(),
            db.code().code(),
            db.constraint()
        )),
        None => StoreError::Pg(e.to_string()),
    }
}

/// A stored security event (timestamps as unix seconds, mirroring the
/// in-memory registry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEvent {
    pub at_unix: i64,
    pub agent_id: String,
    pub kind: SecurityEventKind,
}

/// Persistent agent registry + machine inventory.
pub struct PgStore {
    client: Client,
}

impl PgStore {
    pub fn connect(config: &str) -> Result<Self, StoreError> {
        let mut client = Client::connect(config, NoTls).map_err(pg)?;
        apply_migrations(&mut client)?;
        Ok(Self { client })
    }

    /// Raw access for operator tooling and tests. The application must
    /// never bypass the semantics implemented above this accessor.
    pub fn client(&mut self) -> &mut Client {
        &mut self.client
    }

    /// Registers a fresh agent. Rejects a machine fingerprint already
    /// enrolled (globally — a fingerprint is a physical machine).
    pub fn register_agent(
        &mut self,
        agent_id: &str,
        tenant_id: &str,
        machine_fingerprint: &str,
        certificate_serial: &[u8],
    ) -> Result<(), StoreError> {
        let mut tx = self.client.transaction().map_err(pg)?;
        // SAVEPOINT: on a unique violation the transaction would be
        // aborted — rolling back to the savepoint keeps it usable for
        // the event insert below.
        let mut sp = tx.savepoint("try_insert").map_err(pg)?;
        let inserted = sp.execute(
            "INSERT INTO agents.agents (id, tenant_id, machine_fingerprint, certificate_serial)
             VALUES ($1, $2, $3, $4)",
            &[
                &agent_id,
                &tenant_id,
                &machine_fingerprint,
                &certificate_serial,
            ],
        );
        match inserted {
            Ok(_) => sp.commit().map_err(pg)?,
            Err(e) => {
                sp.rollback().map_err(pg)?;
                if is_unique_violation(&e, "machine_fingerprint") {
                    let held_by = held_by_fingerprint(&mut tx, machine_fingerprint)?;
                    insert_event(
                        &mut tx,
                        tenant_id,
                        agent_id,
                        &SecurityEventKind::FingerprintReuseRejected {
                            fingerprint: machine_fingerprint.to_string(),
                            new_agent_id: agent_id.to_string(),
                            held_by: held_by.clone(),
                        },
                    )?;
                    tx.commit().map_err(pg)?;
                    return Err(StoreError::Registry(RegistryError::FingerprintInUse {
                        fingerprint: machine_fingerprint.to_string(),
                        held_by,
                    }));
                }
                return Err(pg(e));
            }
        }
        insert_event(
            &mut tx,
            tenant_id,
            agent_id,
            &SecurityEventKind::Enrolled {
                agent_id: agent_id.to_string(),
                fingerprint: machine_fingerprint.to_string(),
            },
        )?;
        tx.commit().map_err(pg)?;
        Ok(())
    }

    /// Same semantics as `AgentRegistry::observe`: fingerprint check,
    /// then strictly increasing sequence; violations quarantine the
    /// agent and are recorded as events. Quarantine is sticky.
    pub fn observe(
        &mut self,
        tenant_id: &str,
        agent_id: &str,
        machine_fingerprint: &str,
        sequence: u64,
    ) -> Result<(), StoreError> {
        let mut tx = self.client.transaction().map_err(pg)?;
        let row = tx
            .query_opt(
                "SELECT machine_fingerprint, last_sequence, status, quarantine_reason
                 FROM agents.agents
                 WHERE id = $1 AND tenant_id = $2
                 FOR UPDATE",
                &[&agent_id, &tenant_id],
            )
            .map_err(pg)?
            .ok_or_else(|| {
                StoreError::Registry(RegistryError::UnknownAgent(agent_id.to_string()))
            })?;

        let enrolled: String = row.get("machine_fingerprint");
        let last_sequence: i64 = row.get("last_sequence");
        let status: String = row.get("status");
        let reason: Option<Json<serde_json::Value>> = row.get("quarantine_reason");

        if status == "quarantined" {
            let reason = reason
                .map(|j| serde_json::from_value(j.0).ok())
                .unwrap_or(None)
                .unwrap_or(QuarantineReason::Manual {
                    note: "unknown".into(),
                });
            return Err(StoreError::Registry(RegistryError::Quarantined {
                agent_id: agent_id.to_string(),
                reason,
            }));
        }

        if enrolled != machine_fingerprint {
            let reason = QuarantineReason::CloneSuspected {
                expected: enrolled.clone(),
                presented: machine_fingerprint.to_string(),
            };
            set_quarantined(&mut tx, tenant_id, agent_id, &reason)?;
            insert_event(
                &mut tx,
                tenant_id,
                agent_id,
                &SecurityEventKind::CloneRejected {
                    agent_id: agent_id.to_string(),
                    expected: enrolled,
                    presented: machine_fingerprint.to_string(),
                },
            )?;
            tx.commit().map_err(pg)?;
            return Err(StoreError::Registry(RegistryError::CloneSuspected {
                agent_id: agent_id.to_string(),
                expected: row.get("machine_fingerprint"),
                presented: machine_fingerprint.to_string(),
            }));
        }

        if sequence as i64 <= last_sequence {
            let reason = QuarantineReason::SequenceRegression {
                presented: sequence,
                last_seen: last_sequence as u64,
            };
            set_quarantined(&mut tx, tenant_id, agent_id, &reason)?;
            insert_event(
                &mut tx,
                tenant_id,
                agent_id,
                &SecurityEventKind::SequenceRegressionRejected {
                    agent_id: agent_id.to_string(),
                    presented: sequence,
                    last_seen: last_sequence as u64,
                },
            )?;
            tx.commit().map_err(pg)?;
            return Err(StoreError::Registry(RegistryError::SequenceRegression {
                agent_id: agent_id.to_string(),
                presented: sequence,
                last_seen: last_sequence as u64,
            }));
        }

        tx.execute(
            "UPDATE agents.agents SET last_sequence = $3 WHERE id = $1 AND tenant_id = $2",
            &[&agent_id, &tenant_id, &(sequence as i64)],
        )
        .map_err(pg)?;
        tx.commit().map_err(pg)?;
        Ok(())
    }

    /// Administrator quarantine, audited.
    pub fn quarantine(
        &mut self,
        tenant_id: &str,
        agent_id: &str,
        note: &str,
    ) -> Result<(), StoreError> {
        let mut tx = self.client.transaction().map_err(pg)?;
        set_quarantined(
            &mut tx,
            tenant_id,
            agent_id,
            &QuarantineReason::Manual {
                note: note.to_string(),
            },
        )?;
        tx.commit().map_err(pg)?;
        Ok(())
    }

    /// Administrator reinstatement after review; the sequence baseline
    /// is kept.
    pub fn reinstate(&mut self, tenant_id: &str, agent_id: &str) -> Result<(), StoreError> {
        let mut tx = self.client.transaction().map_err(pg)?;
        let updated = tx
            .execute(
                "UPDATE agents.agents SET status = 'active', quarantine_reason = NULL
                 WHERE id = $1 AND tenant_id = $2",
                &[&agent_id, &tenant_id],
            )
            .map_err(pg)?;
        if updated == 0 {
            return Err(StoreError::Registry(RegistryError::UnknownAgent(
                agent_id.to_string(),
            )));
        }
        insert_event(
            &mut tx,
            tenant_id,
            agent_id,
            &SecurityEventKind::Reinstated {
                agent_id: agent_id.to_string(),
            },
        )?;
        tx.commit().map_err(pg)?;
        Ok(())
    }

    /// Last events for an agent, oldest first (append-only journal).
    pub fn events(
        &mut self,
        tenant_id: &str,
        agent_id: &str,
        limit: i64,
    ) -> Result<Vec<StoredEvent>, StoreError> {
        let rows = self
            .client
            .query(
                "SELECT at, kind FROM agents.security_events
                 WHERE tenant_id = $1 AND agent_id = $2
                 ORDER BY id ASC LIMIT $3",
                &[&tenant_id, &agent_id, &limit],
            )
            .map_err(pg)?;
        let mut out = Vec::new();
        for row in rows {
            let at: std::time::SystemTime = row.get("at");
            let kind: String = row.get("kind");
            let kind = serde_json::from_str::<SecurityEventKind>(&kind)
                .map_err(|e| StoreError::Pg(format!("stored event kind unreadable: {e}")))?;
            out.push(StoredEvent {
                at_unix: at
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
                agent_id: agent_id.to_string(),
                kind,
            });
        }
        Ok(out)
    }

    /// Upserts the machine inventory row (first_seen kept, last_seen
    /// refreshed).
    pub fn upsert_machine(
        &mut self,
        tenant_id: &str,
        fingerprint: &str,
        agent_id: &str,
        hostname: &str,
        distro: &str,
        arch: &str,
    ) -> Result<(), StoreError> {
        self.client
            .execute(
                "INSERT INTO inventory.machines
                     (tenant_id, fingerprint, agent_id, hostname, distro, arch)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (tenant_id, fingerprint) DO UPDATE SET
                     agent_id = EXCLUDED.agent_id,
                     hostname = EXCLUDED.hostname,
                     distro = EXCLUDED.distro,
                     arch = EXCLUDED.arch,
                     last_seen = now()",
                &[
                    &tenant_id,
                    &fingerprint,
                    &agent_id,
                    &hostname,
                    &distro,
                    &arch,
                ],
            )
            .map_err(pg)?;
        Ok(())
    }
}

fn is_unique_violation(e: &postgres::Error, constraint_fragment: &str) -> bool {
    match e.as_db_error() {
        Some(db) => {
            db.code() == &SqlState::UNIQUE_VIOLATION && db.message().contains(constraint_fragment)
        }
        None => false,
    }
}

fn held_by_fingerprint(tx: &mut Transaction<'_>, fingerprint: &str) -> Result<String, StoreError> {
    let row = tx
        .query_opt(
            "SELECT id FROM agents.agents WHERE machine_fingerprint = $1",
            &[&fingerprint],
        )
        .map_err(pg)?;
    Ok(row
        .map(|r| r.get::<_, String>(0))
        .unwrap_or_else(|| "unknown".to_string()))
}

fn set_quarantined(
    tx: &mut Transaction<'_>,
    tenant_id: &str,
    agent_id: &str,
    reason: &QuarantineReason,
) -> Result<(), StoreError> {
    let reason_json =
        Json(serde_json::to_value(reason).map_err(|e| StoreError::Pg(e.to_string()))?);
    let updated = tx
        .execute(
            "UPDATE agents.agents SET status = 'quarantined', quarantine_reason = $3
             WHERE id = $1 AND tenant_id = $2",
            &[&agent_id, &tenant_id, &reason_json],
        )
        .map_err(pg)?;
    if updated == 0 {
        return Err(StoreError::Registry(RegistryError::UnknownAgent(
            agent_id.to_string(),
        )));
    }
    insert_event(
        tx,
        tenant_id,
        agent_id,
        &SecurityEventKind::Quarantined {
            agent_id: agent_id.to_string(),
            reason: reason.clone(),
        },
    )?;
    Ok(())
}

fn insert_event(
    tx: &mut Transaction<'_>,
    tenant_id: &str,
    agent_id: &str,
    kind: &SecurityEventKind,
) -> Result<(), StoreError> {
    let kind_json = serde_json::to_string(kind).map_err(|e| StoreError::Pg(e.to_string()))?;
    let details = Json(serde_json::to_value(kind).map_err(|e| StoreError::Pg(e.to_string()))?);
    tx.execute(
        "INSERT INTO agents.security_events (tenant_id, agent_id, kind, details)
         VALUES ($1, $2, $3, $4)",
        &[&tenant_id, &agent_id, &kind_json, &details],
    )
    .map_err(pg)?;
    Ok(())
}
