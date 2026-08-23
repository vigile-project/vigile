// SPDX-License-Identifier: AGPL-3.0-or-later
//! PostgreSQL integration tests (ISS-016). Marked `#[ignore]`: they need
//! a live database — run them with `tests/run-pg-podman.sh` (rootless
//! podman) or set `VIGILE_PG_CONN` yourself.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)] // tests : échec rapide acceptable

use vigile_pki::{QuarantineReason, RegistryError, SecurityEventKind};
use vigile_store::{PgStore, StoreError};

fn store() -> PgStore {
    let cfg =
        std::env::var("VIGILE_PG_CONN").expect("set VIGILE_PG_CONN (see tests/run-pg-podman.sh)");
    PgStore::connect(&cfg).expect("connection + migrations")
}

/// Unique-per-run identifiers so tests are order-independent and
/// re-runnable against the same database.
fn ids(name: &str) -> (String, String) {
    let suffix = format!("{name}-{}", std::process::id());
    (format!("agent-{suffix}"), format!("machine-id:{suffix}"))
}

const TENANT: &str = "tenant-lab";

#[test]
#[ignore = "needs VIGILE_PG_CONN (tests/run-pg-podman.sh)"]
fn t01_register_observe_and_events() {
    let mut s = store();
    let (agent, fp) = ids("t01");
    s.register_agent(&agent, TENANT, &fp, &[1, 2, 3])
        .expect("register");
    s.observe(TENANT, &agent, &fp, 1).expect("observe 1");
    s.observe(TENANT, &agent, &fp, 42).expect("observe 42");

    let events = s.events(TENANT, &agent, 100).expect("events");
    assert!(events
        .iter()
        .any(|e| matches!(e.kind, SecurityEventKind::Enrolled { .. })));
    assert_eq!(events.len(), 1, "no spurious events: {events:?}");
}

#[test]
#[ignore = "needs VIGILE_PG_CONN (tests/run-pg-podman.sh)"]
fn t02_fingerprint_reuse_rejected() {
    let mut s = store();
    let (agent, fp) = ids("t02");
    s.register_agent(&agent, TENANT, &fp, &[])
        .expect("register");
    let err = s
        .register_agent("agent-other", TENANT, &fp, &[])
        .expect_err("fingerprint reuse");
    match err {
        StoreError::Registry(RegistryError::FingerprintInUse { held_by, .. }) => {
            assert_eq!(held_by, agent)
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
#[ignore = "needs VIGILE_PG_CONN (tests/run-pg-podman.sh)"]
fn t03_clone_fingerprint_quarantined_and_sticky() {
    let mut s = store();
    let (agent, fp) = ids("t03");
    s.register_agent(&agent, TENANT, &fp, &[])
        .expect("register");
    s.observe(TENANT, &agent, &fp, 5).expect("original");

    let err = s
        .observe(TENANT, &agent, "machine-id:clone", 6)
        .expect_err("clone detected");
    assert!(matches!(
        err,
        StoreError::Registry(RegistryError::CloneSuspected { .. })
    ));

    // Sticky: even the original is refused.
    let err = s
        .observe(TENANT, &agent, &fp, 7)
        .expect_err("quarantine is sticky");
    assert!(matches!(
        err,
        StoreError::Registry(RegistryError::Quarantined { .. })
    ));

    let events = s.events(TENANT, &agent, 100).unwrap();
    assert!(events.iter().any(|e| matches!(
        e.kind,
        SecurityEventKind::Quarantined {
            reason: QuarantineReason::CloneSuspected { .. },
            ..
        }
    )));
}

#[test]
#[ignore = "needs VIGILE_PG_CONN (tests/run-pg-podman.sh)"]
fn t04_sequence_regression_quarantined() {
    let mut s = store();
    let (agent, fp) = ids("t04");
    s.register_agent(&agent, TENANT, &fp, &[])
        .expect("register");
    s.observe(TENANT, &agent, &fp, 10).expect("progress");

    let err = s
        .observe(TENANT, &agent, &fp, 4)
        .expect_err("regression detected");
    assert!(matches!(
        err,
        StoreError::Registry(RegistryError::SequenceRegression {
            presented: 4,
            last_seen: 10,
            ..
        })
    ));

    let events = s.events(TENANT, &agent, 100).unwrap();
    assert!(events.iter().any(|e| matches!(
        e.kind,
        SecurityEventKind::SequenceRegressionRejected {
            presented: 4,
            last_seen: 10,
            ..
        }
    )));
}

#[test]
#[ignore = "needs VIGILE_PG_CONN (tests/run-pg-podman.sh)"]
fn t05_manual_quarantine_then_reinstate() {
    let mut s = store();
    let (agent, fp) = ids("t05");
    s.register_agent(&agent, TENANT, &fp, &[])
        .expect("register");
    s.observe(TENANT, &agent, &fp, 1).expect("observe");
    s.quarantine(TENANT, &agent, "INC-42").expect("quarantine");

    let err = s
        .observe(TENANT, &agent, &fp, 2)
        .expect_err("quarantined refused");
    assert!(matches!(
        err,
        StoreError::Registry(RegistryError::Quarantined { .. })
    ));

    s.reinstate(TENANT, &agent).expect("reinstate");
    s.observe(TENANT, &agent, &fp, 3).expect("active again");
    // Sequence baseline kept: 2 is refused after 3.
    let err = s
        .observe(TENANT, &agent, &fp, 2)
        .expect_err("baseline kept");
    assert!(matches!(
        err,
        StoreError::Registry(RegistryError::SequenceRegression { .. })
    ));
}

#[test]
#[ignore = "needs VIGILE_PG_CONN (tests/run-pg-podman.sh)"]
fn t06_events_append_only_enforced_by_trigger() {
    let mut s = store();
    let (agent, fp) = ids("t06");
    s.register_agent(&agent, TENANT, &fp, &[])
        .expect("register");

    let updated = s
        .client()
        .execute("UPDATE agents.security_events SET kind = 'x'", &[]);
    assert!(updated.is_err(), "UPDATE must be blocked by the trigger");

    let deleted = s
        .client()
        .execute("DELETE FROM agents.security_events", &[]);
    assert!(deleted.is_err(), "DELETE must be blocked by the trigger");
}

#[test]
#[ignore = "needs VIGILE_PG_CONN (tests/run-pg-podman.sh)"]
fn t07_machine_upsert_is_idempotent() {
    let mut s = store();
    let (agent, fp) = ids("t07");
    s.register_agent(&agent, TENANT, &fp, &[])
        .expect("register");
    s.upsert_machine(TENANT, &fp, &agent, "host-a", "fedora", "x86_64")
        .expect("first upsert");
    s.upsert_machine(TENANT, &fp, &agent, "host-a-renamed", "fedora", "x86_64")
        .expect("second upsert");

    let row = s
        .client()
        .query_one(
            "SELECT hostname, agent_id FROM inventory.machines
             WHERE tenant_id = $1 AND fingerprint = $2",
            &[&TENANT, &fp],
        )
        .expect("single row");
    let hostname: String = row.get(0);
    assert_eq!(hostname, "host-a-renamed");
    let count: i64 = s
        .client()
        .query_one("SELECT count(*) FROM inventory.machines", &[])
        .unwrap()
        .get(0);
    assert_eq!(count, 1, "no duplicate rows");
}

#[test]
#[ignore = "needs VIGILE_PG_CONN (tests/run-pg-podman.sh)"]
fn t08_tenant_isolation_and_unknown_agent() {
    let mut s = store();
    let (agent, fp) = ids("t08");
    s.register_agent(&agent, TENANT, &fp, &[])
        .expect("register");

    // Same agent id under another tenant: unknown there (tenant_id is
    // part of every lookup, never client-supplied trust).
    let err = s
        .observe("tenant-other", &agent, &fp, 1)
        .expect_err("tenant isolation");
    assert!(matches!(
        err,
        StoreError::Registry(RegistryError::UnknownAgent(_))
    ));
}
