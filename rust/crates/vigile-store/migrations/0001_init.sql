-- ISS-016 — initial schema, per ADR-0007 (logical separation by domain).
--
-- tenants: every row carries tenant_id, always resolved server-side
-- (never trusted from the client).

CREATE SCHEMA IF NOT EXISTS agents;
CREATE SCHEMA IF NOT EXISTS inventory;

-- ---------------------------------------------------------------------------
-- agents: identity registry (persistent twin of vigile_pki::AgentRegistry)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS agents.agents (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    machine_fingerprint TEXT NOT NULL,
    certificate_serial  BYTEA NOT NULL,
    last_sequence       BIGINT NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    status              TEXT NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'quarantined')),
    quarantine_reason   JSONB,
    enrolled_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- A machine fingerprint is a physical machine identity: globally
    -- unique, across tenants (cross-tenant reuse = cloned image).
    UNIQUE (machine_fingerprint)
);

CREATE TABLE IF NOT EXISTS agents.security_events (
    id        BIGSERIAL PRIMARY KEY,
    at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    tenant_id TEXT NOT NULL,
    agent_id  TEXT NOT NULL,
    kind      TEXT NOT NULL,
    details   JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS security_events_agent_idx
    ON agents.security_events (tenant_id, agent_id, id);

-- Append-only from the application's point of view (ADR-0007, SEC-305):
-- UPDATE and DELETE raise regardless of the application role. Operations
-- that must purge for legal reasons go through a dedicated, audited
-- operator procedure (documented in the operator guide) — never the app.
CREATE OR REPLACE FUNCTION agents.security_events_append_only()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'agents.security_events is append-only';
END;
$$;

DROP TRIGGER IF EXISTS security_events_append_only ON agents.security_events;
CREATE TRIGGER security_events_append_only
    BEFORE UPDATE OR DELETE ON agents.security_events
    FOR EACH ROW EXECUTE FUNCTION agents.security_events_append_only();

-- ---------------------------------------------------------------------------
-- inventory: machines (minimal ISS-016 scope — application inventory
-- grows with ISS-017..022)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS inventory.machines (
    tenant_id   TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    hostname    TEXT NOT NULL DEFAULT '',
    distro      TEXT NOT NULL DEFAULT '',
    arch        TEXT NOT NULL DEFAULT '',
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, fingerprint)
);
