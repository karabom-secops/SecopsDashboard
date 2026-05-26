-- Arctic Wolf MDR Ticket Tracking — schema migration
-- Run against an existing deployment.
-- Usage: PGPASSWORD='...' psql -h 127.0.0.1 -U secops_user -d secops_db -f db/migrate-mdr-tickets.sql

BEGIN;

-- ── MDR Upload Metadata ────────────────────────────────────────────────────
-- Tracks each CSV upload per tenant (latest-only pattern)

CREATE TABLE IF NOT EXISTS mdr_uploads (
  id               SERIAL PRIMARY KEY,
  tenant_id        INT         REFERENCES tenants(id) ON DELETE CASCADE,
  uploaded_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  uploaded_by      INT         REFERENCES users(id) ON DELETE SET NULL,
  total_tickets    INT         NOT NULL DEFAULT 0,
  resolved_count   INT         NOT NULL DEFAULT 0,
  pending_count    INT         NOT NULL DEFAULT 0,
  avg_resolution_hours NUMERIC(10, 2)
);

CREATE INDEX IF NOT EXISTS idx_mdr_uploads_tenant ON mdr_uploads (tenant_id);

-- If this migration is applied to an existing deployment, allow system-wide uploads by
-- making tenant_id nullable and removing any tenant-level uniqueness constraint.
ALTER TABLE mdr_uploads ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE mdr_uploads DROP CONSTRAINT IF EXISTS mdr_uploads_tenant_id_key;
ALTER TABLE mdr_uploads DROP INDEX IF EXISTS idx_mdr_uploads_tenant;
CREATE INDEX IF NOT EXISTS idx_mdr_uploads_tenant ON mdr_uploads (tenant_id);

-- ── MDR Tickets ────────────────────────────────────────────────────────────
-- Individual ticket records

CREATE TABLE IF NOT EXISTS mdr_tickets (
  id                SERIAL PRIMARY KEY,
  upload_id         INT         NOT NULL REFERENCES mdr_uploads(id) ON DELETE CASCADE,
  ticket_number     TEXT        NOT NULL,
  subject           TEXT        NOT NULL,
  status            TEXT        NOT NULL,  -- solved, closed, pending, etc.
  ticket_type       TEXT,                  -- incident, info, support, etc.
  severity          TEXT,                  -- HIGH, MEDIUM, LOW
  created_at        TIMESTAMPTZ,
  resolved_at       TIMESTAMPTZ,
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  assigned_to       TEXT,
  notes             TEXT
);

CREATE INDEX IF NOT EXISTS idx_mdr_tickets_upload  ON mdr_tickets (upload_id);
CREATE INDEX IF NOT EXISTS idx_mdr_tickets_status  ON mdr_tickets (status);
CREATE INDEX IF NOT EXISTS idx_mdr_tickets_type    ON mdr_tickets (ticket_type);
CREATE INDEX IF NOT EXISTS idx_mdr_tickets_severity ON mdr_tickets (severity);

COMMIT;
