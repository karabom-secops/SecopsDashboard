-- Security Awareness Training — schema migration
-- Run against an existing deployment.
-- Usage: PGPASSWORD='...' psql -h 127.0.0.1 -U secops_user -d secops_db -f db/migrate-awareness.sql

BEGIN;

CREATE TABLE IF NOT EXISTS awareness_uploads (
  id               SERIAL PRIMARY KEY,
  tenant_id        INT         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  uploaded_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  uploaded_by      INT         REFERENCES users(id) ON DELETE SET NULL,
  total_users      INT         NOT NULL DEFAULT 0,
  total_incomplete INT         NOT NULL DEFAULT 0,
  UNIQUE (tenant_id)   -- latest-only: one row per tenant
);

CREATE TABLE IF NOT EXISTS awareness_users (
  id                  SERIAL PRIMARY KEY,
  upload_id           INT  NOT NULL REFERENCES awareness_uploads(id) ON DELETE CASCADE,
  manager_first_name  TEXT,
  manager_last_name   TEXT,
  manager_email       TEXT,
  user_first_name     TEXT NOT NULL,
  user_last_name      TEXT NOT NULL,
  user_email          TEXT NOT NULL,
  incomplete_sessions INT  NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_awareness_users_upload  ON awareness_users (upload_id);
CREATE INDEX IF NOT EXISTS idx_awareness_users_manager ON awareness_users (manager_email);

COMMIT;
