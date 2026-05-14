-- SecOps Dashboard — PostgreSQL Schema
-- Run this once on a fresh database.
-- Usage: psql -U secops_user -d secops_db -f db/schema.sql
--
-- For an EXISTING deployment that already has the old schema (no tenants),
-- run db/migrate-tenants.sql instead.

-- ── Sessions (managed by connect-pg-simple) ───────────────────────────────

CREATE TABLE IF NOT EXISTS "sessions" (
  "sid"    varchar       NOT NULL COLLATE "default",
  "sess"   json          NOT NULL,
  "expire" timestamp(6)  NOT NULL,
  CONSTRAINT "sessions_pkey" PRIMARY KEY ("sid")
);
CREATE INDEX IF NOT EXISTS "IDX_sessions_expire" ON "sessions" ("expire");

-- ── Tenants ───────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tenants (
  id         SERIAL PRIMARY KEY,
  name       VARCHAR(100) UNIQUE NOT NULL,
  slug       VARCHAR(30)  UNIQUE NOT NULL,
  created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ── Users ─────────────────────────────────────────────────────────────────
-- superadmin: tenant_id IS NULL — sees all tenants
-- admin/readonly: tenant_id NOT NULL — scoped to their org

CREATE TABLE IF NOT EXISTS users (
  id               SERIAL PRIMARY KEY,
  username         VARCHAR(30) UNIQUE NOT NULL,
  password_hash    TEXT        NOT NULL,
  role             VARCHAR(15) NOT NULL DEFAULT 'readonly'
                     CONSTRAINT users_role_chk CHECK (role IN ('superadmin', 'admin', 'readonly')),
  tenant_id        INT         REFERENCES tenants(id) ON DELETE SET NULL,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login       TIMESTAMPTZ,
  totp_secret      TEXT,
  totp_enabled     BOOLEAN     NOT NULL DEFAULT FALSE,
  totp_required    BOOLEAN     NOT NULL DEFAULT FALSE
);

-- ── Vulnerability Scans ───────────────────────────────────────────────────
-- month_key is unique per tenant, not globally unique.

CREATE TABLE IF NOT EXISTS vuln_scans (
  id           SERIAL PRIMARY KEY,
  tenant_id    INT         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  month_key    CHAR(7)     NOT NULL,   -- 'YYYY-MM'
  summary      JSONB       NOT NULL DEFAULT '{}',
  uploaded_by  INT         REFERENCES users(id) ON DELETE SET NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, month_key)
);

-- ── Vulnerability Findings ────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS vuln_findings (
  id                SERIAL PRIMARY KEY,
  scan_id           INT         NOT NULL REFERENCES vuln_scans(id) ON DELETE CASCADE,
  finding_index     INT         NOT NULL,    -- 0-based order; used by PATCH endpoint
  plugin_id         TEXT,
  name              TEXT,
  risk              TEXT,
  host              TEXT,
  port              TEXT,
  protocol          TEXT,
  cve               TEXT,
  cvss_v2           TEXT,
  cvss_v3           TEXT,
  synopsis          TEXT,
  solution          TEXT,
  status            VARCHAR(20) NOT NULL DEFAULT 'open'
                      CONSTRAINT vuln_findings_status_chk
                        CHECK (status IN ('open', 'in-progress', 'fixed', 'accepted')),
  notes             TEXT        NOT NULL DEFAULT '',
  status_updated_at TIMESTAMPTZ,
  first_seen_at     TIMESTAMPTZ,
  UNIQUE (scan_id, finding_index)
);

CREATE INDEX IF NOT EXISTS idx_vuln_findings_scan ON vuln_findings (scan_id);

-- ── Security Awareness Uploads ────────────────────────────────────────────
-- One row per tenant (latest-only). Delete + re-insert on each upload.

CREATE TABLE IF NOT EXISTS awareness_uploads (
  id               SERIAL PRIMARY KEY,
  tenant_id        INT         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  uploaded_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  uploaded_by      INT         REFERENCES users(id) ON DELETE SET NULL,
  total_users      INT         NOT NULL DEFAULT 0,
  total_incomplete INT         NOT NULL DEFAULT 0,
  UNIQUE (tenant_id)
);

-- ── Security Awareness Users ──────────────────────────────────────────────

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
