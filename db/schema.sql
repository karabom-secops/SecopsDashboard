-- SecOps Dashboard — PostgreSQL Schema
-- Run this once to set up all tables.
-- Usage: psql -U secops_user -d secops_db -f db/schema.sql

-- ── Sessions (managed by connect-pg-simple) ───────────────────────────────

CREATE TABLE IF NOT EXISTS "sessions" (
  "sid"    varchar       NOT NULL COLLATE "default",
  "sess"   json          NOT NULL,
  "expire" timestamp(6)  NOT NULL,
  CONSTRAINT "sessions_pkey" PRIMARY KEY ("sid")
);
CREATE INDEX IF NOT EXISTS "IDX_sessions_expire" ON "sessions" ("expire");

-- ── Users ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS users (
  id               SERIAL PRIMARY KEY,
  username         VARCHAR(30) UNIQUE NOT NULL,
  password_hash    TEXT        NOT NULL,
  role             VARCHAR(10) NOT NULL DEFAULT 'readonly'
                     CONSTRAINT users_role_chk CHECK (role IN ('admin', 'readonly')),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login       TIMESTAMPTZ
);

-- ── Vulnerability Scans ───────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS vuln_scans (
  id           SERIAL PRIMARY KEY,
  month_key    CHAR(7)     UNIQUE NOT NULL,   -- 'YYYY-MM'
  summary      JSONB       NOT NULL DEFAULT '{}',
  uploaded_by  INT         REFERENCES users(id) ON DELETE SET NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
  UNIQUE (scan_id, finding_index)
);

CREATE INDEX IF NOT EXISTS idx_vuln_findings_scan ON vuln_findings (scan_id);
