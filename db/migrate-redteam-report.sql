-- Red Team penetration test report generator.
-- Adds the report-grade fields to pentest_findings, evidence image storage, and
-- the per-engagement narrative sections that make up the Word deliverable.
-- Run once: psql -d secops -f db/migrate-redteam-report.sql

-- ── Report-grade fields on findings ───────────────────────────────────────────
ALTER TABLE pentest_findings ADD COLUMN IF NOT EXISTS cvss_vector        VARCHAR(160) NOT NULL DEFAULT '';
ALTER TABLE pentest_findings ADD COLUMN IF NOT EXISTS cvss_score         NUMERIC(3,1);
ALTER TABLE pentest_findings ADD COLUMN IF NOT EXISTS classification     VARCHAR(200) NOT NULL DEFAULT '';
ALTER TABLE pentest_findings ADD COLUMN IF NOT EXISTS affected_endpoints TEXT NOT NULL DEFAULT '';
ALTER TABLE pentest_findings ADD COLUMN IF NOT EXISTS business_impact    TEXT NOT NULL DEFAULT '';
ALTER TABLE pentest_findings ADD COLUMN IF NOT EXISTS sort_order         INT NOT NULL DEFAULT 0;

-- ── Evidence screenshots (stored inline so tenant/finding deletes cascade) ────
CREATE TABLE IF NOT EXISTS pentest_finding_evidence (
  id          SERIAL PRIMARY KEY,
  finding_id  INT NOT NULL REFERENCES pentest_findings(id) ON DELETE CASCADE,
  mime        VARCHAR(60)  NOT NULL,
  filename    VARCHAR(255) NOT NULL DEFAULT '',
  caption     VARCHAR(300) NOT NULL DEFAULT '',
  sort_order  INT NOT NULL DEFAULT 0,
  width_px    INT,
  height_px   INT,
  data        BYTEA NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_pentest_evidence_finding
  ON pentest_finding_evidence(finding_id, sort_order);

-- ── Narrative sections, one row per engagement ────────────────────────────────
CREATE TABLE IF NOT EXISTS redteam_report_meta (
  project_id            INT PRIMARY KEY REFERENCES redteam_projects(id) ON DELETE CASCADE,
  tenant_id             INT REFERENCES tenants(id) ON DELETE CASCADE,
  report_title          TEXT NOT NULL DEFAULT '',
  report_subtitle       TEXT NOT NULL DEFAULT 'Web Application Penetration Test Report',
  report_version        TEXT NOT NULL DEFAULT 'v1.0',
  report_date           DATE,
  exec_summary          TEXT NOT NULL DEFAULT '',
  key_risk_themes       TEXT NOT NULL DEFAULT '',
  approach              TEXT NOT NULL DEFAULT '',
  scope_objectives      TEXT NOT NULL DEFAULT '',
  findings_summary      TEXT NOT NULL DEFAULT '',
  mitigating_factors    TEXT NOT NULL DEFAULT '',
  attack_paths_intro    TEXT NOT NULL DEFAULT '',
  attack_paths_narrative TEXT NOT NULL DEFAULT '',
  next_steps            TEXT NOT NULL DEFAULT '',
  scope_endpoints       TEXT NOT NULL DEFAULT '',
  methodology           TEXT NOT NULL DEFAULT '',
  timeline_note         TEXT NOT NULL DEFAULT '',
  delivery_team         JSONB NOT NULL DEFAULT '[]'::jsonb,
  owasp_results         JSONB NOT NULL DEFAULT '[]'::jsonb,
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by            INT REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_redteam_report_meta_tenant ON redteam_report_meta(tenant_id);
