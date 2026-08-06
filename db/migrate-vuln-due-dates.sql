-- Vulnerability remediation due dates — schema migration
-- Run against an existing deployment.
-- Usage: PGPASSWORD='...' psql -h 127.0.0.1 -U secops_user -d secops_db -f db/migrate-vuln-due-dates.sql

BEGIN;

-- ── Remediation SLA ────────────────────────────────────────────────────────
-- due_date = first_seen_at + the SLA window for the finding's severity:
--   Critical  1 week    (7 days)
--   High      2 weeks   (14 days)
--   Medium    1 month   (30 days)
--   Low       2 months  (60 days)
--
-- Computed at upload time in server.js so the stored value stays stable even if
-- the policy is retuned later; this migration backfills rows uploaded before the
-- policy existed. Findings with no first_seen_at get no due date.

ALTER TABLE vuln_findings ADD COLUMN IF NOT EXISTS due_date TIMESTAMPTZ;

UPDATE vuln_findings
   SET due_date = first_seen_at + (
         CASE lower(risk)
           WHEN 'critical' THEN INTERVAL '7 days'
           WHEN 'high'     THEN INTERVAL '14 days'
           WHEN 'medium'   THEN INTERVAL '30 days'
           WHEN 'low'      THEN INTERVAL '60 days'
           ELSE NULL
         END)
 WHERE due_date IS NULL
   AND first_seen_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_vuln_findings_due ON vuln_findings (due_date);

COMMIT;
