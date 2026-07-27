-- Report deck metric overrides — schema migration
-- Run against an existing deployment.
-- Usage: PGPASSWORD='...' psql -h 127.0.0.1 -U secops_user -d secops_db -f db/migrate-report-metrics.sql

BEGIN;

-- ── Report Metrics ─────────────────────────────────────────────────────────
-- Backs the Overview tiles on the generated client deck.
--
-- Two kinds of row land here, distinguished by `source`:
--   'manual'      — typed by an operator in the Reports tab. Always wins.
--   'arctic_wolf' — warmed by the scheduled sync from the Arctic Wolf Reports
--                   API, for tiles the dashboard cannot derive itself
--                   (observations, cultureScore).
--
-- `value` is TEXT on purpose: tiles legitimately hold '223 M' as well as '95',
-- and a numeric column would either lose the unit or need a second column.

CREATE TABLE IF NOT EXISTS report_metrics (
  id         SERIAL      PRIMARY KEY,
  tenant_id  INT         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  period     CHAR(7)     NOT NULL,                    -- 'YYYY-MM'
  metric_id  TEXT        NOT NULL,                    -- 'observations', 'cultureScore', ...
  value      TEXT,
  source     TEXT        NOT NULL DEFAULT 'manual',   -- 'manual' | 'arctic_wolf'
  updated_by INT         REFERENCES users(id) ON DELETE SET NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, period, metric_id, source)
);

CREATE INDEX IF NOT EXISTS idx_report_metrics_lookup ON report_metrics (tenant_id, period);

COMMIT;
