-- Daily Rollups Migration
-- Run once: psql -d secops -f migrate-daily-rollups.sql
--
-- The generic daily metric store. Every integration that trends over time
-- writes here: FortiAnalyzer (Managed NDR), Microsoft Graph and the Office 365
-- Management API (Managed Identity), and DNSFilter (AI Visibility). The source
-- systems keep 7-90 days depending on the product and the licence, so a daily
-- job snapshots each client-local day here for long-term trending and for the
-- client report deck.
--
-- Deliberately TWO GENERIC TABLES rather than a table per screen: the panels on
-- these screens change often, and a wide per-screen table means a schema
-- migration every time one does.
--
-- These tables were called wazuh_daily_metric and wazuh_rollup_run until the
-- Wazuh Indexer was removed; db/migrate-remove-wazuh.sql renames them on an
-- existing database. This file creates them under the new names for a fresh
-- one. Run whichever applies — both are safe to run twice.

CREATE TABLE IF NOT EXISTS daily_metric (
  id             BIGSERIAL PRIMARY KEY,
  tenant_id      INTEGER       NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  integration_id INTEGER       NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
  day            DATE          NOT NULL,          -- tenant-local calendar day
  source         TEXT          NOT NULL,          -- 'fortigate' | 'office365' | 'ms-graph' | 'dnsfilter'
  metric         TEXT          NOT NULL,          -- 'traffic.decision' | 'ips.attack' | 'ai.requests' | ...
  -- Three fixed keyword dimensions cover every panel and index cleanly.
  -- NOT NULL DEFAULT '' is deliberate: Postgres unique constraints treat NULL
  -- as distinct, so nullable dims would silently break re-snapshot idempotency.
  dim1           TEXT          NOT NULL DEFAULT '',
  dim2           TEXT          NOT NULL DEFAULT '',
  dim3           TEXT          NOT NULL DEFAULT '',
  value          NUMERIC(20,2) NOT NULL DEFAULT 0,
  value2         NUMERIC(20,2),                   -- optional secondary, e.g. distinct users
  meta           JSONB,                           -- display-only extras; never filtered on
  created_at     TIMESTAMPTZ   NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ   NOT NULL DEFAULT now(),
  CONSTRAINT daily_metric_uniq
    UNIQUE (integration_id, day, source, metric, dim1, dim2, dim3)
);

CREATE INDEX IF NOT EXISTS daily_metric_trend_idx
  ON daily_metric (tenant_id, source, metric, day DESC);

CREATE INDEX IF NOT EXISTS daily_metric_day_idx
  ON daily_metric (integration_id, day);

-- Job bookkeeping: which days are snapshotted, and did it work. Drives the
-- backfill pass that re-runs missing/failed days.
CREATE TABLE IF NOT EXISTS rollup_run (
  id             BIGSERIAL   PRIMARY KEY,
  integration_id INTEGER     NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
  day            DATE        NOT NULL,
  source         TEXT        NOT NULL,
  status         TEXT        NOT NULL,            -- 'ok' | 'partial' | 'error' | 'no_data' | 'partial_day'
  message        TEXT,
  rows_written   INTEGER     NOT NULL DEFAULT 0,
  doc_count      BIGINT,                          -- total matching docs, for sanity checks
  duration_ms    INTEGER,
  ran_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT rollup_run_uniq UNIQUE (integration_id, day, source)
);

CREATE INDEX IF NOT EXISTS rollup_run_day_idx
  ON rollup_run (integration_id, day DESC);
