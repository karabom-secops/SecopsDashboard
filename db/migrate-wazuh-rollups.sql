-- Wazuh Rollups Migration
-- Run once: psql -d secops -f migrate-wazuh-rollups.sql
--
-- The Managed NDR and Managed Identity screens live-query the Wazuh Indexer
-- for short ranges. The indexer typically only keeps 30-90 days (ISM policy),
-- so a nightly job also snapshots daily rollups here for long-term trending and
-- for the client report deck.
--
-- Deliberately TWO GENERIC TABLES rather than a table per screen: the panels on
-- these screens will change often, and a wide per-screen table means a schema
-- migration every time one does.

CREATE TABLE IF NOT EXISTS wazuh_daily_metric (
  id             BIGSERIAL PRIMARY KEY,
  tenant_id      INTEGER       NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  integration_id INTEGER       NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
  day            DATE          NOT NULL,          -- tenant-local calendar day
  source         TEXT          NOT NULL,          -- 'fortigate' | 'office365' | 'ms-graph'
  metric         TEXT          NOT NULL,          -- 'traffic.decision' | 'ips.attack' | ...
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
  CONSTRAINT wazuh_daily_metric_uniq
    UNIQUE (integration_id, day, source, metric, dim1, dim2, dim3)
);

CREATE INDEX IF NOT EXISTS wazuh_daily_metric_trend_idx
  ON wazuh_daily_metric (tenant_id, source, metric, day DESC);

CREATE INDEX IF NOT EXISTS wazuh_daily_metric_day_idx
  ON wazuh_daily_metric (integration_id, day);

-- Job bookkeeping: which days are snapshotted, and did it work. Drives the
-- backfill pass that re-runs missing/failed days.
CREATE TABLE IF NOT EXISTS wazuh_rollup_run (
  id             BIGSERIAL   PRIMARY KEY,
  integration_id INTEGER     NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
  day            DATE        NOT NULL,
  source         TEXT        NOT NULL,
  status         TEXT        NOT NULL,            -- 'ok' | 'partial' | 'error' | 'no_data'
  message        TEXT,
  rows_written   INTEGER     NOT NULL DEFAULT 0,
  doc_count      BIGINT,                          -- total matching docs, for sanity checks
  duration_ms    INTEGER,
  ran_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT wazuh_rollup_run_uniq UNIQUE (integration_id, day, source)
);

CREATE INDEX IF NOT EXISTS wazuh_rollup_run_day_idx
  ON wazuh_rollup_run (integration_id, day DESC);
