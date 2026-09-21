-- Remove Wazuh, and rename the rollup tables it gave its name to.
-- Run once: psql -d secops -f migrate-remove-wazuh.sql
--
-- WHY
--
-- The Managed NDR and Managed Identity screens were built on the Wazuh Indexer
-- and have since moved to the source systems directly — FortiAnalyzer for NDR,
-- Microsoft Graph and the Office 365 Management API for Identity. DNSFilter's
-- AI Visibility arrived on the same rollup plumbing and never touched Wazuh at
-- all. Nothing reads the indexer any more, so the integration goes.
--
-- The two tables, however, are NOT going anywhere: they are the generic daily
-- rollup store every direct integration writes to. Only the name was ever about
-- Wazuh, and a table called wazuh_daily_metric holding DNSFilter AI usage is a
-- trap for whoever reads this schema next.
--
-- ══ THIS DESTROYS DATA ══
--
-- The rollup rows and run records belonging to a wazuh integration are deleted:
-- the pre-FortiAnalyzer NDR history and the pre-Graph Identity history. That is
-- deliberate and was asked for. Dump both tables first if that history is worth
-- anything to you; there is no way back from here.
--
-- SAFE TO RUN ON A FRESH DATABASE. db/migrate-daily-rollups.sql creates the
-- tables under their new names, so on a new install every step below finds
-- nothing to do and says so, rather than failing half-way and leaving the
-- schema in a state no version of the code can read.

BEGIN;

-- ── 1. The integration, and everything downstream of it ────────────────────
--
-- Both tables cascade from integrations(id), so deleting the integration row
-- would take the rest with it. The deletes are spelled out anyway: a reader has
-- to be able to see what removing four rows actually removes.

DO $$
DECLARE
  n_int INTEGER := 0;
  n_met BIGINT  := 0;
  n_run BIGINT  := 0;
BEGIN
  IF to_regclass('public.integrations') IS NULL THEN
    RAISE NOTICE 'No integrations table — nothing to remove.';
    RETURN;
  END IF;

  SELECT count(*) INTO n_int FROM integrations WHERE provider = 'wazuh';

  IF to_regclass('public.wazuh_daily_metric') IS NOT NULL THEN
    SELECT count(*) INTO n_met FROM wazuh_daily_metric
      WHERE integration_id IN (SELECT id FROM integrations WHERE provider = 'wazuh');
    DELETE FROM wazuh_daily_metric
      WHERE integration_id IN (SELECT id FROM integrations WHERE provider = 'wazuh');
  END IF;

  IF to_regclass('public.wazuh_rollup_run') IS NOT NULL THEN
    SELECT count(*) INTO n_run FROM wazuh_rollup_run
      WHERE integration_id IN (SELECT id FROM integrations WHERE provider = 'wazuh');
    DELETE FROM wazuh_rollup_run
      WHERE integration_id IN (SELECT id FROM integrations WHERE provider = 'wazuh');
  END IF;

  DELETE FROM integrations WHERE provider = 'wazuh';

  RAISE NOTICE 'Removed % wazuh integration(s): % metric row(s), % run record(s).',
    n_int, n_met, n_run;
END $$;

-- ── 2. The rename ──────────────────────────────────────────────────────────
--
-- Tables, then the constraints, indexes and sequences that carry the old name
-- in their own. Postgres renames none of those with the table, and an index
-- called wazuh_daily_metric_trend_idx sitting on daily_metric is the same trap
-- one level down.

DO $$
BEGIN
  IF to_regclass('public.wazuh_daily_metric') IS NULL THEN
    RAISE NOTICE 'wazuh_daily_metric is absent — already renamed, or a fresh database.';
  ELSE
    ALTER TABLE wazuh_daily_metric RENAME TO daily_metric;
    ALTER TABLE daily_metric RENAME CONSTRAINT wazuh_daily_metric_uniq TO daily_metric_uniq;
    ALTER INDEX wazuh_daily_metric_pkey      RENAME TO daily_metric_pkey;
    ALTER INDEX wazuh_daily_metric_trend_idx RENAME TO daily_metric_trend_idx;
    ALTER INDEX wazuh_daily_metric_day_idx   RENAME TO daily_metric_day_idx;
    ALTER SEQUENCE wazuh_daily_metric_id_seq RENAME TO daily_metric_id_seq;
    RAISE NOTICE 'wazuh_daily_metric -> daily_metric';
  END IF;

  IF to_regclass('public.wazuh_rollup_run') IS NULL THEN
    RAISE NOTICE 'wazuh_rollup_run is absent — already renamed, or a fresh database.';
  ELSE
    ALTER TABLE wazuh_rollup_run RENAME TO rollup_run;
    ALTER TABLE rollup_run RENAME CONSTRAINT wazuh_rollup_run_uniq TO rollup_run_uniq;
    ALTER INDEX wazuh_rollup_run_pkey      RENAME TO rollup_run_pkey;
    ALTER INDEX wazuh_rollup_run_day_idx   RENAME TO rollup_run_day_idx;
    ALTER SEQUENCE wazuh_rollup_run_id_seq RENAME TO rollup_run_id_seq;
    RAISE NOTICE 'wazuh_rollup_run -> rollup_run';
  END IF;
END $$;

DO $$
BEGIN
  IF to_regclass('public.daily_metric') IS NOT NULL THEN
    COMMENT ON TABLE daily_metric IS
      'Generic daily rollup store: one row per (integration, day, source, metric, dims). '
      'Written by the FortiAnalyzer, Microsoft Identity and DNSFilter collectors.';
  END IF;
  IF to_regclass('public.rollup_run') IS NOT NULL THEN
    COMMENT ON TABLE rollup_run IS
      'Per-(integration, day, source) collection bookkeeping: drives the backfill pass.';
  END IF;
END $$;

COMMIT;
