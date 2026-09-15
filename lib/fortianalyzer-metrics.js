'use strict';

/**
 * lib/fortianalyzer-metrics.js — FortiAnalyzer into the daily rollups.
 *
 * ══ WHY THE NDR SCREEN READS ROLLUPS, NOT FORTIANALYZER LIVE ══
 *
 * Wazuh was queried live for short ranges. FortiAnalyzer is not, deliberately:
 * one on-prem appliance serves every client, log searches run as tasks that
 * take seconds each, and a thirty-day screen would fan out into hundreds of
 * them on every tab switch. So an hourly job collects each day once into the
 * same wazuh_daily_metric tables, and the screen reads Postgres.
 *
 *   today        re-collected every run, stored as 'partial_day'
 *   yesterday    collected again once after midnight (still 'partial_day'
 *                from the last run of the day), which also catches late logs
 *   older days   backfilled when missing or failed, up to BACKFILL_DAYS back
 *
 * MAX_DAYS_PER_RUN caps each run, so a new client's thirty-day backfill is
 * spread over several hours instead of landing on the appliance at once.
 *
 * Rows are written with source 'fortigate' and the SAME metric names as the
 * Wazuh path (flattenNdr), so ndrFromRollups rebuilds the screen unchanged.
 */

const wm  = require('./wazuh-metrics');
const faz = require('./integrations/fortianalyzer');

const SOURCE = 'fortigate';
const BACKFILL_DAYS = 30;
const MAX_DAYS_PER_RUN = 4;

/**
 * Which days to collect this run, most recent first.
 */
async function daysNeedingSnapshot(pool, integrationId, timeZone, now) {
  const today = wm.localDay(now || new Date(), timeZone);
  const res = await pool.query(
    `SELECT day::text AS day, status
       FROM wazuh_rollup_run
      WHERE integration_id = $1 AND source = $2 AND day >= $3::date`,
    [integrationId, SOURCE, wm.shiftDay(today, -BACKFILL_DAYS)]
  );
  const complete = new Set(res.rows
    .filter(r => r.status === 'ok' || r.status === 'no_data')
    .map(r => r.day));

  const out = [today];
  for (let i = 1; i <= BACKFILL_DAYS; i++) {
    const day = wm.shiftDay(today, -i);
    if (!complete.has(day)) out.push(day);
  }
  return out.slice(0, MAX_DAYS_PER_RUN);
}

/**
 * Collect one day and store it.
 *
 * A panel that fails is simply absent from the bag, and writeBag only
 * replaces the metrics a run actually produced — so a failed IPS search never
 * wipes the IPS figures an earlier run stored for that day.
 *
 * @param {object} integration { id, tenant_id, base_url, api_key, config }
 * @param {string} day         'YYYY-MM-DD', appliance-local
 * @param {object} [opts]      { isToday, cfg } — cfg merges over the stored
 *                             config (test seams only)
 */
async function snapshotDay(pool, integration, day, opts) {
  const o = opts || {};
  const started = Date.now();
  const cfg = Object.assign({}, faz.sanitiseStoredConfig(integration.config), {
    base_url: integration.base_url,
    api_key: integration.api_key,
  }, o.cfg || {});

  let ndr;
  try {
    ndr = await faz.fetchNdrDay(cfg, day);
  } catch (err) {
    ndr = { _error: err.message };
  }

  let bag, status, message;
  const partialPanels = ndr._partial || [];
  if (ndr._error) {
    bag = wm.rowBag(SOURCE);
    status = 'error';
    message = ndr._error;
  } else {
    bag = wm.flattenNdr(ndr);
    status = partialPanels.length ? 'partial' : (bag.rows.length ? 'ok' : 'no_data');
    message = partialPanels.length ? `Panels unavailable: ${partialPanels.join(', ')}` : null;
    // A day still in progress is never "complete", so it is collected again.
    if (o.isToday) {
      status = 'partial_day';
      message = message || 'Day in progress — re-collected hourly.';
    }
  }

  const client = await pool.connect();
  let rows = 0;
  try {
    await client.query('BEGIN');
    rows = await wm.writeBag(client, {
      tenantId: integration.tenant_id,
      integrationId: integration.id,
      day,
      bag,
      status,
      message,
      durationMs: Date.now() - started,
    });
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }

  return { day, rows, status, message, partialPanels, error: ndr._error || null };
}

module.exports = {
  SOURCE,
  BACKFILL_DAYS,
  MAX_DAYS_PER_RUN,
  daysNeedingSnapshot,
  snapshotDay,
};
