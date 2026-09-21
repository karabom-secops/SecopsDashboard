'use strict';

/**
 * lib/identity-metrics.js — Microsoft Graph and Office 365 audit into the
 * daily rollups, for the Managed Identity screen.
 *
 * Same model as lib/fortianalyzer-metrics.js: an hourly job collects each
 * client-local day into daily_metric, and the screen reads Postgres. Rows are
 * written through the shared flattenO365 with sources 'office365' and
 * 'ms-graph', so o365FromRollups rebuilds exactly the screen shape the tab
 * renders. They carry the ms_graph integration's id, and the screen reads by
 * that id.
 *
 *   today, yesterday   re-collected every run ('partial_day'): sign-ins arrive
 *                      within minutes, but Office 365 audit content can trail
 *                      by many hours
 *   older days         backfilled when missing or failed, up to BACKFILL_DAYS
 *
 * A day whose audit content is past Microsoft's seven-day retention is stored
 * as complete with those parts marked beyond_retention — re-trying it every
 * hour would never succeed.
 */

const wm  = require('./daily-metrics');
const idn = require('./integrations/ms-identity');

const SOURCES = ['office365', 'ms-graph'];
const BACKFILL_DAYS = 30;
const RECOLLECT_DAYS = 2;
const MAX_DAYS_PER_RUN = 3;

async function daysNeedingSnapshot(pool, integrationId, timeZone, now) {
  const today = wm.localDay(now || new Date(), timeZone);
  const res = await pool.query(
    `SELECT day::text AS day, source, status
       FROM rollup_run
      WHERE integration_id = $1 AND source = ANY($2::text[]) AND day >= $3::date`,
    [integrationId, SOURCES, wm.shiftDay(today, -BACKFILL_DAYS)]
  );

  const good = new Map();   // day → number of sources complete
  res.rows.forEach((r) => {
    if (r.status === 'ok' || r.status === 'no_data') good.set(r.day, (good.get(r.day) || 0) + 1);
  });

  const out = [];
  for (let i = 0; i <= BACKFILL_DAYS; i++) {
    const day = wm.shiftDay(today, -i);
    if (i < RECOLLECT_DAYS || (good.get(day) || 0) < SOURCES.length) out.push(day);
  }
  return out.slice(0, MAX_DAYS_PER_RUN);
}

/** A source's status for the day, from its envelope and what could not be read. */
function statusFor(env, rows, recent) {
  if (!env || !env.available) return 'error';
  const real = (env.data.unavailable || []).filter(u => u.reason !== 'beyond_retention');
  if (recent) return 'partial_day';
  if (real.length) return 'partial';
  return rows ? 'ok' : 'no_data';
}

function messageFor(env, errors) {
  if (!env) return null;
  if (!env.available) return `Unavailable: ${env.reason}`;
  const list = (env.data.unavailable || []).map(u => `${u.key} (${u.reason})`);
  return list.length ? `Not read: ${list.join(', ')}` : null;
}

/**
 * Collect one day and store both sources in one transaction.
 *
 * @param {object} integration { id, tenant_id, base_url, api_key, config }
 * @param {object} [opts]      { timeZone, now, http }
 */
async function snapshotDay(pool, integration, day, opts) {
  const o = opts || {};
  const started = Date.now();
  const tz = o.timeZone || (integration.config && integration.config.identity_time_zone) || 'UTC';
  const now = o.now || Date.now();
  const today = wm.localDay(new Date(now), tz);
  const recent = day >= wm.shiftDay(today, -(RECOLLECT_DAYS - 1));

  const cfg = Object.assign({}, integration.config || {}, {
    base_url: integration.base_url,
    api_key: integration.api_key,
  });

  let data;
  try {
    data = await idn.fetchIdentityDay(cfg, day, { timeZone: tz, now, isToday: day === today, http: o.http });
  } catch (err) {
    data = { _error: err.message };
  }

  let bags;
  if (data._error) {
    bags = SOURCES.map(s => ({ bag: wm.rowBag(s), status: 'error', message: data._error }));
  } else {
    const split = wm.flattenO365(data);
    bags = [
      { bag: split.office365, status: statusFor(data.o365, split.office365.rows.length, recent), message: messageFor(data.o365) },
      { bag: split.msgraph,   status: statusFor(data.graph, split.msgraph.rows.length, recent),  message: messageFor(data.graph) },
    ];
  }

  const client = await pool.connect();
  let rows = 0;
  try {
    await client.query('BEGIN');
    for (const b of bags) {
      rows += await wm.writeBag(client, {
        tenantId: integration.tenant_id,
        integrationId: integration.id,
        day,
        bag: b.bag,
        status: b.status,
        message: b.message,
        durationMs: Date.now() - started,
      });
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }

  const problems = data._error ? [data._error]
    : Object.keys(data.errors || {})
      .filter(k => data.errors[k].reason !== 'beyond_retention')
      .map(k => `${k} (${data.errors[k].reason})`);

  return { day, rows, statuses: bags.map(b => b.status), problems, error: data._error || null };
}

module.exports = {
  SOURCES,
  BACKFILL_DAYS,
  RECOLLECT_DAYS,
  MAX_DAYS_PER_RUN,
  daysNeedingSnapshot,
  snapshotDay,
};
