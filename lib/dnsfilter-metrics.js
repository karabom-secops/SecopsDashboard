'use strict';

/**
 * lib/dnsfilter-metrics.js — DNSFilter into the daily rollups, for AI Visibility.
 *
 * Same model as lib/fortianalyzer-metrics.js: an hourly job collects each
 * client-local day into wazuh_daily_metric, and the tab reads Postgres. The
 * DNSFilter API is shared by every client on one MSP key, and a thirty-day
 * screen read live would fan out into over a hundred report calls per view.
 *
 *   today, yesterday   re-collected every run ('partial_day'): DNSFilter's
 *                      reports settle over the hours after a lookup
 *   older days         backfilled when missing or failed, up to BACKFILL_DAYS
 *
 * Rows are source 'dnsfilter':
 *
 *   ai.requests        dim1 allowed|blocked                  lookups
 *   ai.total_requests  dim1 total                            every lookup (denominator)
 *   ai.app_allowed     dim1 app key, dim2 name, meta.mapped  lookups
 *   ai.app_blocked     dim1 app key, dim2 name, meta.mapped  lookups
 *   ai.user            dim1 user, dim2 app key               lookups   (staff-only)
 *   ai.policy          dim1 name, dim2 blocked|allowed|unknown, dim3 allow_list_only
 *   ai.unavailable     dim1 part, dim2 reason
 *   ai.sampled         dim1 part
 */

const wm  = require('./wazuh-metrics');
const dns = require('./integrations/dnsfilter');

const SOURCE = 'dnsfilter';
const BACKFILL_DAYS = 30;
const RECOLLECT_DAYS = 2;
const MAX_DAYS_PER_RUN = 4;

const PART_METRICS = {
  usage:  ['ai.requests', 'ai.total_requests'],
  apps:   ['ai.app_allowed', 'ai.app_blocked'],
  users:  ['ai.user'],
  policy: ['ai.policy'],
};

const ready = e => !!(e && e.available && e.data);

/**
 * Adapter output for one day → one bag.
 *
 * A panel that was READ declares its metrics even when it produced no rows, so
 * writeBag clears what an earlier run stored for that day — a re-collected
 * today that went from three AI apps to none must show none, not the stale
 * three. A panel that FAILED declares nothing, so a failed read never wipes
 * figures an earlier run stored successfully; it records why instead.
 */
function flattenAi(data) {
  const bag = wm.rowBag(SOURCE);
  const declare = part => PART_METRICS[part].forEach(m => bag.metrics.add(m));
  const unavailable = (part, reason) => bag.add('ai.unavailable', part, reason || 'query_error', '', 1);
  // Bookkeeping is always rewritten: a part that is readable again must stop
  // being reported unavailable.
  bag.metrics.add('ai.unavailable');
  bag.metrics.add('ai.sampled');

  const u = data.usage;
  if (ready(u)) {
    declare('usage');
    bag.add('ai.requests', 'allowed', '', '', u.data.allowed);
    bag.add('ai.requests', 'blocked', '', '', u.data.blocked);
    if (u.data.total != null) bag.add('ai.total_requests', 'total', '', '', u.data.total);
    else unavailable('total', u.data.totalReason);
  } else {
    unavailable('usage', u && u.reason);
  }

  const a = data.apps;
  if (ready(a)) {
    declare('apps');
    (a.data.rows || []).forEach((r) => {
      const meta = { mapped: !!r.mapped };
      bag.add('ai.app_allowed', r.key, r.name, '', r.allowed, null, meta);
      bag.add('ai.app_blocked', r.key, r.name, '', r.blocked, null, meta);
    });
    if (a.data.sampled) bag.add('ai.sampled', 'apps', '', '', 1);
  } else {
    unavailable('apps', a && a.reason);
  }

  const us = data.users;
  if (ready(us)) {
    declare('users');
    (us.data.rows || []).forEach(r => bag.add('ai.user', r.user, r.appKey, '', r.count));
    if (us.data.sampled) bag.add('ai.sampled', 'users', '', '', 1);
  } else {
    unavailable('users', us && us.reason);
  }

  const p = data.policy;
  if (ready(p)) {
    declare('policy');
    // One row per policy name: two policies sharing a name would collide on the
    // rollup's unique key. Blocked wins, so a merge never hides a block.
    const byName = new Map();
    (p.data.rows || []).forEach((r) => {
      const prev = byName.get(r.name);
      const state = r.aiBlocked === null ? 'unknown' : (r.aiBlocked ? 'blocked' : 'allowed');
      if (!prev || state === 'blocked' || (prev.state === 'unknown' && state === 'allowed')) {
        byName.set(r.name, { state, allowListOnly: r.allowListOnly || (prev && prev.allowListOnly) });
      }
    });
    byName.forEach((v, name) => bag.add('ai.policy', name, v.state, v.allowListOnly ? 'allow_list_only' : '', 1));
  } else {
    unavailable('policy', p && p.reason);
  }

  return bag;
}

async function daysNeedingSnapshot(pool, integrationId, timeZone, now) {
  const today = wm.localDay(now || new Date(), timeZone);
  const res = await pool.query(
    `SELECT day::text AS day, status
       FROM wazuh_rollup_run
      WHERE integration_id = $1 AND source = $2 AND day >= $3::date`,
    [integrationId, SOURCE, wm.shiftDay(today, -BACKFILL_DAYS)]
  );
  const complete = new Set(res.rows.filter(r => r.status === 'ok' || r.status === 'no_data').map(r => r.day));

  const out = [];
  for (let i = 0; i <= BACKFILL_DAYS; i++) {
    const day = wm.shiftDay(today, -i);
    if (i < RECOLLECT_DAYS || !complete.has(day)) out.push(day);
  }
  return out.slice(0, MAX_DAYS_PER_RUN);
}

/**
 * Collect one day and store it.
 *
 * @param {object} integration { id, tenant_id, base_url, api_key, config }
 *                             config carries organization_id, aiCategoryId, timeZone
 * @param {object} [opts]      { now, cfg } — cfg merges over the config (test seams)
 */
async function snapshotDay(pool, integration, day, opts) {
  const o = opts || {};
  const started = Date.now();
  const cfg = Object.assign({}, dns.sanitiseStoredConfig(integration.config), {
    base_url: integration.base_url,
    api_key: integration.api_key,
  }, o.cfg || {});
  const now = o.now || Date.now();
  const today = wm.localDay(new Date(now), cfg.timeZone || 'UTC');
  const recent = day >= wm.shiftDay(today, -(RECOLLECT_DAYS - 1));

  let data;
  try {
    data = await dns.fetchAiDay(cfg, day, { now });
  } catch (err) {
    data = { _error: err.message };
  }

  let bag, status, message;
  let problems = [];
  if (data._error) {
    bag = wm.rowBag(SOURCE);
    status = 'error';
    message = data._error;
    problems = [data._error];
  } else {
    bag = flattenAi(data);
    problems = bag.rows.filter(r => r.metric === 'ai.unavailable').map(r => `${r.dim1} (${r.dim2})`);
    const dataRows = bag.rows.filter(r => r.metric !== 'ai.unavailable' && r.metric !== 'ai.sampled').length;
    status = recent ? 'partial_day' : (problems.length ? 'partial' : (dataRows ? 'ok' : 'no_data'));
    message = problems.length ? `Not read: ${problems.join(', ')}` : (recent ? 'Day in progress — re-collected hourly.' : null);
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

  return { day, rows, status, problems, error: data._error || null };
}

// ── Reading back ─────────────────────────────────────────────────────────────

function sumBy(rows, keyOf) {
  const m = new Map();
  (rows || []).forEach((r) => { const k = keyOf(r); m.set(k, (m.get(k) || 0) + r.value); });
  return m;
}

/**
 * Rebuild the AI Visibility summary from rollups, scoped to one integration.
 *
 * "Not recorded is not none", per panel:
 *   - a panel with data but unread on some days still renders, and lists what
 *     was not read in `unavailable`;
 *   - a panel with no data and a recorded reason is unavailable WITH that reason;
 *   - the AI share of traffic is null unless every day with AI figures also has
 *     the all-traffic denominator — a share over half the days is not a share.
 */
async function aiFromRollups(pool, tenantId, days, integrationId) {
  const m = await wm.loadMetrics(pool, tenantId, SOURCE, days, integrationId);
  const get = k => m.get(k) || [];

  const unavailByPart = new Map();
  get('ai.unavailable').forEach(r => unavailByPart.set(r.dim1, r.dim2 || 'query_error'));
  const sampled = [...new Set(get('ai.sampled').map(r => r.dim1))];

  const envFor = (data, hasRows, part) => {
    if (hasRows) {
      const reason = unavailByPart.get(part);
      return { available: true, data: Object.assign(data, { unavailableOnSomeDays: reason || null }), reason: null, lastEventAt: null };
    }
    if (unavailByPart.has(part)) return { available: false, data: null, reason: unavailByPart.get(part), lastEventAt: null };
    return { available: true, data, reason: 'no_data_in_range', lastEventAt: null };
  };

  // Usage
  const req = get('ai.requests');
  const allowed = req.filter(r => r.dim1 === 'allowed').reduce((s, r) => s + r.value, 0);
  const blocked = req.filter(r => r.dim1 === 'blocked').reduce((s, r) => s + r.value, 0);
  const byDay = new Map();
  req.forEach((r) => {
    if (!byDay.has(r.day)) byDay.set(r.day, { date: r.day, allowed: 0, blocked: 0 });
    byDay.get(r.day)[r.dim1 === 'blocked' ? 'blocked' : 'allowed'] += r.value;
  });
  const reqDays = new Set(req.map(r => r.day));
  const totalRows = get('ai.total_requests');
  const totalDays = new Set(totalRows.map(r => r.day));
  const totalComplete = reqDays.size > 0 && [...reqDays].every(d => totalDays.has(d));
  const total = totalComplete ? totalRows.reduce((s, r) => s + r.value, 0) : null;
  const usage = {
    allowed, blocked,
    total,
    sharePct: total ? Math.round(((allowed + blocked) / total) * 1000) / 10 : null,
    totalReason: totalComplete ? null : (unavailByPart.get('total') || (reqDays.size ? 'incomplete' : null)),
    trend: [...byDay.values()].sort((x, y) => x.date.localeCompare(y.date)),
  };

  // Apps
  const allowedBy = sumBy(get('ai.app_allowed'), r => r.dim1);
  const blockedBy = sumBy(get('ai.app_blocked'), r => r.dim1);
  const names = new Map();
  const mapped = new Map();
  get('ai.app_allowed').concat(get('ai.app_blocked'))
    .sort((x, y) => x.day.localeCompare(y.day))
    .forEach((r) => { names.set(r.dim1, r.dim2 || r.dim1); mapped.set(r.dim1, !!(r.meta && r.meta.mapped)); });
  const appRows = [...names.keys()].map(key => ({
    key, name: names.get(key), mapped: mapped.get(key),
    allowed: allowedBy.get(key) || 0, blocked: blockedBy.get(key) || 0,
  })).filter(r => r.allowed + r.blocked > 0)
    .sort((x, y) => (y.allowed + y.blocked) - (x.allowed + x.blocked))
    .slice(0, 100);
  const apps = { rows: appRows, sampled: sampled.indexOf('apps') >= 0 };

  // Users (staff-only)
  const userTotals = sumBy(get('ai.user'), r => r.dim1);
  const userApps = new Map();
  get('ai.user').forEach((r) => {
    if (!userApps.has(r.dim1)) userApps.set(r.dim1, new Map());
    const um = userApps.get(r.dim1);
    if (r.dim2) um.set(r.dim2, (um.get(r.dim2) || 0) + r.value);
  });
  const users = {
    rows: [...userTotals.entries()].sort((x, y) => y[1] - x[1]).slice(0, 25).map(([user, count]) => ({
      user, count,
      apps: [...(userApps.get(user) || new Map()).entries()].sort((x, y) => y[1] - x[1]).slice(0, 3)
        .map(([key, c]) => ({ key, name: names.get(key) || key, count: c })),
    })),
    sampled: sampled.indexOf('users') >= 0,
  };

  // Policy — current state, from the most recent day that read it.
  const pol = get('ai.policy');
  const latest = pol.reduce((d, r) => (r.day > d ? r.day : d), '');
  const policy = {
    asOf: latest || null,
    rows: pol.filter(r => r.day === latest).map(r => ({
      name: r.dim1,
      aiBlocked: r.dim2 === 'unknown' ? null : r.dim2 === 'blocked',
      allowListOnly: r.dim3 === 'allow_list_only',
    })),
  };

  return {
    usage:  envFor(usage, req.length > 0, 'usage'),
    apps:   envFor(apps, get('ai.app_allowed').length + get('ai.app_blocked').length > 0, 'apps'),
    users:  envFor(users, get('ai.user').length > 0, 'users'),
    policy: envFor(policy, pol.length > 0, 'policy'),
  };
}

module.exports = {
  SOURCE,
  BACKFILL_DAYS,
  RECOLLECT_DAYS,
  MAX_DAYS_PER_RUN,
  PART_METRICS,
  flattenAi,
  daysNeedingSnapshot,
  snapshotDay,
  aiFromRollups,
};
