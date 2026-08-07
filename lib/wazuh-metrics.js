'use strict';

/**
 * lib/wazuh-metrics.js
 *
 * The Postgres half of the hybrid data model.
 *
 *   ≤ 30 days  → the screens live-query the Wazuh Indexer (adapter).
 *   > 30 days  → the screens read the daily rollups written by this module.
 *
 * The two sources are never mixed inside one chart: approximate `cardinality`
 * and top-N truncation make the numbers differ slightly, and a chart that
 * silently switches mid-series reads as a bug. Each summary carries a
 * `source: 'live' | 'rollup'` field so the UI can label it.
 *
 * Both paths produce the SAME summary shape, so the tab modules do not care
 * which one served them.
 */

const wazuh = require('./integrations/wazuh-indexer');

// Ranges up to this many days are served live; longer ranges come from rollups.
const LIVE_MAX_DAYS = 30;

// How far back the backfill pass looks for days that were never snapshotted or
// that failed. Also the window in which late-arriving O365 events get picked up.
const BACKFILL_DAYS = 14;

// ── Row helpers ────────────────────────────────────────────────────────────

/** Accumulates metric rows for one (integration, day, source) snapshot. */
function rowBag(source) {
  const rows = [];
  const metrics = new Set();

  function add(metric, dim1, dim2, dim3, value, value2, meta) {
    // Empty labels would collide on the unique constraint and are useless in a
    // chart legend — drop them rather than writing an "" bucket.
    const d1 = dim1 == null ? '' : String(dim1);
    if (dim1 !== undefined && dim1 !== null && d1 === '') return;
    rows.push({
      source, metric,
      dim1: d1,
      dim2: dim2 == null ? '' : String(dim2),
      dim3: dim3 == null ? '' : String(dim3),
      value:  Number(value) || 0,
      value2: value2 === undefined || value2 === null ? null : Number(value2),
      meta:   meta ? JSON.stringify(meta) : null,
    });
    metrics.add(metric);
  }

  /** Write a tally() array ([{label, count, …}]) as one metric. */
  function addTally(metric, list, pick) {
    (list || []).forEach(r => {
      const extra = pick ? pick(r) : {};
      add(metric, r.label, extra.dim2, extra.dim3, r.count, extra.value2, extra.meta);
    });
  }

  return { rows, metrics, add, addTally, source };
}

// ── Flattening: live adapter output → metric rows ──────────────────────────

/** Managed NDR panels → rows for one day. */
function flattenNdr(data) {
  const bag = rowBag('fortigate');

  const t = data.traffic && data.traffic.available ? data.traffic.data : null;
  if (t) {
    bag.add('traffic.decision', 'allowed', '', '', t.allowed);
    bag.add('traffic.decision', 'denied',  '', '', t.denied);
    (t.trend || []).forEach(d => {
      // The daily snapshot covers a single day, so the trend collapses to the
      // distinct-source estimate for that day.
      bag.add('traffic.sources', 'unique', '', '', d.sources || 0);
    });
    bag.addTally('traffic.top_dst_port', t.topPorts,    r => ({ dim2: r.service }));
    bag.addTally('traffic.top_service',  t.topServices);
    bag.addTally('traffic.top_policy',   t.topPolicies, r => ({ dim2: r.name }));
    bag.addTally('traffic.top_src',      t.topSources,  r => ({ dim2: r.country }));
    bag.addTally('traffic.top_dst',      t.topTargets);
  }

  const th = data.threats && data.threats.available ? data.threats.data : null;
  if (th) {
    bag.add('ips.outcome', 'blocked', '', '', th.blocked);
    bag.add('ips.outcome', 'allowed', '', '', th.allowed);
    bag.add('ips.total',   'total',   '', '', th.total, th.uniqueSources);
    bag.addTally('ips.attack', th.topAttacks, r => ({
      dim2: r.severity, value2: r.targets, meta: { blocked: r.blocked, allowed: r.allowed },
    }));
    bag.addTally('ips.severity',  th.bySeverity);
    bag.addTally('ips.action',    th.byAction);
    bag.addTally('ips.top_src',   th.topSources, r => ({ dim2: r.country }));
    bag.addTally('ips.top_dst',   th.topTargets);
    bag.addTally('utm.virus',     th.virus     && th.virus.top);
    bag.addTally('utm.webfilter', th.webfilter && th.webfilter.top);
    bag.addTally('utm.appctrl',   th.appctrl   && th.appctrl.top, r => ({ dim2: r.category }));
  }

  const g = data.geo && data.geo.available ? data.geo.data : null;
  if (g) {
    bag.addTally('geo.src_country', g.countries, r => ({
      value2: r.sources, meta: { denied: r.denied },
    }));
  }

  const va = data.vpnAdmin && data.vpnAdmin.available ? data.vpnAdmin.data : null;
  if (va) {
    bag.add('vpn.outcome', 'success', '', '', va.vpn.success);
    bag.add('vpn.outcome', 'failure', '', '', va.vpn.failed);
    bag.addTally('vpn.failed_user', va.vpn.failedUsers, r => ({ dim2: r.reason, value2: r.sources }));
    bag.add('admin.login_total', 'total',  '', '', va.admin.logins);
    bag.add('admin.login_total', 'failed', '', '', va.admin.failedLogins);
    bag.addTally('admin.login',            va.admin.topAdmins, r => ({ dim2: r.via }));
    bag.add('admin.config_total', 'total', '', '', va.admin.configChanges);
    bag.addTally('admin.config_change',    va.admin.changesByPath);
    bag.addTally('admin.config_admin',     va.admin.changesByAdmin);
  }

  return bag;
}

/** Managed O365 panels → rows for one day, split by source. */
function flattenO365(data) {
  const o = rowBag('office365');
  const g = rowBag('ms-graph');

  const d = data.o365 && data.o365.available ? data.o365.data : null;
  if (d) {
    o.add('o365.signin', 'success', '', '', d.signins.success, d.signins.uniqueUsers);
    o.add('o365.signin', 'failed',  '', '', d.signins.failed);
    o.addTally('o365.login_error', d.failedLogins.byReason);
    o.addTally('o365.failed_user', d.failedLogins.byUser, r => ({ value2: r.distinctIps }));
    o.addTally('o365.failed_ip',   d.failedLogins.byIp,   r => ({
      value2: r.targetedUsers, meta: { spray: r.spray },
    }));
    o.add('o365.admin_total', 'total', '', '', d.admin.total);
    o.addTally('o365.admin_op',      d.admin.byOperation);
    o.addTally('o365.admin_actor',   d.admin.byActor);
    o.add('o365.mailbox_total', 'total', '', '', d.mailboxRules.total);
    o.addTally('o365.mailbox_op',    d.mailboxRules.byOperation);
    o.addTally('o365.mailbox_owner', d.mailboxRules.byMailbox);
    o.add('o365.sharing_total', 'total', '', '', d.sharing.total);
    o.addTally('o365.sharing_op',    d.sharing.byOperation);
    o.addTally('o365.sharing_site',  d.sharing.bySite);
    o.addTally('o365.sharing_user',  d.sharing.byUser);
    o.add('o365.dlp_total', 'total', '', '', d.dlp.total);
    o.addTally('o365.dlp_policy',    d.dlp.byPolicy);
    o.addTally('o365.dlp_info',      d.dlp.byInfoType);
    o.addTally('o365.workload',      d.byWorkload);
  }

  const gd = data.graph && data.graph.available ? data.graph.data : null;
  if (gd) {
    g.add('graph.alert_total', 'total', '', '', gd.alerts.total);
    g.add('graph.alert_total', 'high',  '', '', gd.alerts.high);
    g.addTally('graph.alert',           gd.alerts.bySeverity);
    g.addTally('graph.alert_status',    gd.alerts.byStatus);
    g.addTally('graph.alert_source',    gd.alerts.bySource);
    g.addTally('graph.alert_technique', gd.alerts.byTechnique);
    // riskyUsers is state, not events — one row per user carrying its latest
    // level/state, value 1 so a COUNT over the day is a distinct-user count.
    (gd.riskyUsers.users || []).forEach(u => {
      g.add('graph.risky_user', u.label, u.level, u.state, 1, null, { detail: u.detail });
    });
    g.addTally('graph.risk_type',    gd.riskDetections.byType);
    g.addTally('graph.risk_country', gd.riskDetections.byCountry);
    g.addTally('graph.signin_country', gd.signins.byCountry, r => ({
      value2: r.users, meta: { failed: r.failed },
    }));
    g.add('graph.signin_total', 'total', '', '', gd.signins.total);
    g.add('graph.legacy_auth_total', 'total', '', '', gd.signins.legacyAuth.total);
    g.addTally('graph.legacy_auth',  gd.signins.legacyAuth.byUser);
    g.add('graph.ca_failure', 'total', '', '', gd.signins.caFailures);
    // Identity posture tallies. Absent fields produce no rows at all, which the
    // report reads as "not measured" rather than as a zero score.
    g.addTally('graph.auth_requirement',  gd.signins.authRequirement);
    g.addTally('graph.ca_status',         gd.signins.caStatus);
    g.addTally('graph.device_compliance', gd.signins.deviceCompliance);
    g.addTally('graph.risk_state',        gd.riskyUsers.byState);
  }

  return { office365: o, msgraph: g };
}

// ── Writing a snapshot ─────────────────────────────────────────────────────

/**
 * Persist one (integration, day, source) bag idempotently.
 *
 * `ON CONFLICT DO UPDATE` alone is NOT sufficient for dimensioned metrics: if
 * today's run returns a different top-15 than the previous run, the names that
 * dropped out would linger as stale rows and inflate every total. So we first
 * delete the day's rows *for exactly the metrics this run produced*, then bulk
 * insert. Scoping the delete to those metrics means a partial run — FortiGate
 * fine, Office 365 down — never wipes the other source's data.
 */
async function writeBag(client, { tenantId, integrationId, day, bag, status, message, docCount, durationMs }) {
  const metrics = [...bag.metrics];

  if (metrics.length) {
    await client.query(
      `DELETE FROM wazuh_daily_metric
        WHERE integration_id = $1 AND day = $2 AND source = $3 AND metric = ANY($4::text[])`,
      [integrationId, day, bag.source, metrics]
    );
  }

  if (bag.rows.length) {
    await client.query(
      `INSERT INTO wazuh_daily_metric
         (tenant_id, integration_id, day, source, metric, dim1, dim2, dim3, value, value2, meta)
       SELECT * FROM UNNEST(
         $1::int[], $2::int[], $3::date[], $4::text[], $5::text[],
         $6::text[], $7::text[], $8::text[], $9::numeric[], $10::numeric[], $11::jsonb[])
       ON CONFLICT ON CONSTRAINT wazuh_daily_metric_uniq
       DO UPDATE SET value  = EXCLUDED.value,
                     value2 = EXCLUDED.value2,
                     meta   = EXCLUDED.meta,
                     updated_at = now()`,
      [
        bag.rows.map(() => tenantId),
        bag.rows.map(() => integrationId),
        bag.rows.map(() => day),
        bag.rows.map(r => r.source),
        bag.rows.map(r => r.metric),
        bag.rows.map(r => r.dim1),
        bag.rows.map(r => r.dim2),
        bag.rows.map(r => r.dim3),
        bag.rows.map(r => r.value),
        bag.rows.map(r => r.value2),
        bag.rows.map(r => r.meta),
      ]
    );
  }

  await client.query(
    `INSERT INTO wazuh_rollup_run
       (integration_id, day, source, status, message, rows_written, doc_count, duration_ms)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
     ON CONFLICT ON CONSTRAINT wazuh_rollup_run_uniq
     DO UPDATE SET status = EXCLUDED.status, message = EXCLUDED.message,
                   rows_written = EXCLUDED.rows_written, doc_count = EXCLUDED.doc_count,
                   duration_ms = EXCLUDED.duration_ms, ran_at = now()`,
    [integrationId, day, bag.source, status, message || null, bag.rows.length,
     docCount == null ? null : docCount, durationMs == null ? null : durationMs]
  );

  return bag.rows.length;
}

/**
 * Snapshot one tenant-local day for one integration.
 *
 * @param {object} pool        pg pool
 * @param {object} integration { id, tenant_id, base_url, api_key, config }
 * @param {string} day         'YYYY-MM-DD' in the tenant's zone
 */
async function snapshotDay(pool, integration, day) {
  const started = Date.now();
  const cfg = Object.assign({}, integration.config || {}, {
    base_url: integration.base_url,
    api_key:  integration.api_key,
  });
  const tz = cfg.timeZone || 'UTC';

  // Unqualified bounds resolved by the range clause's time_zone, so the day
  // boundary matches what the live chart draws.
  const range = { from: `${day}T00:00:00.000`, to: `${day}T23:59:59.999`, tz };

  const [ndr, o365] = await Promise.all([
    wazuh.fetchNdr(cfg, range).catch(err => ({ _error: err.message })),
    wazuh.fetchO365(cfg, range).catch(err => ({ _error: err.message })),
  ]);

  const bags = [];

  if (ndr._error) {
    bags.push({ bag: rowBag('fortigate'), status: 'error', message: ndr._error });
  } else {
    const bag = flattenNdr(ndr);
    bags.push({
      bag,
      status: (ndr._partial || []).length ? 'partial' : (bag.rows.length ? 'ok' : 'no_data'),
      message: (ndr._partial || []).length ? `Panels unavailable: ${ndr._partial.join(', ')}` : null,
    });
  }

  if (o365._error) {
    ['office365', 'ms-graph'].forEach(src => {
      bags.push({ bag: rowBag(src), status: 'error', message: o365._error });
    });
  } else {
    const split = flattenO365(o365);
    const partial = o365._partial || [];
    bags.push({
      bag: split.office365,
      status: partial.includes('o365') ? 'error' : (split.office365.rows.length ? 'ok' : 'no_data'),
      message: partial.includes('o365') ? 'Office 365 search failed.' : null,
    });
    bags.push({
      bag: split.msgraph,
      status: partial.includes('graph') ? 'error' : (split.msgraph.rows.length ? 'ok' : 'no_data'),
      message: partial.includes('graph') ? 'MS Graph search failed.' : null,
    });
  }

  const durationMs = Date.now() - started;
  let written = 0;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const b of bags) {
      written += await writeBag(client, {
        tenantId: integration.tenant_id,
        integrationId: integration.id,
        day,
        bag: b.bag,
        status: b.status,
        message: b.message,
        durationMs,
      });
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }

  return { day, rows: written, sources: bags.map(b => ({ source: b.bag.source, status: b.status })) };
}

/**
 * Days in the recent window that were never snapshotted, or whose last run
 * errored or came back partial.
 *
 * Yesterday is always included even when it looks fine: the Office 365
 * Management Activity API routinely delivers events hours late (up to 24h), so
 * a day that read as complete last night is often incomplete. Re-snapshotting
 * it is safe precisely because writeBag is idempotent.
 */
async function daysNeedingSnapshot(pool, integrationId, timeZone) {
  const today     = localDay(new Date(), timeZone);
  const yesterday = shiftDay(today, -1);

  const res = await pool.query(
    `SELECT day::text AS day, source, status
       FROM wazuh_rollup_run
      WHERE integration_id = $1 AND day >= $2::date`,
    [integrationId, shiftDay(today, -BACKFILL_DAYS)]
  );

  const good = new Map();
  res.rows.forEach(r => {
    const prev = good.get(r.day);
    const ok = r.status === 'ok' || r.status === 'no_data';
    good.set(r.day, prev === undefined ? ok : prev && ok);
  });

  const out = [];
  for (let i = 1; i <= BACKFILL_DAYS; i++) {
    const day = shiftDay(today, -i);
    if (day === yesterday || good.get(day) !== true) out.push(day);
  }
  return out;
}

// ── Date helpers (tenant-local) ────────────────────────────────────────────

/** 'YYYY-MM-DD' for `date` as seen in `timeZone`. */
function localDay(date, timeZone) {
  try {
    return new Intl.DateTimeFormat('en-CA', {
      timeZone: timeZone || 'UTC', year: 'numeric', month: '2-digit', day: '2-digit',
    }).format(date);
  } catch (_) {
    return date.toISOString().slice(0, 10);
  }
}

/** Shift a 'YYYY-MM-DD' string by whole days without tripping over DST. */
function shiftDay(day, delta) {
  const d = new Date(`${day}T12:00:00Z`);
  d.setUTCDate(d.getUTCDate() + delta);
  return d.toISOString().slice(0, 10);
}

// ── Reading rollups back ───────────────────────────────────────────────────

/**
 * Load every metric row for a source over a window, indexed by metric name.
 * @returns {Map<string, Array<{dim1,dim2,dim3,value,value2,meta,day}>>}
 */
async function loadMetrics(pool, tenantId, source, days) {
  const res = await pool.query(
    `SELECT day::text AS day, metric, dim1, dim2, dim3, value, value2, meta
       FROM wazuh_daily_metric
      WHERE tenant_id = $1 AND source = $2
        AND day >= (CURRENT_DATE - ($3::int * INTERVAL '1 day'))
      ORDER BY day`,
    [tenantId, source, days]
  );

  const byMetric = new Map();
  res.rows.forEach(r => {
    if (!byMetric.has(r.metric)) byMetric.set(r.metric, []);
    byMetric.get(r.metric).push({
      day: r.day,
      dim1: r.dim1, dim2: r.dim2, dim3: r.dim3,
      value:  Number(r.value)  || 0,
      value2: r.value2 == null ? null : Number(r.value2),
      meta:   r.meta || {},
    });
  });
  return byMetric;
}

/** Sum a metric's rows by dim1, newest label wins for dim2/dim3. */
function rollTally(rows, limit) {
  const acc = new Map();
  (rows || []).forEach(r => {
    const prev = acc.get(r.dim1);
    if (prev) {
      prev.count += r.value;
      if (r.value2 != null) prev._v2 = Math.max(prev._v2 || 0, r.value2);
      prev.dim2 = r.dim2 || prev.dim2;
      prev.dim3 = r.dim3 || prev.dim3;
      Object.assign(prev.meta, r.meta || {});
    } else {
      acc.set(r.dim1, {
        label: r.dim1, count: r.value, _v2: r.value2, dim2: r.dim2, dim3: r.dim3,
        meta: Object.assign({}, r.meta),
      });
    }
  });
  const out = [...acc.values()].sort((a, b) => b.count - a.count);
  return limit ? out.slice(0, limit) : out;
}

/** Total of a metric, optionally restricted to one dim1 label. */
function rollTotal(rows, label) {
  return (rows || [])
    .filter(r => label === undefined || r.dim1 === label)
    .reduce((s, r) => s + r.value, 0);
}

/** Per-day series of a metric, with named dim1 labels as separate keys. */
function rollSeries(rows, labelKeys) {
  const byDay = new Map();
  (rows || []).forEach(r => {
    if (!byDay.has(r.day)) {
      const seed = { date: r.day, count: 0 };
      Object.values(labelKeys || {}).forEach(k => { seed[k] = 0; });
      byDay.set(r.day, seed);
    }
    const d = byDay.get(r.day);
    d.count += r.value;
    const key = labelKeys && labelKeys[r.dim1];
    if (key) d[key] += r.value;
  });
  return [...byDay.values()].sort((a, b) => a.date.localeCompare(b.date));
}

const env = (data, rows) => ({
  available: true,
  data,
  reason: (rows && rows.length) ? null : 'no_data_in_range',
  lastEventAt: null,
});

/** Rebuild the Managed NDR summary shape from rollups. */
async function ndrFromRollups(pool, tenantId, days) {
  const m = await loadMetrics(pool, tenantId, 'fortigate', days);
  const get = k => m.get(k) || [];

  const traffic = {
    allowed: rollTotal(get('traffic.decision'), 'allowed'),
    denied:  rollTotal(get('traffic.decision'), 'denied'),
    trend:   rollSeries(get('traffic.decision'), { allowed: 'allowed', denied: 'denied' }),
    topPorts:    rollTally(get('traffic.top_dst_port'), 10).map(r => ({ label: r.label, count: r.count, service: r.dim2 })),
    topServices: rollTally(get('traffic.top_service'), 10),
    topPolicies: rollTally(get('traffic.top_policy'), 10).map(r => ({ label: r.label, count: r.count, name: r.dim2 })),
    topSources:  rollTally(get('traffic.top_src'), 10).map(r => ({ label: r.label, count: r.count, country: r.dim2 })),
    topTargets:  rollTally(get('traffic.top_dst'), 10),
  };

  const attacks = rollTally(get('ips.attack'), 15);
  const threats = {
    total:   rollTotal(get('ips.total')),
    blocked: rollTotal(get('ips.outcome'), 'blocked'),
    allowed: rollTotal(get('ips.outcome'), 'allowed'),
    uniqueSources: Math.max(0, ...get('ips.total').map(r => r.value2 || 0)),
    topAttacks: attacks.map(r => ({
      label: r.label, count: r.count, severity: r.dim2,
      blocked: r.meta.blocked || 0, allowed: r.meta.allowed || 0, targets: r._v2 || 0,
    })),
    bySeverity: rollTally(get('ips.severity')),
    byAction:   rollTally(get('ips.action')),
    topSources: rollTally(get('ips.top_src'), 10).map(r => ({ label: r.label, count: r.count, country: r.dim2 })),
    topTargets: rollTally(get('ips.top_dst'), 10),
    trend: rollSeries(get('ips.outcome'), { blocked: 'blocked' }),
    virus:     { total: 0, top: rollTally(get('utm.virus'), 10) },
    webfilter: { total: 0, top: rollTally(get('utm.webfilter'), 10) },
    appctrl:   { total: 0, top: rollTally(get('utm.appctrl'), 10).map(r => ({ label: r.label, count: r.count, category: r.dim2 })) },
  };

  const geo = {
    countries: rollTally(get('geo.src_country'), 20).map(r => ({
      label: r.label, count: r.count, sources: r._v2 || 0, denied: r.meta.denied || 0,
    })),
    source: 'fortigate',
  };

  const vpnAdmin = {
    vpn: {
      total:   rollTotal(get('vpn.outcome')),
      success: rollTotal(get('vpn.outcome'), 'success'),
      failed:  rollTotal(get('vpn.outcome'), 'failure'),
      failedUsers: rollTally(get('vpn.failed_user'), 10).map(r => ({
        label: r.label, count: r.count, reason: r.dim2, sources: r._v2 || 0,
      })),
      trend: rollSeries(get('vpn.outcome'), { failure: 'failed' }),
    },
    admin: {
      logins:       rollTotal(get('admin.login_total'), 'total'),
      failedLogins: rollTotal(get('admin.login_total'), 'failed'),
      topAdmins:    rollTally(get('admin.login'), 10).map(r => ({ label: r.label, count: r.count, via: r.dim2 })),
      configChanges:  rollTotal(get('admin.config_total'), 'total'),
      changesByPath:  rollTally(get('admin.config_change'), 15),
      changesByAdmin: rollTally(get('admin.config_admin'), 10),
    },
  };

  return {
    traffic:  env(traffic,  get('traffic.decision')),
    threats:  env(threats,  get('ips.total')),
    geo:      env(geo,      get('geo.src_country')),
    vpnAdmin: env(vpnAdmin, get('vpn.outcome').concat(get('admin.login_total'))),
    _partial: [],
  };
}

/** Rebuild the Managed Office 365 summary shape from rollups. */
async function o365FromRollups(pool, tenantId, days) {
  const [mo, mg] = await Promise.all([
    loadMetrics(pool, tenantId, 'office365', days),
    loadMetrics(pool, tenantId, 'ms-graph',  days),
  ]);
  const o = k => mo.get(k) || [];
  const g = k => mg.get(k) || [];

  const o365 = {
    signins: {
      success: rollTotal(o('o365.signin'), 'success'),
      failed:  rollTotal(o('o365.signin'), 'failed'),
      uniqueUsers: Math.max(0, ...o('o365.signin').map(r => r.value2 || 0)),
      trend: rollSeries(o('o365.signin'), { success: 'success', failed: 'failed' }),
    },
    failedLogins: {
      byReason: rollTally(o('o365.login_error'), 12),
      byUser:   rollTally(o('o365.failed_user'), 15).map(r => ({ label: r.label, count: r.count, distinctIps: r._v2 || 0 })),
      byIp:     rollTally(o('o365.failed_ip'), 15).map(r => ({
        label: r.label, count: r.count, targetedUsers: r._v2 || 0, spray: !!r.meta.spray,
      })),
    },
    admin: {
      total:       rollTotal(o('o365.admin_total'), 'total'),
      byOperation: rollTally(o('o365.admin_op'), 15),
      byActor:     rollTally(o('o365.admin_actor'), 10),
      recent: [], // top_hits detail is live-only; rollups keep counts, not events
    },
    mailboxRules: {
      total:       rollTotal(o('o365.mailbox_total'), 'total'),
      byOperation: rollTally(o('o365.mailbox_op'), 10),
      byMailbox:   rollTally(o('o365.mailbox_owner'), 10),
      recent: [],
    },
    sharing: {
      total:       rollTotal(o('o365.sharing_total'), 'total'),
      byOperation: rollTally(o('o365.sharing_op'), 10),
      bySite:      rollTally(o('o365.sharing_site'), 10),
      byUser:      rollTally(o('o365.sharing_user'), 10),
    },
    dlp: {
      total:      rollTotal(o('o365.dlp_total'), 'total'),
      byPolicy:   rollTally(o('o365.dlp_policy'), 10),
      byInfoType: rollTally(o('o365.dlp_info'), 10),
      trend:      rollSeries(o('o365.dlp_total')),
    },
    byWorkload: rollTally(o('o365.workload'), 10),
  };

  const graph = {
    alerts: {
      total: rollTotal(g('graph.alert_total'), 'total'),
      high:  rollTotal(g('graph.alert_total'), 'high'),
      bySeverity:  rollTally(g('graph.alert')),
      byStatus:    rollTally(g('graph.alert_status')),
      bySource:    rollTally(g('graph.alert_source')),
      byTechnique: rollTally(g('graph.alert_technique'), 12),
      trend: rollSeries(g('graph.alert_total'), { high: 'high' }),
      recent: [],
    },
    riskyUsers: {
      // One row per user per day with value 1, so the distinct count is the
      // number of users seen at risk anywhere in the window.
      distinct: rollTally(g('graph.risky_user')).length,
      users: rollTally(g('graph.risky_user'), 25).map(r => ({
        label: r.label, level: r.dim2, state: r.dim3, detail: r.meta.detail || null, updatedAt: null,
      })),
      byState: rollTally(g('graph.risk_state'), 8),
    },
    riskDetections: {
      byType:    rollTally(g('graph.risk_type'), 15),
      byCountry: rollTally(g('graph.risk_country'), 20),
    },
    signins: {
      total: rollTotal(g('graph.signin_total'), 'total'),
      byCountry: rollTally(g('graph.signin_country'), 25).map(r => ({
        label: r.label, count: r.count, users: r._v2 || 0, failed: r.meta.failed || 0,
      })),
      legacyAuth: {
        total:  rollTotal(g('graph.legacy_auth_total'), 'total'),
        byUser: rollTally(g('graph.legacy_auth'), 10),
      },
      caFailures: rollTotal(g('graph.ca_failure'), 'total'),
      authRequirement:  rollTally(g('graph.auth_requirement'), 8),
      caStatus:         rollTally(g('graph.ca_status'), 8),
      deviceCompliance: rollTally(g('graph.device_compliance'), 4),
    },
  };

  return {
    o365:  env(o365,  o('o365.signin')),
    graph: env(graph, g('graph.alert_total').concat(g('graph.signin_total'))),
    _partial: [],
  };
}

module.exports = {
  LIVE_MAX_DAYS,
  BACKFILL_DAYS,
  snapshotDay,
  daysNeedingSnapshot,
  ndrFromRollups,
  o365FromRollups,
  localDay,
  shiftDay,
  flattenNdr,
  flattenO365,
};
