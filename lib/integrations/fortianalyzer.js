'use strict';

/**
 * FortiAnalyzer adapter — Managed NDR telemetry, read directly.
 *
 * ══ THE ONLY SOURCE FOR NDR ══
 *
 * FortiGate logs used to reach the dashboard second-hand, via syslog into a
 * log platform we also paid to run. Every client's firewalls already log to our
 * FortiAnalyzer, which is built for exactly this, so the NDR screen reads it
 * directly and the middleman was removed.
 *
 * fetchNdrDay() returns { traffic, threats, geo, vpnAdmin } envelopes — the
 * shape the NDR tab, the daily rollups (lib/daily-metrics.js flattenNdr /
 * ndrFromRollups) and the board report all consume.
 *
 * ══ API ══
 *
 * FortiAnalyzer 7.6 JSON-RPC: POST {base}/jsonrpc with
 *   { id, jsonrpc: '2.0', method, params: [{ url, ...options }] }
 * authenticated by a REST API admin's token (Authorization: Bearer). The token
 * is stored in the integrations row's encrypted api_key column, like every
 * other credential; the ADOM name and time zone live in config_json.
 *
 * Log search and FortiView are ASYNCHRONOUS TASKS:
 *   add  {url}           → { tid }
 *   get  {url}/{tid}     → { percentage, total-count, data } — poll to 100
 *   delete {url}/{tid}   → cancel/clean up
 * runTask() always deletes the task afterwards, including on timeout, so
 * abandoned searches cannot pile up on a FortiAnalyzer every client shares.
 *
 * ══ ONE FORTIANALYZER, EVERY CLIENT ══
 *
 *   - The ADOM comes from the integration row ONLY, is validated strictly (it
 *     is interpolated into the JSON-RPC url), and is never taken from a request.
 *   - Each client should have its own REST API admin restricted to its own
 *     ADOM, read-only. Then a mistake in this code cannot cross clients either.
 *   - The device list is verified at Test and checked again before every sync:
 *     an ADOM whose FortiGates share nothing with the verified list is refused
 *     rather than displayed. See checkDevices().
 *   - Concurrent tasks against one FortiAnalyzer are capped (withSlot), because
 *     the hourly sync walks every tenant against the box analysts are using.
 *   - The TLS certificate is pinned: on-prem appliances present self-signed
 *     certificates, so chain validation is off and a changed fingerprint is a
 *     hard failure on sync (Test re-pins, as an explicit operator action).
 *
 * ══ WHAT IS VERIFIED AND WHAT IS NOT ══
 *
 * Written against the documented 7.x JSON-RPC shapes without a live appliance.
 * The envelope, task lifecycle and log field names (srcip, dstip, action,
 * attack, severity, logid, cfgpath, ui, …) are FortiOS log fields and long
 * stable. FortiView VIEW NAMES and their row fields are the least certain part:
 * they are gathered in VIEWS below, read through pick() with aliases, and
 * probe() records which views answer and with which fields, so the pilot shows
 * any mismatch on the first Test instead of as silent zeros. A view that does
 * not answer marks its tables unavailable — never empty.
 */

const https  = require('https');
const http   = require('http');
const crypto = require('crypto');
const { URL } = require('url');

const REQ_TIMEOUT      = 30000;
const TASK_TIMEOUT_MS  = 120000;
const PAGE_SIZE        = 1000;
/** Most concurrent tasks per FortiAnalyzer host. */
const MAX_CONCURRENT_TASKS = 2;
/** Rows pulled per log type per day before a panel is reported as sampled. */
const DEFAULT_MAX_ROWS = 20000;

const ADOM_RE = /^[A-Za-z0-9_-]{1,64}$/;

/** Every FortiGate in the ADOM. */
const ALL_FORTIGATES = [{ devid: 'All_FortiGate' }];

/**
 * FortiView views used, in one place. VERIFY ON THE PILOT: probe() reports
 * which of these answer on the appliance and the row fields they return.
 */
const VIEWS = {
  sources:      'top-sources',
  destinations: 'top-destinations',
  countries:    'top-countries',
  policies:     'policy-hits',
};

/** IPS actions that stopped the attack, and ones that let it through. */
const IPS_BLOCKED = new Set(['dropped', 'blocked', 'reset', 'reset_client', 'reset_server',
  'reset_client_server', 'drop_session', 'clear_session', 'deny', 'block']);
const IPS_ALLOWED = new Set(['detected', 'pass', 'pass_session', 'monitored', 'accept']);

/** FortiOS event log ids. Normalised to 10 digits before comparison. */
const LOGID = {
  adminLoginOk:     '0100032001',
  adminLoginFailed: '0100032002',
  configChange:     new Set(['0100044544', '0100044545', '0100044546', '0100044547']),
};

// ── Config ────────────────────────────────────────────────────────────────

function normaliseConfig(config) {
  const c = config || {};
  return {
    base_url:       c.base_url,
    api_key:        c.api_key,
    adom:           c.adom,
    timeZone:       c.timeZone || 'UTC',
    tlsFingerprint: c.tlsFingerprint || null,
    maxRows:        Number.isInteger(c.maxRows) && c.maxRows > 0 ? c.maxRows : DEFAULT_MAX_ROWS,
    // Test seams. Never set from stored config: see sanitiseStoredConfig().
    transport:      typeof c.transport === 'function' ? c.transport : null,
    sleep:          typeof c.sleep === 'function' ? c.sleep : null,
    taskTimeoutMs:  Number.isInteger(c.taskTimeoutMs) ? c.taskTimeoutMs : TASK_TIMEOUT_MS,
  };
}

/** The ADOM, or an error. It becomes part of a JSON-RPC url path. */
function validAdom(adom) {
  const a = String(adom == null ? '' : adom);
  if (!ADOM_RE.test(a)) {
    throw new Error('ADOM name is missing or invalid — letters, digits, "-" and "_" only.');
  }
  return a;
}

function requireBasics(cfg) {
  if (!cfg.base_url) throw new Error('FortiAnalyzer URL is required.');
  if (!cfg.api_key)  throw new Error('API token is required.');
  return validAdom(cfg.adom);
}

// ── Transport ─────────────────────────────────────────────────────────────

function fingerprintOf(res) {
  try {
    const cert = res.socket && res.socket.getPeerCertificate && res.socket.getPeerCertificate();
    if (cert && cert.raw) return crypto.createHash('sha256').update(cert.raw).digest('hex');
  } catch (_) { /* plain http, or socket gone */ }
  return null;
}

/** One POST /jsonrpc round trip. Resolves { status, json, fingerprint }. */
function httpTransport(cfg, payloadObj) {
  return new Promise((resolve, reject) => {
    let url;
    try { url = new URL('/jsonrpc', cfg.base_url); } catch (_) {
      return reject(new Error(`Invalid FortiAnalyzer URL: ${cfg.base_url}`));
    }
    const lib = url.protocol === 'https:' ? https : http;
    const payload = Buffer.from(JSON.stringify(payloadObj), 'utf8');

    const req = lib.request({
      hostname: url.hostname,
      port:     url.port || (url.protocol === 'https:' ? 443 : 80),
      path:     url.pathname,
      method:   'POST',
      headers: {
        'Authorization':  `Bearer ${cfg.api_key}`,
        'Content-Type':   'application/json',
        'Content-Length': payload.length,
        'Accept':         'application/json',
        'User-Agent':     'SecOpsDashboard/1.0',
      },
      // Self-signed on-prem certificate; compensated by fingerprint pinning.
      rejectUnauthorized: false,
      timeout: REQ_TIMEOUT,
    }, res => {
      let raw = '';
      res.setEncoding('utf8');
      res.on('data', c => { raw += c; });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(raw); } catch (_) { /* reported below */ }
        resolve({ status: res.statusCode, json, raw: json ? null : raw.slice(0, 200), fingerprint: fingerprintOf(res) });
      });
    });
    req.on('error', err => reject(new Error(`FortiAnalyzer unreachable: ${err.message}`)));
    req.on('timeout', () => { req.destroy(); reject(new Error('FortiAnalyzer request timed out')); });
    req.write(payload);
    req.end();
  });
}

let rpcId = 1;

/**
 * One JSON-RPC call.
 *
 * `opts.raw` returns the whole result object (task calls need `percentage`
 * and `total-count` beside `data`); otherwise `data` is unwrapped.
 * `opts.pin` false skips fingerprint enforcement — Test only.
 */
async function rpc(cfg, method, url, params, opts) {
  const o = opts || {};
  const body = { id: rpcId++, jsonrpc: '2.0', method, params: [Object.assign({ url }, params || {})] };
  const send = cfg.transport || httpTransport;
  const res = await send(cfg, body);

  if (o.pin !== false && cfg.tlsFingerprint && res.fingerprint && res.fingerprint !== cfg.tlsFingerprint) {
    throw Object.assign(new Error(
      'FortiAnalyzer TLS certificate has changed since the integration was verified. ' +
      'If this was an intended renewal, re-run Test connection under Admin → Integrations.'),
    { certChanged: true });
  }
  if (res.status === 401 || res.status === 403) {
    throw Object.assign(new Error(`FortiAnalyzer rejected the API token (${res.status}).`), { notPermitted: true });
  }
  if (res.status >= 400) {
    throw new Error(`FortiAnalyzer HTTP ${res.status}${res.raw ? ': ' + res.raw : ''}`);
  }
  const json = res.json;
  if (!json || typeof json !== 'object') throw new Error('FortiAnalyzer returned an unreadable response.');
  if (json.error) {
    const msg = typeof json.error === 'object' ? (json.error.message || JSON.stringify(json.error)) : String(json.error);
    throw new Error(`FortiAnalyzer error on ${url}: ${msg}`);
  }

  let r = json.result;
  if (Array.isArray(r)) r = r[0];
  if (!r || typeof r !== 'object') throw new Error(`FortiAnalyzer returned no result for ${url}.`);

  const st = r.status;
  if (st && typeof st.code === 'number' && st.code !== 0) {
    // -11 is "no permission"; -6 / -3 are "object does not exist".
    const err = new Error(`FortiAnalyzer ${url}: ${st.message || 'error'} (${st.code})`);
    if (st.code === -11) err.notPermitted = true;
    if (st.code === -6 || st.code === -3) err.notFound = true;
    throw err;
  }
  if (o.raw) return Object.assign({}, r, { _fingerprint: res.fingerprint });
  return r.data !== undefined ? r.data : r;
}

// ── Concurrency ───────────────────────────────────────────────────────────

const gates = new Map();   // host → { active, queue }

function hostKey(cfg) {
  try { return new URL(cfg.base_url).host; } catch (_) { return String(cfg.base_url); }
}

async function withSlot(cfg, fn) {
  const key = hostKey(cfg);
  if (!gates.has(key)) gates.set(key, { active: 0, queue: [] });
  const g = gates.get(key);
  if (g.active >= MAX_CONCURRENT_TASKS) {
    await new Promise(resolve => g.queue.push(resolve));
  }
  g.active++;
  try {
    return await fn();
  } finally {
    g.active--;
    const next = g.queue.shift();
    if (next) next();
  }
}

/** Current occupancy, for tests. */
function slotStats(cfg) {
  const g = gates.get(hostKey(cfg));
  return g ? { active: g.active, queued: g.queue.length } : { active: 0, queued: 0 };
}

const defaultSleep = ms => new Promise(r => setTimeout(r, ms));

// ── Tasks ─────────────────────────────────────────────────────────────────

/**
 * Create a task, poll it to completion, let `collect` read its results, and
 * ALWAYS delete it afterwards.
 */
async function runTask(cfg, createUrl, createParams, collect, options) {
  const firstLimit = (options && options.firstLimit) || PAGE_SIZE;
  return withSlot(cfg, async () => {
    const created = await rpc(cfg, 'add', createUrl, Object.assign({ apiver: 3 }, createParams), { raw: true });
    const tid = created.tid != null ? created.tid : (created.data && created.data.tid);
    if (tid == null) throw new Error(`FortiAnalyzer did not return a task id for ${createUrl}.`);

    const taskUrl = `${createUrl}/${encodeURIComponent(String(tid))}`;
    const sleep = cfg.sleep || defaultSleep;
    const deadline = Date.now() + cfg.taskTimeoutMs;

    try {
      let wait = 500;
      let first;
      for (;;) {
        first = await rpc(cfg, 'get', taskUrl, { apiver: 3, offset: 0, limit: firstLimit }, { raw: true });
        const pct = Number(first.percentage);
        // No percentage at all means the endpoint answered synchronously.
        if (!Number.isFinite(pct) || pct >= 100) break;
        if (Date.now() > deadline) {
          throw Object.assign(new Error(`FortiAnalyzer task timed out after ${Math.round(cfg.taskTimeoutMs / 1000)}s.`),
            { timedOut: true });
        }
        await sleep(wait);
        wait = Math.min(Math.round(wait * 1.5), 3000);
      }
      return await collect(first, taskUrl);
    } finally {
      // Awaited INSIDE the slot, so the cap bounds tasks that exist on the
      // appliance, including ones still being cleaned up.
      await rpc(cfg, 'delete', taskUrl, { apiver: 3 }).catch(() => { /* already expired */ });
    }
  });
}

/** 'YYYY-MM-DD' → FortiAnalyzer time-range for the whole day (appliance time). */
function dayRange(day) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(day))) throw new Error(`Invalid day: ${day}`);
  return { start: `${day} 00:00:00`, end: `${day} 23:59:59` };
}

const num = v => {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
};

/**
 * Search one log type. Returns { total, rows, truncated }.
 * `countOnly` fetches no rows — `total` comes from total-count.
 */
async function logSearch(config, logtype, range, filter, options) {
  // Exported, so it must not rely on a caller having applied the defaults: an
  // un-normalised config has no maxRows, and the paging loop then reads nothing.
  const cfg = normaliseConfig(config);
  const o = options || {};
  const adom = validAdom(cfg.adom);
  const maxRows = o.countOnly ? 0 : (o.maxRows || cfg.maxRows);

  return runTask(cfg, `/logview/adom/${adom}/logsearch`, {
    logtype,
    device: ALL_FORTIGATES,
    filter: filter || '',
    'time-order': 'desc',
    'time-range': range,
    'case-sensitive': false,
  }, async (first, taskUrl) => {
    const total = num(first['total-count']);
    if (o.countOnly) return { total, rows: [], truncated: false };

    const rows = [];
    let page = Array.isArray(first.data) ? first.data : [];
    let offset = 0;
    while (page.length && rows.length < maxRows) {
      rows.push(...page.slice(0, maxRows - rows.length));
      offset += page.length;
      if (page.length < PAGE_SIZE || (total !== null && offset >= total)) break;
      const next = await rpc(cfg, 'get', taskUrl, { apiver: 3, offset, limit: PAGE_SIZE }, { raw: true });
      page = Array.isArray(next.data) ? next.data : [];
    }
    const known = total !== null ? total : rows.length;
    return { total: known, rows, truncated: known > rows.length };
  }, { firstLimit: o.countOnly ? 1 : Math.min(PAGE_SIZE, Math.max(1, maxRows)) });
}

/** Run a FortiView view. Returns its rows. */
async function fortiView(config, view, range, options) {
  const cfg = normaliseConfig(config);
  const o = options || {};
  const adom = validAdom(cfg.adom);
  if (!Object.values(VIEWS).includes(view)) throw new Error(`Unknown FortiView view: ${view}`);

  const params = {
    device: ALL_FORTIGATES,
    filter: o.filter || '',
    limit: o.limit || 10,
    'time-range': range,
  };
  if (o.sortBy) params['sort-by'] = [{ field: o.sortBy, order: 'desc' }];

  return runTask(cfg, `/fortiview/adom/${adom}/${view}/run`, params,
    async first => (Array.isArray(first.data) ? first.data : []));
}

// ── Shaping ───────────────────────────────────────────────────────────────

/** First present, non-empty value among field aliases. */
function pick(row, ...names) {
  if (!row) return null;
  for (const n of names) {
    const v = row[n];
    if (v !== undefined && v !== null && v !== '') return v;
  }
  return null;
}

const lower = v => String(v == null ? '' : v).trim().toLowerCase();

function normLogid(v) {
  const s = String(v == null ? '' : v).replace(/\D/g, '');
  return s ? s.padStart(10, '0') : '';
}

/** [{label,count,...}] from a Map of label → accumulator, largest first. */
function top(map, limit) {
  return [...map.values()].sort((a, b) => b.count - a.count).slice(0, limit || 10);
}

function bump(map, label, init) {
  if (label === null || label === undefined || label === '') return null;
  const k = String(label);
  if (!map.has(k)) map.set(k, Object.assign({ label: k, count: 0 }, init ? init() : {}));
  const e = map.get(k);
  e.count++;
  return e;
}

function panel(available, data, reason) {
  return { available, data: data || null, reason: reason || null, lastEventAt: null };
}
const unavailable = reason => panel(false, null, reason);

function failureReason(err) {
  return err && err.notPermitted ? 'not_permitted' : 'query_error';
}

/** A FortiView row → { label, count } with aliases, or null. */
function viewRow(row, labelFields, extra) {
  const label = pick(row, ...labelFields);
  if (label === null) return null;
  const count = num(pick(row, 'sessions', 'session', 'counts', 'count', 'hits', 'total_num', 'num'));
  return Object.assign({ label: String(label), count: count || 0 }, extra ? extra(row) : {});
}

// ── Panels ────────────────────────────────────────────────────────────────

/**
 * Traffic. Allowed/denied totals are counted by log search (total-count);
 * the top-N tables come from FortiView. A view that fails leaves its table
 * listed in `unavailable` — the tab says so rather than "no data".
 */
async function trafficPanel(cfg, range) {
  const [allowed, denied] = await Promise.all([
    logSearch(cfg, 'traffic', range, 'action!=deny', { countOnly: true }),
    logSearch(cfg, 'traffic', range, 'action==deny', { countOnly: true }),
  ]);

  const unavailableTables = [];
  const view = async (key, name, labelFields, extra) => {
    try {
      const rows = await fortiView(cfg, name, range, { limit: 10, sortBy: 'sessions' });
      return rows.map(r => viewRow(r, labelFields, extra)).filter(Boolean);
    } catch (err) {
      unavailableTables.push(key);
      return [];
    }
  };

  const [topSources, topTargets, topPolicies] = await Promise.all([
    view('topSources', VIEWS.sources, ['srcip', 'source', 'src', 'srcname'],
      r => ({ country: pick(r, 'srccountry', 'country') })),
    view('topTargets', VIEWS.destinations, ['dstip', 'destination', 'dst', 'dstname']),
    view('topPolicies', VIEWS.policies, ['policyid', 'policy_id', 'policy'],
      r => ({ name: pick(r, 'policyname', 'policy_name', 'name') })),
  ]);

  // FortiView has no documented port/service view; these stay explicitly
  // unavailable rather than empty until the pilot shows a source for them.
  unavailableTables.push('topPorts', 'topServices');

  const data = {
    allowed: allowed.total || 0,
    denied:  denied.total || 0,
    trend: [],
    topPorts: [], topServices: [],
    topPolicies, topSources, topTargets,
    unavailable: unavailableTables,
  };
  const empty = !data.allowed && !data.denied;
  return panel(true, data, empty ? 'no_data_in_range' : null);
}

/**
 * IPS, antivirus, web filter and application control, aggregated from log
 * rows. Volumes here are small enough to read, but a day that exceeds maxRows
 * is marked `sampled` with the true total, and blocked/allowed are scaled
 * from the sample and flagged `estimated` — never presented as exact.
 */
async function threatsPanel(cfg, range) {
  const [attack, virus, web, app] = await Promise.all([
    logSearch(cfg, 'attack', range, ''),
    logSearch(cfg, 'virus', range, '').catch(err => ({ error: err })),
    logSearch(cfg, 'webfilter', range, 'action==blocked').catch(err => ({ error: err })),
    logSearch(cfg, 'app-ctrl', range, 'action==block').catch(err => ({ error: err })),
  ]);

  let blocked = 0, allowed = 0;
  const attacks = new Map(), severity = new Map(), action = new Map();
  const sources = new Map(), targets = new Map();
  const uniqueSources = new Set();

  attack.rows.forEach((row) => {
    const act = lower(pick(row, 'action'));
    const isBlocked = IPS_BLOCKED.has(act);
    const isAllowed = IPS_ALLOWED.has(act);
    if (isBlocked) blocked++;
    if (isAllowed) allowed++;

    const src = pick(row, 'srcip');
    const dst = pick(row, 'dstip');
    if (src) uniqueSources.add(String(src));

    const a = bump(attacks, pick(row, 'attack', 'attackname', 'attack_name'),
      () => ({ severity: null, blocked: 0, allowed: 0, _targets: new Set() }));
    if (a) {
      a.severity = a.severity || lower(pick(row, 'severity', 'crlevel')) || null;
      if (isBlocked) a.blocked++;
      if (isAllowed) a.allowed++;
      if (dst) a._targets.add(String(dst));
    }
    bump(severity, lower(pick(row, 'severity', 'crlevel')));
    bump(action, act);
    const s = bump(sources, src, () => ({ country: null }));
    if (s) s.country = s.country || pick(row, 'srccountry');
    bump(targets, dst);
  });

  const sampled = attack.truncated;
  const scale = sampled && attack.rows.length ? attack.total / attack.rows.length : 1;

  const tally = (res, field, extraField) => {
    if (res.error) return { total: null, top: [], unavailable: true };
    const m = new Map();
    res.rows.forEach((row) => {
      const e = bump(m, pick(row, ...field), () => ({ category: null }));
      if (e && extraField) e.category = e.category || pick(row, ...extraField);
    });
    return { total: res.total, top: top(m, 10).map(e => (extraField ? e : { label: e.label, count: e.count })) };
  };

  const data = {
    total: attack.total,
    blocked: Math.round(blocked * scale),
    allowed: Math.round(allowed * scale),
    estimated: sampled,
    sampled: sampled ? { rows: attack.rows.length, total: attack.total } : null,
    uniqueSources: uniqueSources.size,
    topAttacks: top(attacks, 15).map(e => ({
      label: e.label, count: e.count, severity: e.severity,
      blocked: e.blocked, allowed: e.allowed, targets: e._targets.size,
    })),
    bySeverity: top(severity, 10),
    byAction: top(action, 10),
    topSources: top(sources, 10).map(e => ({ label: e.label, count: e.count, country: e.country })),
    topTargets: top(targets, 10).map(e => ({ label: e.label, count: e.count })),
    trend: [],
    virus:     tally(virus, ['virus', 'virusname']),
    webfilter: tally(web, ['catdesc', 'category', 'cat']),
    appctrl:   tally(app, ['app', 'appname'], ['appcat', 'category']),
  };
  return panel(true, data, attack.total ? null : 'no_data_in_range');
}

/** Source countries from FortiView. */
async function geoPanel(cfg, range) {
  const rows = await fortiView(cfg, VIEWS.countries, range, { limit: 20, sortBy: 'sessions' });
  const countries = rows.map(r => viewRow(r, ['srccountry', 'country', 'countryname'], row => ({
    sources: num(pick(row, 'srcip_count', 'sources', 'unique_src')) || 0,
    denied: num(pick(row, 'blocked', 'denied', 'deny')) || 0,
  }))).filter(Boolean);
  return panel(true, { countries, source: 'fortianalyzer' }, countries.length ? null : 'no_data_in_range');
}

/** "https(10.0.0.5)" → "https". */
function viaOf(ui) {
  const s = String(ui == null ? '' : ui);
  const m = /^([A-Za-z0-9_-]+)\s*\(/.exec(s);
  return m ? m[1].toLowerCase() : (s || null);
}

/** Is this VPN event a login/tunnel attempt, and did it fail? */
function classifyVpn(row) {
  const act = lower(pick(row, 'action'));
  const status = lower(pick(row, 'status', 'result'));
  const desc = lower(pick(row, 'logdesc', 'msg'));
  const isAttempt = /login|tunnel-up|auth|negotiate|phase ?1/.test(act + ' ' + desc);
  if (!isAttempt) return null;
  if (/fail|error|denied|reject/.test(act + ' ' + status + ' ' + desc)) return 'failure';
  if (act === 'tunnel-up' || /success|ok|up/.test(status)) return 'success';
  return null;
}

/** VPN logins and firewall administration, from event logs. */
async function vpnAdminPanel(cfg, range) {
  const [vpn, sys] = await Promise.all([
    logSearch(cfg, 'event', range, 'subtype==vpn'),
    logSearch(cfg, 'event', range, 'subtype==system'),
  ]);

  let vpnOk = 0, vpnFailed = 0;
  const failedUsers = new Map();
  vpn.rows.forEach((row) => {
    const c = classifyVpn(row);
    if (c === 'success') vpnOk++;
    if (c !== 'failure') return;
    vpnFailed++;
    const e = bump(failedUsers, pick(row, 'user', 'xauthuser', 'remip'),
      () => ({ reason: null, _src: new Set() }));
    if (e) {
      e.reason = e.reason || pick(row, 'reason', 'msg', 'logdesc');
      const rem = pick(row, 'remip', 'srcip');
      if (rem) e._src.add(String(rem));
    }
  });

  let logins = 0, failedLogins = 0, configChanges = 0;
  const admins = new Map(), byPath = new Map(), byAdmin = new Map();
  sys.rows.forEach((row) => {
    const id = normLogid(pick(row, 'logid'));
    const act = lower(pick(row, 'action'));
    const status = lower(pick(row, 'status'));
    const user = pick(row, 'user', 'admin');

    const loginOk = id === LOGID.adminLoginOk || (!id && act === 'login' && status === 'success');
    const loginFail = id === LOGID.adminLoginFailed || (!id && act === 'login' && /fail/.test(status));
    if (loginOk || loginFail) {
      logins++;
      if (loginFail) failedLogins++;
      const a = bump(admins, user, () => ({ via: null }));
      if (a) a.via = a.via || viaOf(pick(row, 'ui', 'method'));
      return;
    }

    const cfgpath = pick(row, 'cfgpath');
    if (LOGID.configChange.has(id) || (cfgpath && /^(add|edit|delete|move|set)$/.test(act))) {
      configChanges++;
      bump(byPath, cfgpath);
      bump(byAdmin, user);
    }
  });

  const data = {
    vpn: {
      total: vpnOk + vpnFailed,
      success: vpnOk,
      failed: vpnFailed,
      failedUsers: top(failedUsers, 10).map(e => ({
        label: e.label, count: e.count, reason: e.reason, sources: e._src.size,
      })),
      trend: [],
      sampled: vpn.truncated,
    },
    admin: {
      logins,
      failedLogins,
      topAdmins: top(admins, 10).map(e => ({ label: e.label, count: e.count, via: e.via })),
      configChanges,
      changesByPath: top(byPath, 15).map(e => ({ label: e.label, count: e.count })),
      changesByAdmin: top(byAdmin, 10).map(e => ({ label: e.label, count: e.count })),
      sampled: sys.truncated,
    },
  };
  const empty = !data.vpn.total && !logins && !configChanges;
  return panel(true, data, empty ? 'no_data_in_range' : null);
}

/**
 * Every NDR panel for one appliance-local day. Each panel fails on its own:
 * `_partial` names the ones that could not be answered, and those come back
 * unavailable with a reason — never as zeros.
 */
async function fetchNdrDay(config, day) {
  const cfg = normaliseConfig(config);
  requireBasics(cfg);
  const range = dayRange(day);

  const partial = [];
  const guard = (name, fn) => fn(cfg, range).catch((err) => {
    partial.push(name);
    return Object.assign(unavailable(failureReason(err)), { error: err.message });
  });

  const [traffic, threats, geo, vpnAdmin] = await Promise.all([
    guard('traffic', trafficPanel),
    guard('threats', threatsPanel),
    guard('geo', geoPanel),
    guard('vpnAdmin', vpnAdminPanel),
  ]);
  return { traffic, threats, geo, vpnAdmin, _partial: partial };
}

// ── Connection, probe, device checks ──────────────────────────────────────

/** Device rows → [{ name, sn, platform, version }]. */
function devicesOf(data) {
  const list = Array.isArray(data) ? data : [];
  return list.map(d => ({
    name: pick(d, 'name', 'hostname'),
    sn: pick(d, 'sn', 'serial'),
    platform: pick(d, 'platform_str', 'platform'),
    version: pick(d, 'os_ver', 'version'),
  })).filter(d => d.sn || d.name);
}

/**
 * Verify the URL, token and ADOM, and list the ADOM's FortiGates for the
 * operator to check by eye. Re-pins the TLS certificate.
 */
async function testConnection(config) {
  const cfg = normaliseConfig(config);
  const adom = requireBasics(cfg);

  const status = await rpc(cfg, 'get', '/sys/status', {}, { raw: true, pin: false });
  const s = status.data || {};
  const version = pick(s, 'Version', 'version') || 'unknown';

  try {
    await rpc(cfg, 'get', `/dvmdb/adom/${adom}`, {}, { pin: false });
  } catch (err) {
    if (err.notFound || err.notPermitted) {
      throw new Error(`ADOM "${adom}" was not found, or this API user is not permitted to read it.`);
    }
    throw err;
  }

  const devices = devicesOf(await rpc(cfg, 'get', `/dvmdb/adom/${adom}/device`,
    { fields: ['name', 'sn', 'platform_str', 'os_ver'] }, { pin: false }));

  const fp = status._fingerprint || null;
  const certNote = cfg.tlsFingerprint && fp && cfg.tlsFingerprint !== fp
    ? ' The TLS certificate differs from the one previously verified and has been re-pinned — confirm this was an intended renewal.'
    : '';

  return {
    ok: true,
    version: String(version),
    adom,
    devices,
    tlsFingerprint: fp,
    message: `Connected to FortiAnalyzer ${version}, ADOM "${adom}" with ${devices.length} FortiGate` +
      `${devices.length === 1 ? '' : 's'}: ${devices.map(d => d.name || d.sn).join(', ') || 'none'}.` +
      (devices.length ? '' : ' No devices is unusual — check this is the right ADOM.') + certNote,
  };
}

/**
 * Which log types and FortiView views answer on this appliance, and what row
 * fields each returns. Run after a successful Test, never on page load.
 */
async function probe(config) {
  const cfg = normaliseConfig(config);
  requireBasics(cfg);
  const now = new Date();
  const ymd = d => d.toISOString().slice(0, 10);
  const range = { start: `${ymd(new Date(now - 86400000))} 00:00:00`, end: `${ymd(now)} 23:59:59` };

  const out = { probedAt: now.toISOString(), logtypes: {}, views: {} };

  await Promise.all(['traffic', 'attack', 'event', 'virus', 'webfilter', 'app-ctrl'].map(async (lt) => {
    try {
      const r = await logSearch(cfg, lt, range, '', { maxRows: 1 });
      out.logtypes[lt] = { ok: true, total: r.total, fields: r.rows[0] ? Object.keys(r.rows[0]).slice(0, 60) : [] };
    } catch (err) {
      out.logtypes[lt] = { ok: false, error: err.message };
    }
  }));

  await Promise.all(Object.values(VIEWS).map(async (v) => {
    try {
      const rows = await fortiView(cfg, v, range, { limit: 1 });
      out.views[v] = { ok: true, rows: rows.length, fields: rows[0] ? Object.keys(rows[0]).slice(0, 60) : [] };
    } catch (err) {
      out.views[v] = { ok: false, error: err.message };
    }
  }));

  return out;
}

/**
 * Compare the ADOM's current FortiGates with the verified list.
 *
 *   no verified list      → ok (nothing to compare; Test has not been run)
 *   no overlap at all     → REFUSED: this is not the ADOM that was verified
 *   partial difference    → ok, with a warning naming what changed
 */
function compareDevices(verified, current) {
  const v = new Set((verified || []).map(d => String(d.sn || d.name)));
  const c = new Set((current || []).map(d => String(d.sn || d.name)));
  if (!v.size) return { ok: true, warning: null };
  const overlap = [...v].filter(x => c.has(x));
  const added = [...c].filter(x => !v.has(x));
  const removed = [...v].filter(x => !c.has(x));
  if (!overlap.length) {
    return { ok: false, added, removed,
      error: 'None of the FortiGates verified for this client are in the ADOM any more. ' +
        'Sync has been stopped rather than show another ADOM\'s data — re-run Test connection to review.' };
  }
  const warning = added.length || removed.length
    ? `Device list changed since verification (added: ${added.join(', ') || 'none'}; removed: ${removed.join(', ') || 'none'}).`
    : null;
  return { ok: true, added, removed, warning };
}

async function checkDevices(config, verified) {
  const cfg = normaliseConfig(config);
  const adom = requireBasics(cfg);
  const current = devicesOf(await rpc(cfg, 'get', `/dvmdb/adom/${adom}/device`,
    { fields: ['name', 'sn', 'platform_str', 'os_ver'] }));
  const result = compareDevices(verified, current);
  if (!result.ok) throw Object.assign(new Error(result.error), { deviceMismatch: true });
  return Object.assign(result, { devices: current });
}

/**
 * Strip test seams from a config read out of the database, so nothing stored
 * can ever install a transport or a sleep function.
 */
function sanitiseStoredConfig(config) {
  const c = Object.assign({}, config || {});
  delete c.transport;
  delete c.sleep;
  delete c.taskTimeoutMs;
  return c;
}

module.exports = {
  VIEWS,
  MAX_CONCURRENT_TASKS,
  DEFAULT_MAX_ROWS,
  ADOM_RE,
  validAdom,
  dayRange,
  rpc,
  runTask,
  logSearch,
  fortiView,
  fetchNdrDay,
  testConnection,
  probe,
  checkDevices,
  compareDevices,
  classifyVpn,
  normLogid,
  viaOf,
  slotStats,
  sanitiseStoredConfig,
};
