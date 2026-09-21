'use strict';

/**
 * Managed Identity, read directly from Microsoft.
 *
 * ══ WHAT COMES FROM WHERE ══
 *
 *   Microsoft Graph (the same app registration as Secure Score)
 *     auditLogs/signIns             sign-ins, failures, countries, legacy
 *                                   protocols, Conditional Access failures
 *                                                     AuditLog.Read.All (Entra ID P1)
 *     auditLogs/directoryAudits     admin changes     AuditLog.Read.All
 *     security/alerts_v2            security alerts   SecurityAlert.Read.All
 *     identityProtection/riskyUsers risky users       IdentityRiskyUser.Read.All (P2)
 *     identityProtection/riskDetections               IdentityRiskEvent.Read.All (P2)
 *
 *   Office 365 Management Activity API (manage.office.com)
 *     Audit.Exchange                mailbox rules     ActivityFeed.Read
 *     Audit.SharePoint              external sharing  ActivityFeed.Read
 *     DLP.All                       DLP matches       ActivityFeed.ReadDlp
 *
 * Graph does not carry mailbox rules, sharing or DLP; the Management Activity
 * API does not carry sign-in locations. Hence both.
 *
 * ══ THE SHAPE ══
 *
 * fetchIdentityDay() returns { o365, graph } envelopes — what the Managed
 * Identity tab, the rollups (lib/daily-metrics.js flattenO365 /
 * o365FromRollups) and the board report all consume. Alongside them rides
 * `unavailable`: a list of the parts that
 * could not be read, with a reason — not licensed, not permitted, beyond
 * retention — because a client without Entra ID P2 has no risky-user feed,
 * and that must never read as "no risky users".
 *
 * ══ TIME ══
 *
 * A "day" is the client's local calendar day (identity_time_zone), converted
 * to a UTC window for Graph's $filter.
 *
 * The Management Activity API lists audit content by when each BLOB was
 * created, which trails the events inside it by minutes to hours. So a day is
 * collected from blobs created that day AND the next, and events are kept by
 * their own CreationTime. Content is retained for seven days only: older days
 * are reported beyond_retention, not empty.
 *
 * ══ WHAT IS VERIFIED AND WHAT IS NOT ══
 *
 * Written against the documented v1.0 resources without a live tenant. Fields
 * are read defensively (get()) and aggregates null-strict; probe() records per
 * resource whether this tenant's permissions and licences allow the read, so a
 * gap shows on Test rather than as a silent zero.
 */

const msGraph = require('./ms-graph');

const MANAGE_SCOPE        = 'https://manage.office.com/.default';
const DEFAULT_MANAGE_BASE = 'https://manage.office.com/api/v1.0';
const MAA_RETENTION_DAYS  = 7;
const DAY_MS = 86400000;

const SIGNIN_PAGE      = 999;
const SIGNIN_MAX_PAGES = 50;    // ~50,000 sign-ins a day before sampling
const AUDIT_MAX_PAGES  = 20;
const CONTENT_MAX_PAGES = 20;
const MAX_BLOBS        = 400;
const SPRAY_USERS      = 5;

const CONTENT_TYPES = ['Audit.Exchange', 'Audit.SharePoint', 'DLP.All'];

const PERMISSIONS = {
  signins:        'AuditLog.Read.All',
  admin:          'AuditLog.Read.All',
  alerts:         'SecurityAlert.Read.All',
  riskyUsers:     'IdentityRiskyUser.Read.All',
  riskDetections: 'IdentityRiskEvent.Read.All',
  audit:          'ActivityFeed.Read (Office 365 Management APIs)',
  dlp:            'ActivityFeed.ReadDlp (Office 365 Management APIs)',
};

/** clientAppUsed values that are modern authentication; anything else named is legacy. */
const MODERN_CLIENTS = new Set(['browser', 'mobile apps and desktop clients']);

/**
 * Sign-in "failures" that are really interruptions — MFA or "stay signed in"
 * prompts the user then completes. Counting them as failures would make every
 * MFA-protected tenant look like it is under attack.
 */
const INTERRUPT_CODES = new Set([50074, 50076, 50079, 50125, 50140]);

/** Directory audit categories that are administration, not self-service noise. */
const ADMIN_CATEGORIES = new Set(['rolemanagement', 'usermanagement', 'groupmanagement',
  'applicationmanagement', 'policy', 'directorymanagement', 'devicemanagement']);

const MAILBOX_RULE_OPS = new Set(['new-inboxrule', 'set-inboxrule', 'enable-inboxrule', 'updateinboxrules']);
const ANON_SHARE_OPS   = new Set(['anonymouslinkcreated', 'anonymouslinkupdated', 'sharinginvitationcreated']);
const GUEST_SHARE_OPS  = new Set(['sharingset', 'addedtosecurelink', 'securelinkcreated']);

// ── Small helpers ─────────────────────────────────────────────────────────

/** Nested read: get(obj, 'status.errorCode'). undefined → null. */
function get(obj, path) {
  let cur = obj;
  for (const seg of String(path).split('.')) {
    if (cur === null || cur === undefined || typeof cur !== 'object') return null;
    cur = cur[seg];
  }
  return cur === undefined ? null : cur;
}

function str(v) {
  if (v === null || v === undefined || typeof v === 'object') return null;
  const s = String(v).trim();
  return s === '' ? null : s;
}

function num(v) {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

const lower = v => (str(v) || '').toLowerCase();

function bump(map, label, init) {
  const k = str(label);
  if (k === null) return null;
  if (!map.has(k)) map.set(k, Object.assign({ label: k, count: 0 }, init ? init() : {}));
  const e = map.get(k);
  e.count++;
  return e;
}

function top(map, limit) {
  return [...map.values()].sort((a, b) => b.count - a.count).slice(0, limit || 10);
}

const plain = list => list.map(e => ({ label: e.label, count: e.count }));

/** "1.2.3.4:5678" or "[::1]:443" → the address alone. */
function ipOnly(v) {
  const s = str(v);
  if (!s) return null;
  const v6 = /^\[([^\]]+)\](?::\d+)?$/.exec(s);
  if (v6) return v6[1];
  if (/^\d{1,3}(\.\d{1,3}){3}:\d+$/.test(s)) return s.replace(/:\d+$/, '');
  return s;
}

/** Graph $filter literal: ISO without milliseconds. */
const isoZ = ms => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');

// ── The day window ────────────────────────────────────────────────────────

function tzOffsetMs(ms, timeZone) {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  }).formatToParts(new Date(ms));
  const v = t => Number((parts.find(p => p.type === t) || {}).value);
  return Date.UTC(v('year'), v('month') - 1, v('day'), v('hour'), v('minute'), v('second')) -
    Math.floor(ms / 1000) * 1000;
}

/** Local midnight of y-m-d in timeZone, as epoch ms. Two passes settle DST edges. */
function localMidnight(y, m, d, timeZone) {
  const guess = Date.UTC(y, m - 1, d);
  let t = guess - tzOffsetMs(guess, timeZone);
  t = guess - tzOffsetMs(t, timeZone);
  return t;
}

/**
 * 'YYYY-MM-DD' in `timeZone` → { start, end } epoch ms, end exclusive.
 * An invalid zone is an error, not a silent UTC.
 */
function dayWindow(day, timeZone) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(day));
  if (!m) throw new Error(`Invalid day: ${day}`);
  const tz = timeZone || 'UTC';
  try { new Intl.DateTimeFormat('en-US', { timeZone: tz }); } catch (_) {
    throw new Error(`Invalid time zone: ${tz}`);
  }
  const y = +m[1], mo = +m[2], d = +m[3];
  return { start: localMidnight(y, mo, d, tz), end: localMidnight(y, mo, d + 1, tz) };
}

// ── HTTP ──────────────────────────────────────────────────────────────────

/** The default transport: the Graph adapter's authenticated requests. */
function defaultHttp(cfg) {
  return {
    get:  (url, opts) => msGraph.authGet(cfg, url, opts),
    post: (url, opts) => msGraph.authRequest(cfg, url, Object.assign({ method: 'POST' }, opts)),
  };
}

function graphUrl(cfg, path, params) {
  const base = msGraph.graphBase(cfg);
  const q = Object.keys(params || {})
    .map(k => `${k}=${encodeURIComponent(String(params[k]))}`).join('&');
  return base + path + (q ? '?' + q : '');
}

/** Follow @odata.nextLink up to maxPages. */
async function pages(http, url, opts, maxPages) {
  const items = [];
  let next = url;
  let count = 0;
  while (next && count < maxPages) {
    const page = await http.get(next, opts);
    count++;
    if (page && Array.isArray(page.value)) items.push(...page.value);
    next = str(page && page['@odata.nextLink']);
  }
  return { items, truncated: !!next };
}

/** Why a read failed, in the vocabulary the screens explain. */
function reasonOf(err) {
  const msg = String((err && err.message) || '');
  if (err && err.beyondRetention) return 'beyond_retention';
  if (err && err.notSubscribed) return 'not_ingesting';
  // Entra ID P1/P2 missing: Graph answers 403 with a "premium" / SKU message.
  if (/premium|\bsku\b|licen[cs]e|B2C/i.test(msg)) return 'not_licensed';
  if ((err && (err.notPermitted || err.statusCode === 403 || err.statusCode === 401))) return 'not_permitted';
  return 'query_error';
}

async function part(fn) {
  try {
    return { ok: true, value: await fn() };
  } catch (err) {
    return { ok: false, reason: reasonOf(err), error: String((err && err.message) || err).slice(0, 300) };
  }
}

// ── Graph: sign-ins ───────────────────────────────────────────────────────

function aggregateSignIns(rows) {
  let success = 0, failed = 0, interrupted = 0, legacy = 0, caFailures = 0;
  const users = new Set();
  const reasons = new Map(), failedUsers = new Map(), failedIps = new Map();
  const countries = new Map(), legacyUsers = new Map();

  (rows || []).forEach((s) => {
    const code = num(get(s, 'status.errorCode'));
    const upn = str(get(s, 'userPrincipalName')) || str(get(s, 'userId'));
    const ip = ipOnly(get(s, 'ipAddress'));

    let outcome = null;
    if (code === 0) outcome = 'success';
    else if (code !== null && INTERRUPT_CODES.has(code)) outcome = 'interrupted';
    else if (code !== null) outcome = 'failed';

    if (outcome === 'success') { success++; if (upn) users.add(upn); }
    if (outcome === 'interrupted') interrupted++;
    if (outcome === 'failed') {
      failed++;
      bump(reasons, str(get(s, 'status.failureReason')) || `Error ${code}`);
      const fu = bump(failedUsers, upn, () => ({ _ips: new Set() }));
      if (fu && ip) fu._ips.add(ip);
      const fi = bump(failedIps, ip, () => ({ _users: new Set() }));
      if (fi && upn) fi._users.add(upn);
    }

    const c = bump(countries, get(s, 'location.countryOrRegion'), () => ({ failed: 0, _users: new Set() }));
    if (c) {
      if (outcome === 'failed') c.failed++;
      if (upn) c._users.add(upn);
    }

    const client = lower(get(s, 'clientAppUsed'));
    if (client && !MODERN_CLIENTS.has(client)) {
      legacy++;
      bump(legacyUsers, upn);
    }
    if (lower(get(s, 'conditionalAccessStatus')) === 'failure') caFailures++;
  });

  return {
    signins: { success, failed, interrupted, uniqueUsers: users.size, trend: [] },
    failedLogins: {
      byReason: plain(top(reasons, 12)),
      byUser: top(failedUsers, 15).map(e => ({ label: e.label, count: e.count, distinctIps: e._ips.size })),
      byIp: top(failedIps, 15).map(e => ({
        label: e.label, count: e.count, targetedUsers: e._users.size,
        // One source against many accounts is the password-spray shape.
        spray: e._users.size > SPRAY_USERS,
      })),
    },
    graphSignins: {
      total: (rows || []).length,
      byCountry: top(countries, 25).map(e => ({ label: e.label, count: e.count, users: e._users.size, failed: e.failed })),
      legacyAuth: { total: legacy, byUser: plain(top(legacyUsers, 10)) },
      caFailures,
    },
  };
}

async function collectSignIns(cfg, http, win) {
  const url = graphUrl(cfg, '/auditLogs/signIns', {
    '$filter': `createdDateTime ge ${isoZ(win.start)} and createdDateTime lt ${isoZ(win.end)}`,
    '$top': SIGNIN_PAGE,
  });
  const r = await pages(http, url, { permission: PERMISSIONS.signins }, SIGNIN_MAX_PAGES);
  return Object.assign(aggregateSignIns(r.items), { sampled: r.truncated });
}

// ── Graph: admin changes ──────────────────────────────────────────────────

function aggregateAdmin(rows) {
  const ops = new Map(), actors = new Map();
  const admin = (rows || []).filter(a => ADMIN_CATEGORIES.has(lower(get(a, 'category'))));
  const actorOf = a => str(get(a, 'initiatedBy.user.userPrincipalName')) || str(get(a, 'initiatedBy.app.displayName'));

  admin.forEach((a) => {
    bump(ops, get(a, 'activityDisplayName'));
    bump(actors, actorOf(a));
  });

  const recent = admin.slice()
    .sort((x, y) => String(get(y, 'activityDateTime')).localeCompare(String(get(x, 'activityDateTime'))))
    .slice(0, 25)
    .map(a => ({
      when: get(a, 'activityDateTime'),
      operation: get(a, 'activityDisplayName'),
      actor: actorOf(a),
      target: str(get(a, 'targetResources.0.userPrincipalName')) || str(get(a, 'targetResources.0.displayName')),
      clientIp: ipOnly(get(a, 'initiatedBy.user.ipAddress')),
      ok: lower(get(a, 'result')) === 'success',
    }));

  return { total: admin.length, byOperation: plain(top(ops, 15)), byActor: plain(top(actors, 10)), recent };
}

async function collectAdmin(cfg, http, win) {
  const url = graphUrl(cfg, '/auditLogs/directoryAudits', {
    '$filter': `activityDateTime ge ${isoZ(win.start)} and activityDateTime lt ${isoZ(win.end)}`,
    '$top': SIGNIN_PAGE,
  });
  const r = await pages(http, url, { permission: PERMISSIONS.admin }, AUDIT_MAX_PAGES);
  return aggregateAdmin(r.items);
}

// ── Graph: alerts, risky users, risk detections ───────────────────────────

function aggregateAlerts(rows) {
  const sev = new Map(), status = new Map(), source = new Map(), technique = new Map();
  let high = 0;
  (rows || []).forEach((a) => {
    const s = lower(get(a, 'severity'));
    if (s === 'high') high++;
    bump(sev, s || null);
    bump(status, get(a, 'status'));
    bump(source, get(a, 'serviceSource'));
    (Array.isArray(a && a.mitreTechniques) ? a.mitreTechniques : []).forEach(t => bump(technique, t));
  });
  const recent = (rows || []).slice()
    .sort((x, y) => String(get(y, 'createdDateTime')).localeCompare(String(get(x, 'createdDateTime'))))
    .slice(0, 15)
    .map(a => ({
      when: get(a, 'createdDateTime'), title: get(a, 'title'), severity: get(a, 'severity'),
      status: get(a, 'status'), source: get(a, 'serviceSource'), category: get(a, 'category'),
    }));
  return {
    total: (rows || []).length, high,
    bySeverity: plain(top(sev, 10)), byStatus: plain(top(status, 10)),
    bySource: plain(top(source, 10)), byTechnique: plain(top(technique, 12)),
    trend: [], recent,
  };
}

async function collectAlerts(cfg, http, win) {
  const url = graphUrl(cfg, '/security/alerts_v2', {
    '$filter': `createdDateTime ge ${isoZ(win.start)} and createdDateTime lt ${isoZ(win.end)}`,
    '$top': 500,
  });
  const r = await pages(http, url, { permission: PERMISSIONS.alerts }, 10);
  return aggregateAlerts(r.items);
}

const RISK_RANK = { high: 3, medium: 2, low: 1 };

function mapRiskyUsers(rows) {
  const byUser = new Map();
  (rows || []).forEach((u) => {
    const label = str(get(u, 'userPrincipalName')) || str(get(u, 'userDisplayName')) || str(get(u, 'id'));
    if (!label) return;
    const prev = byUser.get(label);
    const at = str(get(u, 'riskLastUpdatedDateTime')) || '';
    if (prev && prev.updatedAt && at <= prev.updatedAt) return;
    byUser.set(label, {
      label,
      level: lower(get(u, 'riskLevel')) || null,
      state: str(get(u, 'riskState')),
      detail: str(get(u, 'riskDetail')),
      updatedAt: at || null,
    });
  });
  const users = [...byUser.values()]
    .sort((a, b) => (RISK_RANK[b.level] || 0) - (RISK_RANK[a.level] || 0));
  return { distinct: users.length, users: users.slice(0, 25) };
}

/**
 * Users whose risk changed in the window; for today, also everyone currently
 * at risk — riskyUsers is state, and a user flagged last week and still at
 * risk belongs on today's picture.
 */
async function collectRiskyUsers(cfg, http, win, isToday) {
  const opts = { permission: PERMISSIONS.riskyUsers };
  const changed = await pages(http, graphUrl(cfg, '/identityProtection/riskyUsers', {
    '$filter': `riskLastUpdatedDateTime ge ${isoZ(win.start)} and riskLastUpdatedDateTime lt ${isoZ(win.end)}`,
  }), opts, 10);
  const current = isToday
    ? await pages(http, graphUrl(cfg, '/identityProtection/riskyUsers', {
      '$filter': "riskState eq 'atRisk' or riskState eq 'confirmedCompromised'",
    }), opts, 10)
    : { items: [] };
  return mapRiskyUsers(changed.items.concat(current.items));
}

function aggregateRiskDetections(rows) {
  const type = new Map(), country = new Map();
  (rows || []).forEach((r) => {
    bump(type, get(r, 'riskEventType'));
    bump(country, get(r, 'location.countryOrRegion'));
  });
  return { byType: plain(top(type, 15)), byCountry: plain(top(country, 20)) };
}

async function collectRiskDetections(cfg, http, win) {
  const r = await pages(http, graphUrl(cfg, '/identityProtection/riskDetections', {
    '$filter': `detectedDateTime ge ${isoZ(win.start)} and detectedDateTime lt ${isoZ(win.end)}`,
  }), { permission: PERMISSIONS.riskDetections }, 10);
  return aggregateRiskDetections(r.items);
}

// ── Office 365 Management Activity API ────────────────────────────────────

function manageFeedBase(cfg) {
  const tenant = str(cfg.azure_tenant_id);
  if (!tenant) throw new Error('Microsoft 365 Directory (tenant) ID is not configured.');
  const base = String(str(cfg.manage_base_url) || DEFAULT_MANAGE_BASE).replace(/\/+$/, '');
  return `${base}/${encodeURIComponent(tenant)}/activity/feed`;
}

const manageOpts = contentType => ({
  scope: MANAGE_SCOPE,
  permission: contentType === 'DLP.All' ? PERMISSIONS.dlp : PERMISSIONS.audit,
});

/**
 * List subscriptions, and start any of ours that are not enabled.
 *
 * Starting a subscription is the one write this integration makes to a
 * client's tenant, so it happens on Test — an explicit operator action — and
 * never from the hourly sync, which only reads.
 */
async function ensureSubscriptions(cfg, http) {
  const base = manageFeedBase(cfg);
  const list = await http.get(`${base}/subscriptions/list`, manageOpts('Audit.Exchange'));
  const enabled = new Set((Array.isArray(list) ? list : [])
    .filter(s => lower(get(s, 'status')) === 'enabled')
    .map(s => str(get(s, 'contentType'))));

  const out = { enabled: [], started: [], failed: [] };
  for (const ct of CONTENT_TYPES) {
    if (enabled.has(ct)) { out.enabled.push(ct); continue; }
    try {
      await http.post(`${base}/subscriptions/start?contentType=${encodeURIComponent(ct)}`, manageOpts(ct));
      out.started.push(ct);
      out.enabled.push(ct);
    } catch (err) {
      out.failed.push({ contentType: ct, reason: reasonOf(err), error: String(err.message || err).slice(0, 200) });
    }
  }
  return out;
}

const maaTime = ms => new Date(ms).toISOString().slice(0, 19);

/** Events of one content type whose own CreationTime falls in the window. */
async function collectContent(cfg, http, contentType, win, nowMs) {
  const now = nowMs || Date.now();
  if (win.start < now - MAA_RETENTION_DAYS * DAY_MS) {
    throw Object.assign(new Error('Office 365 audit content is only retained for 7 days.'), { beyondRetention: true });
  }
  const base = manageFeedBase(cfg);
  const opts = manageOpts(contentType);

  // Blobs created during the day and the day after; each window ≤ 24h.
  const windows = [];
  for (let s = win.start; s < Math.min(win.end + DAY_MS, now) && windows.length < 2; s += DAY_MS) {
    windows.push([s, Math.min(s + DAY_MS, now)]);
  }

  const blobs = new Map();
  let truncated = false;
  for (const [s, e] of windows) {
    if (e <= s) continue;
    let url = `${base}/subscriptions/content?contentType=${encodeURIComponent(contentType)}` +
      `&startTime=${maaTime(s)}&endTime=${maaTime(e)}`;
    let count = 0;
    while (url && count < CONTENT_MAX_PAGES) {
      let page;
      try {
        page = await http.get(url, opts);
      } catch (err) {
        // AF20022: no subscription for this content type — started on Test.
        if (/AF20022|no subscription/i.test(String(err.message))) err.notSubscribed = true;
        throw err;
      }
      count++;
      (Array.isArray(page) ? page : []).forEach((b) => {
        const id = str(get(b, 'contentId')) || str(get(b, 'contentUri'));
        if (id && !blobs.has(id)) blobs.set(id, b);
      });
      const h = (page && page.__headers) || {};
      url = str(h.nextpageuri || h.NextPageUri);
    }
    if (url) truncated = true;
  }

  const list = [...blobs.values()];
  if (list.length > MAX_BLOBS) truncated = true;

  const events = [];
  for (const b of list.slice(0, MAX_BLOBS)) {
    const uri = str(get(b, 'contentUri'));
    if (!uri) continue;
    const arr = await http.get(uri, opts);
    (Array.isArray(arr) ? arr : []).forEach((ev) => {
      const raw = str(get(ev, 'CreationTime'));
      if (!raw) return;
      const t = Date.parse(/[zZ]|[+-]\d\d:?\d\d$/.test(raw) ? raw : raw + 'Z');
      if (Number.isFinite(t) && t >= win.start && t < win.end) events.push(ev);
    });
  }
  return { events, truncated };
}

function aggregateMailboxRules(events) {
  const ops = new Map(), mailboxes = new Map();
  const rules = events.filter(e => MAILBOX_RULE_OPS.has(lower(get(e, 'Operation'))));
  const mailboxOf = e => str(get(e, 'MailboxOwnerUPN')) || str(get(e, 'ObjectId')) || str(get(e, 'UserId'));
  rules.forEach((e) => { bump(ops, get(e, 'Operation')); bump(mailboxes, mailboxOf(e)); });
  return {
    total: rules.length,
    byOperation: plain(top(ops, 10)),
    byMailbox: plain(top(mailboxes, 10)),
    recent: rules.slice()
      .sort((x, y) => String(get(y, 'CreationTime')).localeCompare(String(get(x, 'CreationTime'))))
      .slice(0, 25)
      .map(e => ({
        when: get(e, 'CreationTime'), operation: get(e, 'Operation'), mailbox: mailboxOf(e),
        actor: str(get(e, 'UserId')), clientIp: ipOnly(get(e, 'ClientIP') || get(e, 'ClientIPAddress')),
      })),
  };
}

function isExternalShare(e) {
  const op = lower(get(e, 'Operation'));
  if (ANON_SHARE_OPS.has(op)) return true;
  return GUEST_SHARE_OPS.has(op) && lower(get(e, 'TargetUserOrGroupType')) === 'guest';
}

function aggregateSharing(events) {
  const ops = new Map(), sites = new Map(), users = new Map();
  const shares = events.filter(isExternalShare);
  shares.forEach((e) => {
    bump(ops, get(e, 'Operation'));
    bump(sites, get(e, 'SiteUrl'));
    bump(users, get(e, 'UserId'));
  });
  return { total: shares.length, byOperation: plain(top(ops, 10)), bySite: plain(top(sites, 10)), byUser: plain(top(users, 10)) };
}

function aggregateDlp(events) {
  const policies = new Map(), infoTypes = new Map();
  const matches = events.filter(e => lower(get(e, 'Operation')) === 'dlprulematch');
  matches.forEach((e) => {
    const details = Array.isArray(e && e.PolicyDetails) ? e.PolicyDetails : [];
    details.forEach((pd) => {
      bump(policies, get(pd, 'PolicyName'));
      (Array.isArray(pd && pd.Rules) ? pd.Rules : []).forEach((rule) => {
        const sens = get(rule, 'ConditionsMatched.SensitiveInformation');
        (Array.isArray(sens) ? sens : []).forEach(si => bump(infoTypes, get(si, 'SensitiveInformationTypeName')));
      });
    });
  });
  return { total: matches.length, byPolicy: plain(top(policies, 10)), byInfoType: plain(top(infoTypes, 10)), trend: [] };
}

// ── One day ───────────────────────────────────────────────────────────────

const EMPTY = {
  signins: () => ({ success: 0, failed: 0, interrupted: 0, uniqueUsers: 0, trend: [] }),
  failedLogins: () => ({ byReason: [], byUser: [], byIp: [] }),
  admin: () => ({ total: 0, byOperation: [], byActor: [], recent: [] }),
  mailboxRules: () => ({ total: 0, byOperation: [], byMailbox: [], recent: [] }),
  sharing: () => ({ total: 0, byOperation: [], bySite: [], byUser: [] }),
  dlp: () => ({ total: 0, byPolicy: [], byInfoType: [], trend: [] }),
  alerts: () => ({ total: 0, high: 0, bySeverity: [], byStatus: [], bySource: [], byTechnique: [], trend: [], recent: [] }),
  riskyUsers: () => ({ distinct: 0, users: [] }),
  riskDetections: () => ({ byType: [], byCountry: [] }),
  graphSignins: () => ({ total: 0, byCountry: [], legacyAuth: { total: 0, byUser: [] }, caFailures: 0 }),
};

function envelope(anyOk, data, firstFailure, empty) {
  if (!anyOk) return { available: false, data: null, reason: firstFailure || 'query_error', lastEventAt: null };
  return { available: true, data, reason: empty ? 'no_data_in_range' : null, lastEventAt: null };
}

/**
 * Every Managed Identity panel for one client-local day.
 *
 * @param {object} config  the ms_graph integration config plus api_key
 * @param {string} day     'YYYY-MM-DD'
 * @param {object} [opts]  { timeZone, now, isToday, http }
 */
async function fetchIdentityDay(config, day, opts) {
  const o = opts || {};
  const cfg = config || {};
  const win = dayWindow(day, o.timeZone || cfg.identity_time_zone || 'UTC');
  const http = o.http || defaultHttp(cfg);
  const now = o.now || Date.now();

  const [signins, admin, alerts, risky, detections, exchange, sharepoint, dlp] = await Promise.all([
    part(() => collectSignIns(cfg, http, win)),
    part(() => collectAdmin(cfg, http, win)),
    part(() => collectAlerts(cfg, http, win)),
    part(() => collectRiskyUsers(cfg, http, win, !!o.isToday)),
    part(() => collectRiskDetections(cfg, http, win)),
    part(() => collectContent(cfg, http, 'Audit.Exchange', win, now)),
    part(() => collectContent(cfg, http, 'Audit.SharePoint', win, now)),
    part(() => collectContent(cfg, http, 'DLP.All', win, now)),
  ]);

  const errors = {};
  const note = (name, p) => { if (!p.ok) errors[name] = { reason: p.reason, error: p.error }; };
  [['signins', signins], ['admin', admin], ['alerts', alerts], ['riskyUsers', risky],
   ['riskDetections', detections], ['mailboxRules', exchange], ['sharing', sharepoint], ['dlp', dlp]]
    .forEach(([n, p]) => note(n, p));

  // ── Office 365 half ──
  const unavailableO = [];
  const miss = (list, p, keys) => { if (!p.ok) keys.forEach(key => list.push({ key, reason: p.reason })); };
  miss(unavailableO, signins, ['signins', 'failedLogins']);
  miss(unavailableO, admin, ['admin']);
  miss(unavailableO, exchange, ['mailboxRules']);
  miss(unavailableO, sharepoint, ['sharing']);
  miss(unavailableO, dlp, ['dlp']);

  const auditParts = [exchange, sharepoint, dlp].filter(p => p.ok);
  const workloads = new Map();
  auditParts.forEach(p => p.value.events.forEach(e => bump(workloads, get(e, 'Workload'))));
  if (!auditParts.length) unavailableO.push({ key: 'byWorkload', reason: exchange.reason });

  const o365Data = {
    signins:      signins.ok ? signins.value.signins : EMPTY.signins(),
    failedLogins: signins.ok ? signins.value.failedLogins : EMPTY.failedLogins(),
    admin:        admin.ok ? admin.value : EMPTY.admin(),
    mailboxRules: exchange.ok ? aggregateMailboxRules(exchange.value.events) : EMPTY.mailboxRules(),
    sharing:      sharepoint.ok ? aggregateSharing(sharepoint.value.events) : EMPTY.sharing(),
    dlp:          dlp.ok ? aggregateDlp(dlp.value.events) : EMPTY.dlp(),
    byWorkload:   plain(top(workloads, 10)),
    unavailable:  unavailableO,
    sampled: !!((signins.ok && signins.value.sampled) || auditParts.some(p => p.value.truncated)),
  };
  const o365Ok = [signins, admin, exchange, sharepoint, dlp].some(p => p.ok);
  const o365Empty = !o365Data.signins.success && !o365Data.signins.failed && !o365Data.admin.total &&
    !o365Data.mailboxRules.total && !o365Data.sharing.total && !o365Data.dlp.total;

  // ── Graph half ──
  const unavailableG = [];
  miss(unavailableG, signins, ['signins']);
  miss(unavailableG, alerts, ['alerts']);
  miss(unavailableG, risky, ['riskyUsers']);
  miss(unavailableG, detections, ['riskDetections']);

  const graphData = {
    alerts:         alerts.ok ? alerts.value : EMPTY.alerts(),
    riskyUsers:     risky.ok ? risky.value : EMPTY.riskyUsers(),
    riskDetections: detections.ok ? detections.value : EMPTY.riskDetections(),
    signins:        signins.ok ? signins.value.graphSignins : EMPTY.graphSignins(),
    unavailable:    unavailableG,
  };
  const graphOk = [signins, alerts, risky, detections].some(p => p.ok);
  const graphEmpty = !graphData.alerts.total && !graphData.riskyUsers.distinct && !graphData.signins.total &&
    !graphData.riskDetections.byType.length;

  const firstReason = list => (list.find(p => !p.ok) || {}).reason;

  return {
    o365:  envelope(o365Ok, o365Data, firstReason([signins, admin, exchange, sharepoint, dlp]), o365Empty),
    graph: envelope(graphOk, graphData, firstReason([signins, alerts, risky, detections]), graphEmpty),
    _partial: Object.keys(errors),
    errors,
  };
}

// ── Test connection ───────────────────────────────────────────────────────

const PROBES = [
  ['signins',        '/auditLogs/signIns'],
  ['admin',          '/auditLogs/directoryAudits'],
  ['alerts',         '/security/alerts_v2'],
  ['riskyUsers',     '/identityProtection/riskyUsers'],
  ['riskDetections', '/identityProtection/riskDetections'],
];

/**
 * Which Identity resources this tenant's permissions and licences allow, and
 * the Office 365 audit subscriptions (started here if missing).
 */
async function probe(config, opts) {
  const cfg = config || {};
  const http = (opts && opts.http) || defaultHttp(cfg);
  const out = { probedAt: new Date().toISOString(), graph: {}, audit: null, anyOk: false };

  await Promise.all(PROBES.map(async ([key, path]) => {
    const p = await part(() => http.get(graphUrl(cfg, path, { '$top': 1 }), { permission: PERMISSIONS[key] }));
    out.graph[key] = p.ok ? { ok: true } : { ok: false, reason: p.reason, error: p.error, permission: PERMISSIONS[key] };
  }));

  const subs = await part(() => ensureSubscriptions(cfg, http));
  out.audit = subs.ok ? subs.value : { enabled: [], started: [], failed: [{ contentType: 'all', reason: subs.reason, error: subs.error }] };

  out.anyOk = Object.values(out.graph).some(g => g.ok) || out.audit.enabled.length > 0;
  return out;
}

const PROBE_LABEL = {
  signins: 'sign-ins', admin: 'admin changes', alerts: 'alerts',
  riskyUsers: 'risky users', riskDetections: 'risk detections',
};

/** One sentence for the Test result. */
function describeProbe(p) {
  if (!p) return '';
  const graph = PROBES.map(([k]) => {
    const g = p.graph[k] || {};
    if (g.ok) return `${PROBE_LABEL[k]} ✓`;
    const why = g.reason === 'not_licensed' ? 'needs Entra ID P1/P2' : `needs ${g.permission}`;
    return `${PROBE_LABEL[k]} ✗ (${why})`;
  }).join(', ');
  const a = p.audit || { enabled: [], started: [], failed: [] };
  const audit = (a.enabled.length ? `audit subscriptions enabled: ${a.enabled.join(', ')}` : 'no audit subscriptions') +
    (a.started.length ? ` (started now: ${a.started.join(', ')} — content can take up to 12 hours to appear)` : '') +
    (a.failed.length ? `; failed: ${a.failed.map(f => f.contentType).join(', ')}` : '');
  return `Managed Identity — ${graph}; ${audit}.`;
}

module.exports = {
  PERMISSIONS,
  CONTENT_TYPES,
  MAA_RETENTION_DAYS,
  MANAGE_SCOPE,
  INTERRUPT_CODES,
  dayWindow,
  reasonOf,
  ipOnly,
  aggregateSignIns,
  aggregateAdmin,
  aggregateAlerts,
  mapRiskyUsers,
  aggregateRiskDetections,
  aggregateMailboxRules,
  aggregateSharing,
  aggregateDlp,
  ensureSubscriptions,
  collectContent,
  fetchIdentityDay,
  probe,
  describeProbe,
};
