'use strict';

/**
 * DNSFilter adapter — AI Visibility telemetry.
 *
 * ══ WHAT THIS READS ══
 *
 * Every DNS lookup a client's networks and roaming agents make passes through
 * DNSFilter, which classifies it, and DNSFilter has a "Generative AI" content
 * category. So, per client-local day, this collects:
 *
 *   usage    AI lookups allowed and blocked, plus all lookups as the denominator
 *   apps     which AI tools those lookups were for (domains → applications)
 *   users    who made them (staff-only; never reaches the portal or a report)
 *   policy   whether the client's DNSFilter policies block the AI category
 *
 * ══ ONE MSP KEY, EVERY CLIENT ══
 *
 * The API key is Reflex's MSP key and sees every client organisation. So the
 * organisation id is the whole of the separation between clients:
 *
 *   - it comes from the client's integration row ONLY, never from a request;
 *   - it is validated as digits before it reaches a query string;
 *   - Test confirms the key can actually see that organisation, and records it;
 *     the sync refuses an organisation Test has not verified;
 *   - every traffic report is sent with organization_ids set — a report call
 *     without it would default to the key's own (MSP-wide) scope.
 *
 * ══ READ-ONLY ══
 *
 * The transport issues GET and nothing else. The MSP key can change policies
 * for every client; this code must never be the thing that does.
 *
 * ══ WHAT IS VERIFIED AND WHAT IS NOT ══
 *
 * Paths and parameters follow DNSFilter's published OpenAPI description
 * (api.dnsfilter.com /v1). The response SCHEMAS of the traffic reports are not
 * published in a form we could check, so rows are read through pick() with
 * aliases and located by shape (collectRows), and probe() records the field
 * names each report actually returns. A report whose shape is not recognised is
 * UNAVAILABLE with a reason — never a zero. The pilot's Test result is where a
 * mismatch shows up.
 */

const https = require('https');
const { URL } = require('url');
const { dayWindow } = require('./ms-identity');

const DEFAULT_BASE = 'https://api.dnsfilter.com';
const REQ_TIMEOUT = 30000;
const PAGE_SIZE = 100;
const MAX_PAGES = 50;
const MAX_RETRIES_429 = 2;
const MAX_RETRY_AFTER_S = 30;
/*
 * A 5xx or a dropped connection is retried too. The hourly collection makes
 * roughly eight calls per client per day against an API every client shares,
 * so a single transient failure would otherwise lose a whole day's panel —
 * which is exactly what happened on the first pilot run.
 */
const MAX_TRANSIENT_RETRIES = 2;
const TRANSIENT_BACKOFF_MS = [1000, 3000];
/** Users kept per day. More than enough to find who drives AI use. */
const MAX_USERS = 50;
/** Domain rows read per day before the apps panel is reported as sampled. */
const MAX_DOMAIN_ROWS = 1000;
const CATALOGUE_TTL_MS = 24 * 60 * 60 * 1000;

/*
 * How the AI category is handed to the domain reports.
 *
 * DNSFilter's description says the domains reports take `category_ids`, and the
 * first pilot showed otherwise: with it they answer 400 "Invalid query
 * definition", without it they answer fine. Rather than guess which spelling is
 * right, the adapter tries each in turn on a 400 and remembers what worked.
 *
 * `null` is the last resort: ask WITHOUT a category filter and keep only the
 * rows that are recognisably AI. That can only narrow the result — it must
 * never let a non-AI domain be reported as AI use.
 */
const CATEGORY_PARAM_VARIANTS = ['category_ids', 'categories', 'category_ids[]', 'category_id', null];

const ORG_ID_RE = /^\d{1,12}$/;
const AI_CATEGORY_RE = /^generative\s*ai$/i;
const AI_CATEGORY_LOOSE_RE = /generative\s*ai|artificial\s*intelligence/i;

/*
 * Second-level public suffixes common in our client base. Not the full public
 * suffix list — a miss only means a domain groups one label too coarsely
 * ("example.co.za" as "co.za"), which this list exists to prevent for the
 * suffixes we actually see.
 */
const TWO_LEVEL_SUFFIXES = new Set([
  'co.za', 'org.za', 'gov.za', 'ac.za', 'net.za',
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk',
  'com.au', 'net.au', 'org.au',
  'co.nz', 'com.br', 'co.jp', 'co.in', 'com.cn', 'com.sg',
]);

// ── Config ────────────────────────────────────────────────────────────────

function normaliseConfig(config) {
  const c = config || {};
  return {
    base_url:     c.base_url || DEFAULT_BASE,
    api_key:      c.api_key,
    organization_id: c.organization_id == null ? null : String(c.organization_id),
    aiCategoryId: c.aiCategoryId == null ? null : String(c.aiCategoryId),
    // Which category-filter spelling this DNSFilter accepts, learned by Test.
    categoryParam: c.categoryParam === null || CATEGORY_PARAM_VARIANTS.indexOf(c.categoryParam) >= 0 ? c.categoryParam : undefined,
    timeZone:     c.timeZone || 'UTC',
    // Test seams. Never set from stored config: see sanitiseStoredConfig().
    transport:    typeof c.transport === 'function' ? c.transport : null,
    sleep:        typeof c.sleep === 'function' ? c.sleep : null,
  };
}

/** The organisation id, or an error. It becomes part of a query string. */
function validOrgId(id) {
  const s = String(id == null ? '' : id).trim();
  if (!ORG_ID_RE.test(s)) {
    throw new Error('DNSFilter organisation id is missing or invalid — digits only.');
  }
  return s;
}

function requireKey(cfg) {
  if (!cfg.api_key) throw new Error('The DNSFilter MSP API key is not configured.');
}

// ── Transport ─────────────────────────────────────────────────────────────

/** One GET. Resolves { status, json, headers }. There is no other method. */
function httpTransport(cfg, url, headers) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(url); } catch (_) { return reject(new Error(`Invalid DNSFilter URL: ${url}`)); }
    if (u.protocol !== 'https:') return reject(new Error('DNSFilter must be reached over https.'));

    const req = https.request({
      hostname: u.hostname,
      port:     u.port || 443,
      path:     u.pathname + u.search,
      method:   'GET',
      headers:  Object.assign({ Accept: 'application/json', 'User-Agent': 'SecOpsDashboard/1.0' }, headers),
      timeout:  REQ_TIMEOUT,
    }, (res) => {
      let raw = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { raw += c; });
      res.on('end', () => {
        let json = null;
        try { json = raw ? JSON.parse(raw) : null; } catch (_) { /* reported by the caller */ }
        resolve({ status: res.statusCode, json, headers: res.headers || {} });
      });
    });
    req.on('error', err => reject(new Error(`DNSFilter unreachable: ${err.message}`)));
    req.on('timeout', () => { req.destroy(); reject(new Error('DNSFilter request timed out')); });
    req.end();
  });
}

function buildUrl(cfg, path, params) {
  const u = new URL(path, cfg.base_url);
  Object.keys(params || {}).forEach((k) => {
    const v = params[k];
    if (v === undefined || v === null || v === '') return;
    u.searchParams.set(k, Array.isArray(v) ? v.join(',') : String(v));
  });
  return u.toString();
}

const sleepFor = cfg => cfg.sleep || (ms => new Promise(r => setTimeout(r, ms)));

/**
 * One API call, with the recoveries DNSFilter needs:
 *
 *   401   DNSFilter documents the key as the raw Authorization value. Some
 *         accounts expect "Bearer <key>"; one retry in that form, and the form
 *         that worked is remembered on the config for the rest of the run.
 *   429   honour Retry-After (capped), at most MAX_RETRIES_429 times.
 *   5xx   retried with a short backoff, and so is a dropped connection.
 *
 * Every error it gives up on carries the status and the API's own message, so
 * the panel that could not be read can say WHY rather than "query error".
 */
async function request(cfg, path, params) {
  requireKey(cfg);
  const url = buildUrl(cfg, path, params);
  const send = cfg.transport || httpTransport;
  let rateRetries = 0;
  let transientRetries = 0;
  let triedBearer = cfg._authScheme === 'bearer';

  for (;;) {
    const auth = cfg._authScheme === 'bearer' ? `Bearer ${cfg.api_key}` : cfg.api_key;

    let res;
    try {
      res = await send(cfg, url, { Authorization: auth });
    } catch (err) {
      if (transientRetries < MAX_TRANSIENT_RETRIES) {
        await sleepFor(cfg)(TRANSIENT_BACKOFF_MS[transientRetries++]);
        continue;
      }
      throw Object.assign(err, { unreachable: true });
    }

    if (res.status === 401 && !triedBearer) {
      triedBearer = true;
      cfg._authScheme = 'bearer';
      continue;
    }
    if (res.status === 429 && rateRetries < MAX_RETRIES_429) {
      rateRetries++;
      const ra = parseInt((res.headers || {})['retry-after'], 10);
      const secs = Number.isFinite(ra) && ra >= 0 ? Math.min(ra, MAX_RETRY_AFTER_S) : 5;
      await sleepFor(cfg)(secs * 1000);
      continue;
    }
    if (res.status >= 500 && transientRetries < MAX_TRANSIENT_RETRIES) {
      await sleepFor(cfg)(TRANSIENT_BACKOFF_MS[transientRetries++]);
      continue;
    }

    const apiMsg = res.json && (res.json.error || res.json.message);
    const where = `${path} (HTTP ${res.status})`;
    if (res.status === 401) {
      throw Object.assign(new Error('DNSFilter rejected the API key (401).'), { notPermitted: true, status: 401 });
    }
    if (res.status === 403) {
      throw Object.assign(new Error(`DNSFilter refused ${where}${apiMsg ? ': ' + apiMsg : ''}.`), { notPermitted: true, status: 403 });
    }
    if (res.status === 404) {
      throw Object.assign(new Error(`DNSFilter has no ${where}.`), { notFound: true, status: 404 });
    }
    if (res.status === 429) {
      throw Object.assign(new Error(`DNSFilter rate limit reached on ${path} — it was retried ${rateRetries} time(s) and still refused.`),
        { rateLimited: true, status: 429 });
    }
    if (res.status >= 500) {
      throw Object.assign(new Error(`DNSFilter failed on ${where}${apiMsg ? ': ' + apiMsg : ''} — retried ${transientRetries} time(s).`),
        { serverError: true, status: res.status });
    }
    if (res.status >= 400) {
      throw Object.assign(new Error(`DNSFilter rejected ${where}${apiMsg ? ': ' + apiMsg : ''}`), { status: res.status });
    }
    if (!res.json || typeof res.json !== 'object') {
      throw Object.assign(new Error(`DNSFilter returned an unreadable response for ${where}.`), { status: res.status });
    }
    return res.json;
  }
}

/** Every item of a paged JSON:API list. Stops on a short page or MAX_PAGES. */
async function getAllPages(cfg, path, params) {
  const out = [];
  for (let n = 1; n <= MAX_PAGES; n++) {
    const json = await request(cfg, path, Object.assign({}, params, { 'page[number]': n, 'page[size]': PAGE_SIZE }));
    const data = Array.isArray(json.data) ? json.data : [];
    out.push(...data);
    const next = json.links && Object.prototype.hasOwnProperty.call(json.links, 'next') ? json.links.next : undefined;
    if (data.length < PAGE_SIZE || next === null) break;
  }
  return out;
}

// ── Reading rows whose schema is not published ────────────────────────────

/** A JSON:API resource flattened: attributes over the top-level fields. */
function flat(r) {
  if (!r || typeof r !== 'object') return {};
  return Object.assign({}, r, r.attributes || {});
}

/** First defined value among dotted-path aliases. */
function pick(obj, ...keys) {
  for (const k of keys) {
    let v = obj;
    for (const part of k.split('.')) {
      if (v == null || typeof v !== 'object') { v = undefined; break; }
      v = v[part];
    }
    if (v !== undefined && v !== null && v !== '') return v;
  }
  return undefined;
}

const COUNT_KEYS = ['total', 'requests', 'total_requests', 'count', 'queries', 'value', 'hits'];

function countOf(row) {
  const v = pick(flat(row), ...COUNT_KEYS);
  const n = Number(v);
  return v === undefined || !Number.isFinite(n) ? null : n;
}

/**
 * Every object below `node` that satisfies `isRow`, searched depth-first.
 * Reports arrive either flat or split into time buckets; collecting rows
 * wherever they sit, then summing, reads both shapes the same way.
 * Returns null when the response holds no recognisable rows AND is not simply
 * empty — "could not read" and "nothing happened" are different findings.
 */
function collectRows(node, isRow) {
  const rows = [];
  let sawArray = false;
  (function walk(n, depth) {
    if (depth > 6 || n == null || typeof n !== 'object') return;
    if (Array.isArray(n)) {
      sawArray = true;
      n.forEach(x => walk(x, depth + 1));
      return;
    }
    if (isRow(n)) { rows.push(flat(n)); return; }
    Object.keys(n).forEach(k => walk(n[k], depth + 1));
  })(node, 0);
  if (rows.length) return rows;
  return isEmptyReport(node) || sawArray ? [] : null;
}

function isEmptyReport(node) {
  if (node == null) return true;
  if (Array.isArray(node)) return node.length === 0;
  if (typeof node !== 'object') return false;
  const keys = Object.keys(node);
  return keys.length === 0 || keys.every(k => isEmptyReport(node[k]));
}

/** Field names of the first row a report returned — what probe() records. */
function shapeOf(json) {
  let first = null;
  (function walk(n, depth) {
    if (first || depth > 6 || n == null || typeof n !== 'object') return;
    if (Array.isArray(n)) { if (n.length && typeof n[0] === 'object') first = flat(n[0]); else n.forEach(x => walk(x, depth + 1)); return; }
    Object.keys(n).forEach(k => walk(n[k], depth + 1));
  })(json && json.data !== undefined ? json.data : json, 0);
  return first ? Object.keys(first).sort() : [];
}

// ── Domains and applications ──────────────────────────────────────────────

function hostOf(value) {
  const s = String(value || '').trim().toLowerCase();
  if (!s) return '';
  try {
    return new URL(/^[a-z]+:\/\//.test(s) ? s : `https://${s}`).hostname.replace(/\.$/, '');
  } catch (_) {
    return '';
  }
}

/** "chat.openai.com" → "openai.com"; "x.example.co.za" → "example.co.za". */
function registeredDomain(host) {
  const h = hostOf(host);
  if (!h || /^\d+\.\d+\.\d+\.\d+$/.test(h)) return h;
  const parts = h.split('.');
  if (parts.length <= 2) return h;
  const lastTwo = parts.slice(-2).join('.');
  return TWO_LEVEL_SUFFIXES.has(lastTwo) ? parts.slice(-3).join('.') : lastTwo;
}

function slug(s) {
  return String(s || '').toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 120);
}

const catalogueCache = new Map(); // base_url → { at, value }

/**
 * DNSFilter's AI application catalogue: { byDomain: Map(regDomain → app), apps }.
 * The catalogue is global (not per organisation), so it is cached per API host.
 * A catalogue that cannot be read leaves every domain unmapped — shown under
 * its own domain name, never dropped.
 */
async function aiCatalogue(cfg, now) {
  const key = cfg.base_url;
  const hit = catalogueCache.get(key);
  const t = now || Date.now();
  if (hit && t - hit.at < CATALOGUE_TTL_MS) return hit.value;

  const cats = (await getAllPages(cfg, '/v1/application_categories', {})).map(flat);
  const aiCats = cats.filter(c => AI_CATEGORY_LOOSE_RE.test(String(c.name || '')) || /^ai\b/i.test(String(c.name || '')));
  const apps = [];
  const byDomain = new Map();
  if (aiCats.length) {
    const list = await getAllPages(cfg, '/v1/applications/all', { category_ids: aiCats.map(c => c.id) });
    list.map(flat).forEach((a) => {
      const name = a.display_name || a.name;
      if (!name) return;
      const app = { key: `app:${slug(a.id || name)}`, name: String(name), domain: registeredDomain(a.home_page_url) };
      apps.push(app);
      if (app.domain && !byDomain.has(app.domain)) byDomain.set(app.domain, app);
    });
  }
  const value = { apps, byDomain, categories: aiCats.map(c => ({ id: String(c.id), name: c.name })) };
  catalogueCache.set(key, { at: t, value });
  return value;
}

/** The application a looked-up domain belongs to, or the domain itself. */
function appFor(domain, catalogue) {
  const reg = registeredDomain(domain);
  const app = reg && catalogue && catalogue.byDomain.get(reg);
  if (app) return { key: app.key, name: app.name, mapped: true };
  return { key: `domain:${slug(reg || domain) || 'unknown'}`, name: reg || String(domain || 'unknown'), mapped: false };
}

// ── The AI category ───────────────────────────────────────────────────────

/**
 * The content category called Generative AI, found by NAME. Ids are
 * DNSFilter's to renumber; a hard-coded one would silently start counting a
 * different category.
 */
async function resolveAiCategory(cfg) {
  const cats = (await getAllPages(cfg, '/v1/categories/all', {})).map(flat);
  const exact = cats.find(c => AI_CATEGORY_RE.test(String(c.name || '').trim()));
  const loose = exact || cats.find(c => AI_CATEGORY_LOOSE_RE.test(String(c.name || '')));
  return loose ? { id: String(loose.id), name: String(loose.name) } : null;
}

// ── Panels ────────────────────────────────────────────────────────────────

function panel(available, data, reason, detail) {
  return { available, data: data || null, reason: reason || null, detail: detail || null, lastEventAt: null };
}
const unavailable = (reason, detail) => panel(false, null, reason, detail);

function reasonOf(err) {
  if (err && err.noCategoryFilter) return 'category_filter_unsupported';
  if (err && err.notPermitted) return 'not_permitted';
  if (err && err.notFound) return 'not_available';
  if (err && err.rateLimited) return 'rate_limited';
  if (err && err.serverError) return 'source_error';
  if (err && err.unreachable) return 'unreachable';
  return 'query_error';
}

/** The underlying failure, kept so a panel can say what went wrong. */
function detailOf(err) {
  return err && err.message ? String(err.message).slice(0, 300) : null;
}

function windowParams(cfg, day) {
  const w = dayWindow(day, cfg.timeZone);
  return {
    from: new Date(w.start).toISOString(),
    to:   new Date(w.end).toISOString(),
    organization_ids: validOrgId(cfg.organization_id),
  };
}

const isCategoryRow = r => {
  const f = flat(r);
  return pick(f, 'category_id', 'category.id', 'id') !== undefined &&
    pick(f, 'category_name', 'category.name', 'name') !== undefined && countOf(r) !== null;
};

function isAiCategoryRow(row, aiId) {
  const id = pick(row, 'category_id', 'category.id', 'id');
  if (id !== undefined && String(id) === aiId) return true;
  return AI_CATEGORY_RE.test(String(pick(row, 'category_name', 'category.name', 'name') || '').trim());
}

/** AI lookups of one type ('allowed' | 'blocked') for the day. */
async function aiCategoryCount(cfg, day, type) {
  const json = await request(cfg, '/v1/traffic_reports/total_categories',
    Object.assign(windowParams(cfg, day), { type, bucket_size: '1day' }));
  const rows = collectRows(json.data !== undefined ? json.data : json, isCategoryRow);
  if (rows === null) throw Object.assign(new Error('unrecognised total_categories response'), { shape: true });
  // A report that lists categories but not this one had no AI traffic of this type.
  return rows.filter(r => isAiCategoryRow(r, cfg.aiCategoryId)).reduce((s, r) => s + countOf(r), 0);
}

/** Every lookup of the day, as the denominator for "AI share". */
async function totalRequests(cfg, day) {
  const json = await request(cfg, '/v1/traffic_reports/total_requests',
    Object.assign(windowParams(cfg, day), { type: 'all', bucket_size: '1day' }));
  const d = json.data !== undefined ? json.data : json;
  const direct = d && !Array.isArray(d) && typeof d === 'object' ? countOf(d) : null;
  if (direct !== null) return direct;
  const rows = collectRows(d, r => countOf(r) !== null);
  if (rows === null) throw Object.assign(new Error('unrecognised total_requests response'), { shape: true });
  return rows.reduce((s, r) => s + countOf(r), 0);
}

const domainOf = r => pick(r, 'domain', 'fqdn', 'domain_name', 'host', 'name');

const categoryOf = r => pick(r, 'category_id', 'category.id', 'category_ids', 'category_name', 'category.name', 'category');

function hostOfCfg(cfg) {
  try { return new URL(cfg.base_url).host; } catch (_) { return String(cfg.base_url); }
}

/** Remembered per DNSFilter host: the spelling its reports actually accept. */
const categoryParamCache = new Map();

function withCategory(params, variant, aiCategoryId) {
  if (variant === null || variant === undefined) return Object.assign({}, params);
  return Object.assign({}, params, { [variant]: aiCategoryId });
}

/**
 * A report that needs to be limited to the AI category, asked in whichever
 * form this DNSFilter accepts. Only a 400 — a rejected QUERY — makes it try
 * another form; a 403 or a 500 is about this request, not its shape.
 *
 * @returns {{ json, variant }} variant null meaning "no filter was applied",
 *          which obliges the caller to narrow the rows itself.
 */
async function reportByCategory(cfg, path, params) {
  const host = hostOfCfg(cfg);
  const known = cfg.categoryParam !== undefined ? cfg.categoryParam
    : (categoryParamCache.has(host) ? categoryParamCache.get(host) : undefined);
  const order = known === undefined ? CATEGORY_PARAM_VARIANTS
    : [known].concat(CATEGORY_PARAM_VARIANTS.filter(v => v !== known));

  let lastErr = null;
  for (const variant of order) {
    try {
      const json = await request(cfg, path, withCategory(params, variant, cfg.aiCategoryId));
      categoryParamCache.set(host, variant);
      return { json, variant };
    } catch (err) {
      if (err.status !== 400) throw err;
      lastErr = err;
    }
  }
  throw lastErr;
}

/**
 * Keep only the rows that are recognisably AI, when DNSFilter could not be
 * asked to do it. By the row's own category if it carries one; otherwise by the
 * AI application catalogue, which misses AI domains the catalogue does not list
 * — reported as `filter: 'catalogue'` so the screen can say so.
 * Returns null when neither is possible: under-reporting is recoverable,
 * calling every domain an AI tool is not.
 */
function narrowToAi(rows, cfg, catalogue) {
  if (rows.length && rows.every(r => categoryOf(r) !== undefined)) {
    const matches = r => String(categoryOf(r)).split(',').map(s => s.trim())
      .some(v => v === cfg.aiCategoryId || AI_CATEGORY_RE.test(v));
    return { rows: rows.filter(matches), filter: 'row_category' };
  }
  if (catalogue && catalogue.byDomain.size) {
    return { rows: rows.filter(r => catalogue.byDomain.has(registeredDomain(domainOf(r)))), filter: 'catalogue' };
  }
  return null;
}

async function aiDomains(cfg, day, type, catalogue) {
  const { json, variant } = await reportByCategory(cfg, '/v1/traffic_reports/total_domains',
    Object.assign(windowParams(cfg, day), { type }));
  const rows = collectRows(json.data !== undefined ? json.data : json,
    r => domainOf(flat(r)) !== undefined && countOf(r) !== null);
  if (rows === null) throw Object.assign(new Error('unrecognised total_domains response'), { shape: true });
  if (variant !== null) return { rows, filter: null };

  const narrowed = narrowToAi(rows, cfg, catalogue);
  if (!narrowed) {
    throw Object.assign(new Error(
      'DNSFilter would not filter this report by category, and the rows carry no category to filter on.'),
    { noCategoryFilter: true });
  }
  return narrowed;
}

async function collectApps(cfg, day, now) {
  let catalogue = null;
  try { catalogue = await aiCatalogue(cfg, now); } catch (_) { /* domains stay unmapped */ }

  const a = await aiDomains(cfg, day, 'allowed', catalogue);
  const b = await aiDomains(cfg, day, 'blocked', catalogue);
  const allowed = a.rows;
  const blocked = b.rows;
  const byApp = new Map();
  const add = (rows, field) => rows.slice(0, MAX_DOMAIN_ROWS).forEach((r) => {
    const app = appFor(domainOf(r), catalogue);
    if (!byApp.has(app.key)) byApp.set(app.key, Object.assign({ allowed: 0, blocked: 0 }, app));
    byApp.get(app.key)[field] += countOf(r);
  });
  add(allowed, 'allowed');
  add(blocked, 'blocked');

  return {
    rows: [...byApp.values()].sort((x, y) => (y.allowed + y.blocked) - (x.allowed + x.blocked)),
    sampled: allowed.length > MAX_DOMAIN_ROWS || blocked.length > MAX_DOMAIN_ROWS,
    catalogueRead: !!catalogue,
    filter: a.filter || b.filter || null,
  };
}

const userOf = r => pick(r, 'user_name', 'username', 'user.name', 'agent_name', 'agent.name',
  'hostname', 'local_user_name', 'user_id', 'agent_id');

async function collectUsers(cfg, day, now) {
  let catalogue = null;
  try { catalogue = await aiCatalogue(cfg, now); } catch (_) { /* unmapped */ }

  const { json, variant } = await reportByCategory(cfg, '/v1/traffic_reports/total_domains_users',
    Object.assign(windowParams(cfg, day), { type: 'all' }));
  const found = collectRows(json.data !== undefined ? json.data : json,
    r => userOf(flat(r)) !== undefined && countOf(r) !== null);
  if (found === null) throw Object.assign(new Error('unrecognised total_domains_users response'), { shape: true });

  let rows = found;
  let filter = null;
  if (variant === null) {
    const narrowed = narrowToAi(found, cfg, catalogue);
    if (!narrowed) {
      throw Object.assign(new Error(
        'DNSFilter would not filter this report by category, and the rows carry no category to filter on.'),
      { noCategoryFilter: true });
    }
    rows = narrowed.rows;
    filter = narrowed.filter;
  }

  const byUser = new Map();
  rows.forEach((r) => {
    const user = String(userOf(r));
    const d = domainOf(r);
    const app = d !== undefined ? appFor(d, catalogue).key : '';
    const k = `${user} ${app}`;
    if (!byUser.has(k)) byUser.set(k, { user, appKey: app, count: 0 });
    byUser.get(k).count += countOf(r);
  });

  const totals = new Map();
  byUser.forEach(v => totals.set(v.user, (totals.get(v.user) || 0) + v.count));
  const top = new Set([...totals.entries()].sort((a, b) => b[1] - a[1]).slice(0, MAX_USERS).map(e => e[0]));

  return {
    rows: [...byUser.values()].filter(v => top.has(v.user)),
    sampled: totals.size > MAX_USERS,
    filter,
  };
}

const idList = v => (Array.isArray(v) ? v : (v == null ? [] : String(v).split(','))).map(x => String(x && x.id != null ? x.id : x).trim());

async function collectPolicy(cfg) {
  const policies = (await getAllPages(cfg, '/v1/policies/all', { organization_id: validOrgId(cfg.organization_id) })).map(flat);
  return {
    rows: policies
      // The query asks for this organisation; a policy that names another is
      // not this client's and is not shown.
      .filter(p => p.organization_id == null || String(p.organization_id) === cfg.organization_id)
      .map(p => ({
        name: String(p.name || `Policy ${p.id}`),
        aiBlocked: cfg.aiCategoryId ? idList(p.blacklist_categories).indexOf(cfg.aiCategoryId) >= 0 : null,
        allowListOnly: p.allow_list_only === true,
      })),
  };
}

/**
 * Everything for one client-local day. Each panel stands alone: one that
 * cannot be read is unavailable with a reason, and the rest still arrive.
 */
async function fetchAiDay(config, day, opts) {
  const o = opts || {};
  const cfg = normaliseConfig(Object.assign({}, config, o.timeZone ? { timeZone: o.timeZone } : {}));
  if (o.transport) cfg.transport = o.transport;
  if (o.sleep) cfg.sleep = o.sleep;
  requireKey(cfg);
  validOrgId(cfg.organization_id);
  const now = o.now || Date.now();

  const out = { usage: null, apps: null, users: null, policy: null };
  const guard = async (key, fn) => {
    try { out[key] = panel(true, await fn()); } catch (err) {
      out[key] = unavailable(err.shape ? 'unrecognised_response' : reasonOf(err), detailOf(err));
    }
  };

  if (!cfg.aiCategoryId) {
    // Without the category nothing can be attributed to AI. Say so per panel.
    out.usage = unavailable('category_unknown');
    out.apps  = unavailable('category_unknown');
    out.users = unavailable('category_unknown');
  } else {
    await guard('usage', async () => {
      const allowed = await aiCategoryCount(cfg, day, 'allowed');
      const blocked = await aiCategoryCount(cfg, day, 'blocked');
      let total = null;
      let totalReason = null;
      let totalDetail = null;
      try { total = await totalRequests(cfg, day); } catch (err) {
        totalReason = err.shape ? 'unrecognised_response' : reasonOf(err);
        totalDetail = detailOf(err);
      }
      return { allowed, blocked, total, totalReason, totalDetail };
    });
    await guard('apps', () => collectApps(cfg, day, now));
    await guard('users', () => collectUsers(cfg, day, now));
  }
  await guard('policy', () => collectPolicy(cfg));
  return out;
}

// ── Test and probe ────────────────────────────────────────────────────────

/** Organisations the MSP key can see: [{ id, name }]. */
async function listOrganisations(config) {
  const cfg = normaliseConfig(config);
  const orgs = (await getAllPages(cfg, '/v1/organizations/all', {})).map(flat);
  return orgs
    .filter(o => o.id != null)
    .map(o => ({ id: String(o.id), name: String(o.name || `Organisation ${o.id}`) }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * The MSP-level Test: the key works, which organisations it sees, and which
 * category is Generative AI.
 */
async function testMspConnection(config) {
  const cfg = normaliseConfig(config);
  requireKey(cfg);
  const organisations = await listOrganisations(cfg);
  const category = await resolveAiCategory(cfg);
  return {
    organisations,
    aiCategory: category,
    message: `Connected to DNSFilter — ${organisations.length} organisation${organisations.length === 1 ? '' : 's'} visible. ` +
      (category ? `Generative AI category found (${category.name}).`
                : 'No Generative AI category found — AI traffic cannot be attributed until it is.'),
  };
}

/**
 * The per-client Test: the organisation id is one this key can see. This is
 * the check that stops a mistyped id filling one client's tab with another's.
 */
async function testConnection(config) {
  const cfg = normaliseConfig(config);
  requireKey(cfg);
  const orgId = validOrgId(cfg.organization_id);
  const organisations = await listOrganisations(cfg);
  const org = organisations.find(o => o.id === orgId);
  if (!org) {
    throw Object.assign(new Error(
      `Organisation ${orgId} is not visible to the DNSFilter MSP key. Check the id against the DNSFilter dashboard.`),
    { orgNotFound: true });
  }
  const category = cfg.aiCategoryId
    ? { id: cfg.aiCategoryId, name: null }
    : await resolveAiCategory(cfg);
  return {
    orgId,
    orgName: org.name,
    aiCategory: category,
    message: `Verified organisation "${org.name}" (${orgId}).` +
      (category ? '' : ' No Generative AI category found — AI traffic cannot be attributed until it is.'),
  };
}

/** Which reports answer for this organisation, and with which fields. */
async function probe(config, day) {
  const cfg = normaliseConfig(config);
  const d = day || new Date(Date.now() - 86400000).toISOString().slice(0, 10);
  const plain = {
    total_categories: { type: 'all', bucket_size: '1day' },
    total_requests:   { type: 'all', bucket_size: '1day' },
  };
  const out = { probedAt: new Date().toISOString(), day: d, reports: {}, categoryParam: undefined };

  for (const name of Object.keys(plain)) {
    try {
      const json = await request(cfg, `/v1/traffic_reports/${name}`, Object.assign(windowParams(cfg, d), plain[name]));
      out.reports[name] = { ok: true, fields: shapeOf(json) };
    } catch (err) {
      out.reports[name] = { ok: false, reason: reasonOf(err), detail: detailOf(err) };
    }
  }

  /*
   * The two reports that must be limited to the AI category, probed WITH that
   * filter — the first pilot's Test proved only that they answer without it,
   * and the sync then failed on every day with a 400.
   */
  for (const name of ['total_domains', 'total_domains_users']) {
    try {
      const r = await reportByCategory(cfg, `/v1/traffic_reports/${name}`, Object.assign(windowParams(cfg, d), { type: 'all' }));
      out.reports[name] = { ok: true, fields: shapeOf(r.json), categoryParam: r.variant };
      if (out.categoryParam === undefined) out.categoryParam = r.variant;
    } catch (err) {
      out.reports[name] = { ok: false, reason: reasonOf(err), detail: detailOf(err) };
    }
  }
  return out;
}

/**
 * Strip test seams and runtime state from a config read out of the database,
 * so nothing stored can install a transport or pre-select an auth scheme.
 */
function sanitiseStoredConfig(config) {
  const c = Object.assign({}, config || {});
  delete c.transport;
  delete c.sleep;
  delete c._authScheme;
  return c;
}

module.exports = {
  DEFAULT_BASE,
  MAX_USERS,
  MAX_TRANSIENT_RETRIES,
  CATEGORY_PARAM_VARIANTS,
  reasonOf,
  narrowToAi,
  _clearCategoryParamCache: () => categoryParamCache.clear(),
  ORG_ID_RE,
  validOrgId,
  normaliseConfig,
  buildUrl,
  request,
  getAllPages,
  collectRows,
  pick,
  countOf,
  hostOf,
  registeredDomain,
  appFor,
  aiCatalogue,
  resolveAiCategory,
  fetchAiDay,
  listOrganisations,
  testMspConnection,
  testConnection,
  probe,
  sanitiseStoredConfig,
  _clearCatalogueCache: () => catalogueCache.clear(),
};
