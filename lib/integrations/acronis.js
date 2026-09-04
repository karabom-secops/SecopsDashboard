'use strict';

/**
 * Acronis Cyber Protect Cloud adapter — Managed Email Security.
 *
 * Auth is OAuth 2.0 client credentials, NOT an API key, which is the one way
 * this provider differs structurally from every other integration here:
 *
 *   POST {base_url}/api/2/idp/token
 *   Authorization: Basic base64(client_id:client_secret)
 *   Content-Type: application/x-www-form-urlencoded
 *   grant_type=client_credentials
 *     -> { access_token, token_type: 'bearer', expires_on: <unix seconds> }
 *
 * The bearer token is short-lived (roughly two hours) and is cached in memory
 * per credential for the life of the process. The `integrations` row stores
 * client_id in config_json (it is an identifier, not a secret) and the client
 * SECRET in the existing encrypted api_key column — so the secret gets exactly
 * the same handling as every other provider's key and no new storage path
 * exists for someone to forget to encrypt.
 *
 * Alerts come from the Alert Manager API:
 *   GET {base_url}/api/alert_manager/v1/alerts?tenant=<uuid>&limit=&after=
 *
 * ══ WHAT IS VERIFIED AND WHAT IS NOT ══
 *
 * This adapter was written against Acronis's documented API shape without a
 * live tenant to call. The token exchange and the alert endpoint are stable,
 * long-published parts of that API. What is NOT verified is the exact `type`
 * strings Advanced Email Security raises and the exact field names inside an
 * alert's `details` object, both of which vary by product edition.
 *
 * Everything below is therefore written to degrade honestly rather than guess:
 *
 *   - field reads go through pick(), which tries several documented spellings
 *     and returns null rather than inventing a value;
 *   - classification is keyword-based over the type/category strings, and an
 *     alert we do not recognise is recorded as NOT email rather than being
 *     quietly folded into an 'other' bucket that would inflate the counts;
 *   - EVERY type seen is reported back to the caller in `typesSeen`, so a new
 *     Acronis alert type shows up as an unrecognised type in the tab instead of
 *     silently becoming zero on a chart.
 *
 * Validate against a real tenant before anyone reports these numbers to a
 * client. `probeTypes()` exists for exactly that.
 */

const https = require('https');
const http  = require('http');
const { URL } = require('url');

const PAGE_LIMIT  = 200;    // Alert Manager caps a page well below this; it clamps.
const MAX_PAGES   = 100;    // hard stop so a paging bug cannot loop forever
const REQ_TIMEOUT = 30000;

// Refresh this many ms before the token actually expires, so a long sync does
// not have a request fail on a token that died mid-flight.
const TOKEN_SKEW_MS = 5 * 60 * 1000;

// ── HTTP ───────────────────────────────────────────────────────────────────

function request(baseUrl, path, { method = 'GET', headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    let fullUrl;
    try {
      fullUrl = new URL(path, baseUrl);
    } catch (_) {
      return reject(new Error('Acronis base URL is not a valid URL: ' + baseUrl));
    }
    const lib = fullUrl.protocol === 'https:' ? https : http;

    const opts = {
      hostname: fullUrl.hostname,
      port:     fullUrl.port || (fullUrl.protocol === 'https:' ? 443 : 80),
      path:     fullUrl.pathname + fullUrl.search,
      method,
      headers: Object.assign({
        'Accept':     'application/json',
        'User-Agent': 'SecOpsDashboard/1.0',
      }, headers),
      timeout: REQ_TIMEOUT,
    };

    const req = lib.request(opts, (res) => {
      let raw = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { raw += c; });
      res.on('end', () => {
        if (res.statusCode >= 400) {
          /*
           * The error body is echoed, but only a slice of it, and only after
           * trying the structured field first. A token response body carries
           * the access token; an error body from the same endpoint can echo
           * request context. Capping it keeps a credential out of a message
           * that ends up in integrations.last_sync_message and on screen.
           */
          let detail = '';
          try {
            const parsed = JSON.parse(raw);
            detail = parsed.error_description || parsed.message ||
                     (parsed.error && (parsed.error.message || parsed.error)) || '';
          } catch (_) { /* fall through to the slice */ }
          if (!detail) detail = raw.slice(0, 200);
          if (typeof detail !== 'string') detail = String(detail);
          return reject(new Error(
            'Acronis API ' + res.statusCode + ': ' + detail.slice(0, 300)));
        }
        if (!raw) return resolve({});
        try { resolve(JSON.parse(raw)); }
        catch (_) { reject(new Error('Acronis API returned invalid JSON')); }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Acronis API request timed out')); });
    if (body) req.write(body);
    req.end();
  });
}

// ── Token ──────────────────────────────────────────────────────────────────

/*
 * Cache keyed by base URL + client id. Deliberately NOT keyed by the secret:
 * the secret would then be a map key, printable by anything that ever dumps the
 * cache. Rotating a secret without restarting means one stale-token 401, after
 * which invalidateToken() drops the entry and the next call re-authenticates.
 */
const tokenCache = new Map();

function cacheKey(config) {
  return String(config.base_url) + '|' + String(config.client_id);
}

function invalidateToken(config) {
  tokenCache.delete(cacheKey(config));
}

async function getToken(config) {
  const key = cacheKey(config);
  const hit = tokenCache.get(key);
  if (hit && hit.expiresAt - TOKEN_SKEW_MS > Date.now()) return hit.token;

  const clientId     = String(config.client_id || '').trim();
  const clientSecret = String(config.api_key   || '').trim();
  if (!clientId)     throw new Error('Acronis client ID is not configured.');
  if (!clientSecret) throw new Error('Acronis client secret is not configured.');

  const basic = Buffer.from(clientId + ':' + clientSecret).toString('base64');
  const data  = await request(config.base_url, '/api/2/idp/token', {
    method: 'POST',
    headers: {
      'Authorization':  'Basic ' + basic,
      'Content-Type':   'application/x-www-form-urlencoded',
      'Content-Length': Buffer.byteLength('grant_type=client_credentials'),
    },
    body: 'grant_type=client_credentials',
  });

  const token = data && data.access_token;
  if (!token) throw new Error('Acronis did not return an access token.');

  /*
   * expires_on is an absolute unix timestamp in seconds. Where it is missing or
   * nonsensical, fall back to a short life rather than a long one: re-fetching
   * a token needlessly costs one request, whereas trusting a bad expiry means
   * every call failing until the process restarts.
   */
  const expSec = Number(data.expires_on);
  const expiresAt = Number.isFinite(expSec) && expSec * 1000 > Date.now()
    ? expSec * 1000
    : Date.now() + 15 * 60 * 1000;

  tokenCache.set(key, { token, expiresAt });
  return token;
}

/** An authenticated GET that retries once on a 401 with a fresh token. */
async function authGet(config, path) {
  const token = await getToken(config);
  try {
    return await request(config.base_url, path, {
      headers: { 'Authorization': 'Bearer ' + token },
    });
  } catch (err) {
    if (!/Acronis API 401/.test(err.message)) throw err;
    // The cached token was revoked or the secret rotated. One retry, then out —
    // a loop here would hammer the IdP with bad credentials and get us locked.
    invalidateToken(config);
    const fresh = await getToken(config);
    return request(config.base_url, path, {
      headers: { 'Authorization': 'Bearer ' + fresh },
    });
  }
}

// ── Field reading ──────────────────────────────────────────────────────────

function str(v) {
  if (v === null || v === undefined) return null;
  if (typeof v === 'object') return null;
  const s = String(v).trim();
  return s === '' ? null : s;
}

function ts(v) {
  if (v === null || v === undefined || v === '') return null;
  // Acronis sends ISO 8601; a numeric unix timestamp is accepted defensively.
  const d = typeof v === 'number' ? new Date(v > 1e12 ? v : v * 1000) : new Date(v);
  return isNaN(d.getTime()) ? null : d.toISOString();
}

/**
 * First present value among several candidate paths, e.g.
 *   pick(alert, 'details.recipient', 'details.to', 'recipient')
 *
 * Exists because the alert `details` shape differs by product edition and this
 * adapter has not been run against every one. Returning null when no candidate
 * matches is the point: an absent field must read as "the alert did not say",
 * never as a default that looks like data.
 */
function pick(obj, ...paths) {
  for (const p of paths) {
    let cur = obj;
    for (const seg of String(p).split('.')) {
      if (cur === null || cur === undefined || typeof cur !== 'object') { cur = undefined; break; }
      cur = cur[seg];
    }
    const v = str(cur);
    if (v !== null) return v;
  }
  return null;
}

/** The domain half of an address, lowercased. null for anything unparseable. */
function domainOf(address) {
  const a = str(address);
  if (!a) return null;
  const at = a.lastIndexOf('@');
  if (at < 0 || at === a.length - 1) return null;
  return a.slice(at + 1).toLowerCase().replace(/^<|>$/g, '') || null;
}

// ── Classification ─────────────────────────────────────────────────────────

/**
 * Which alerts are email security, and what kind of threat they describe.
 *
 * Acronis raises backup, disaster-recovery, patching and endpoint alerts
 * through this same API, so most alerts a tenant returns are NOT email, and
 * that is the expected outcome rather than a failure.
 *
 * Matching is on keywords in the type and category strings rather than on an
 * exact list of type names, because the exact names differ by edition and a
 * missed name would silently zero a chart. A keyword match is looser than an
 * enum and that is the intended trade: over-matching shows up as a visible
 * miscategorised alert, under-matching shows up as nothing at all.
 *
 * ORDER MATTERS. The first matching class wins, so the specific patterns come
 * before the general ones — a "phishing url" alert is phishing, not url.
 */
const THREAT_CLASSES = [
  { key: 'bec',        patterns: [/\bbec\b/, /business.?email.?compromise/, /impersonat/, /spoof/] },
  { key: 'phishing',   patterns: [/phish/, /credential.?harvest/] },
  { key: 'malware',    patterns: [/malware/, /ransom/, /trojan/, /virus/, /malicious.?attach/] },
  { key: 'url',        patterns: [/malicious.?url/, /\burl\b/, /\blink\b/] },
  { key: 'attachment', patterns: [/attach/] },
  { key: 'spam',       patterns: [/spam/, /bulk/, /graymail/, /greymail/] },
  { key: 'dlp',        patterns: [/\bdlp\b/, /data.?loss/, /data.?leak/] },
];

/** Signals that an alert concerns email at all. */
const EMAIL_PATTERNS = [
  /email/, /\bmail\b/, /mailbox/, /message/, /smtp/, /\bmta\b/,
  /perception.?point/,   // Acronis Advanced Email Security is Perception Point
  /phish/, /\bspam\b/,
];

/**
 * Split an identifier into lower-case words.
 *
 * Acronis type names are camelCase run together — `EmailBECAttemptDetected`.
 * Lower-casing that whole string gives `emailbecattemptdetected`, in which
 * NOTHING has a word boundary, so every \b pattern below silently fails to
 * match and the alert falls through as unclassified. Splitting on case
 * transitions first turns it into `email bec attempt detected`, which is what
 * the patterns are actually written against.
 *
 * Two passes, in this order: the acronym rule (BECAttempt -> BEC Attempt) then
 * the ordinary camel rule (EmailBEC -> Email BEC). Reversing them leaves the
 * acronym fused to the word before it.
 */
function words(s) {
  return String(s || '')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[^A-Za-z0-9]+/g, ' ')
    .toLowerCase()
    .trim();
}

function haystack(alert) {
  return [
    pick(alert, 'type'),
    pick(alert, 'category'),
    pick(alert, 'details.name'),
    pick(alert, 'details.threatName'),
    pick(alert, 'details.threat_name'),
  ].filter(Boolean).map(words).join(' ');
}

/**
 * @returns {{ isEmail: boolean, threatClass: string|null }}
 *
 * threatClass is null when the alert is email but the KIND is unrecognised.
 * That null travels all the way to the tab, which shows it as "unclassified"
 * rather than picking a bucket. A wrong bucket is worse than an honest gap:
 * nobody audits a number that looks plausible.
 */
function classify(alert) {
  const hay = haystack(alert);
  if (!hay) return { isEmail: false, threatClass: null };

  const isEmail = EMAIL_PATTERNS.some(re => re.test(hay));
  if (!isEmail) return { isEmail: false, threatClass: null };

  for (const c of THREAT_CLASSES) {
    if (c.patterns.some(re => re.test(hay))) return { isEmail: true, threatClass: c.key };
  }
  return { isEmail: true, threatClass: null };
}

/**
 * What happened to the message.
 *
 * Returns null when the alert does not say, and null must survive: a message
 * whose fate is unknown is not a message that was blocked, and counting it as
 * blocked would turn a reporting gap into a reassuring number on a board slide.
 */
const DISPOSITIONS = [
  { key: 'quarantined', patterns: [/quarantin/] },
  { key: 'blocked',     patterns: [/block/, /reject/, /denied/, /prevent/] },
  { key: 'remediated',  patterns: [/remediat/, /retract/, /clawback/, /removed/, /purge/] },
  { key: 'delivered',   patterns: [/deliver/, /allow/, /passed/, /released/] },
];

function readDisposition(alert) {
  const raw = [
    pick(alert, 'details.action'), pick(alert, 'details.disposition'),
    pick(alert, 'details.verdict'), pick(alert, 'details.status'),
    pick(alert, 'details.remediationStatus'), pick(alert, 'details.remediation_status'),
  ].filter(Boolean).map(words).join(' ');
  if (!raw) return null;

  for (const d of DISPOSITIONS) {
    if (d.patterns.some(re => re.test(raw))) return d.key;
  }
  return null;
}

// ── Normalisation ──────────────────────────────────────────────────────────

function mapAlert(alert) {
  const { isEmail, threatClass } = classify(alert);

  const recipient = pick(alert,
    'details.recipient', 'details.recipients', 'details.to',
    'details.mailbox', 'details.userEmail', 'details.user_email');
  const sender = pick(alert,
    'details.sender', 'details.from', 'details.senderAddress', 'details.sender_address');

  return {
    alertId:   pick(alert, 'id', 'alertId', 'alert_id'),
    alertType: pick(alert, 'type'),
    category:  pick(alert, 'category'),
    severity:  pick(alert, 'severity'),
    isEmail,
    threatClass,
    disposition: readDisposition(alert),

    recipient,
    recipientDomain: domainOf(recipient),
    sender,
    senderDomain:    domainOf(sender),
    subject: pick(alert, 'details.subject', 'details.messageSubject', 'details.message_subject'),

    createdAt:  ts(pick(alert, 'createdAt', 'created_at')),
    updatedAt:  ts(pick(alert, 'updatedAt', 'updated_at')),
    receivedAt: ts(pick(alert, 'receivedAt', 'received_at')),
    resolvedAt: ts(pick(alert, 'resolvedAt', 'resolved_at', 'details.resolvedAt')),
    status:     pick(alert, 'status', 'state', 'details.status'),

    raw: alert,
  };
}

// ── Fetching ───────────────────────────────────────────────────────────────

function alertsPath(config, { since, limit, after }) {
  const params = ['limit=' + encodeURIComponent(limit)];

  /*
   * The tenant UUID scopes the query to this client. It is required, not
   * optional: an unscoped call against a partner-level credential returns
   * every tenant that credential can see, and those alerts would be written
   * against whichever dashboard tenant happened to trigger the sync.
   */
  const uuid = str(config.tenant_uuid);
  if (uuid) params.push('tenant=' + encodeURIComponent(uuid));

  if (after) params.push('after=' + encodeURIComponent(after));
  if (since) params.push('updatedAt=' + encodeURIComponent('gt(' + since + ')'));

  return '/api/alert_manager/v1/alerts?' + params.join('&');
}

/** Cursor for the next page, across the shapes the API has used. */
function nextCursor(page) {
  if (!page || typeof page !== 'object') return null;
  const paging = page.paging || {};
  const cursors = paging.cursors || {};
  return str(cursors.after) || str(paging.after) || str(paging.next) || null;
}

function itemsOf(page) {
  if (Array.isArray(page)) return page;
  if (page && Array.isArray(page.items)) return page.items;
  if (page && Array.isArray(page.data))  return page.data;
  return [];
}

/**
 * Pull alerts and split them into email-security alerts and a ledger of every
 * type seen.
 *
 * @returns {{ alerts: Array, typesSeen: Array<{alertType, category, isEmail, count}>,
 *             pagesFetched: number, truncated: boolean }}
 *
 * `truncated` is true when MAX_PAGES was hit with a cursor still outstanding —
 * so a partial pull is reported as partial instead of looking like a quiet
 * month.
 */
async function fetchAlerts(config, { since = null, testOnly = false } = {}) {
  const alerts = [];
  const seen = new Map();
  let after = null;
  let pages = 0;
  let truncated = false;

  while (pages < MAX_PAGES) {
    const page = await authGet(config, alertsPath(config, {
      since: testOnly ? null : since,
      limit: testOnly ? 1 : PAGE_LIMIT,
      after,
    }));

    const items = itemsOf(page);
    pages++;

    for (const item of items) {
      const mapped = mapAlert(item);

      // An alert with no id cannot be upserted, deduplicated or reconciled on a
      // later sync. Counted in the ledger so the gap is visible, then dropped.
      const typeKey = mapped.alertType || '(untyped)';
      const entry = seen.get(typeKey) || {
        alertType: typeKey, category: mapped.category,
        isEmail: mapped.isEmail, count: 0,
      };
      entry.count++;
      seen.set(typeKey, entry);

      if (!mapped.isEmail) continue;
      if (!mapped.alertId) continue;
      alerts.push(mapped);
    }

    after = nextCursor(page);
    if (testOnly || !after || items.length === 0) break;
    if (pages >= MAX_PAGES && after) truncated = true;
  }

  return {
    alerts,
    typesSeen: [...seen.values()],
    pagesFetched: pages,
    truncated,
  };
}

/**
 * Credential check. Exchanges the token and asks for a single alert, so it
 * proves the client id, the secret AND that the tenant scope returns something
 * the Alert Manager will serve — three separate ways this can be misconfigured.
 */
async function testConnection(config) {
  const result = await fetchAlerts(config, { testOnly: true });
  return {
    ok: true,
    typesSeen: result.typesSeen,
    emailAlertsOnFirstPage: result.alerts.length,
  };
}

/**
 * What alert types this tenant actually raises, and which ones we read as email.
 *
 * The tool for validating the classifier against a real tenant: run it, look at
 * what came back marked isEmail:false that should have been true, and add the
 * keyword. Every guess in this file is a guess this makes visible.
 */
async function probeTypes(config) {
  const result = await fetchAlerts(config, {});
  return result.typesSeen.sort((a, b) => b.count - a.count);
}

module.exports = {
  fetchAlerts,
  testConnection,
  probeTypes,
  // Exported for tests — the classifier is the part most likely to be wrong,
  // and it must be assertable without a live tenant.
  classify,
  readDisposition,
  mapAlert,
  domainOf,
  pick,
  THREAT_CLASSES,
  EMAIL_PATTERNS,
  words,
  _invalidateToken: invalidateToken,
};
