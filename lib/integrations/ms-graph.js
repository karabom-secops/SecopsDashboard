'use strict';

/**
 * Microsoft Graph adapter — Microsoft Secure Score.
 *
 * ══ WHY THIS EXISTS WHEN WE ALREADY READ MICROSOFT DATA ══
 *
 * The Managed Identity tab already shows Microsoft telemetry, but it arrives
 * second-hand: Wazuh's `ms-graph` wodle forwards alerts_v2, riskyUsers,
 * riskDetections and signIns into the alerts index, and lib/wazuh-metrics.js
 * aggregates from there. Secure Score is not among those relationships and
 * structurally cannot be — it is a daily POSTURE SNAPSHOT, not an event stream,
 * so it never lands in wazuh-alerts-4.x-* and no query against the indexer can
 * reach it. It has to be pulled from Graph directly, which is what this is.
 *
 * ══ AUTH ══
 *
 * OAuth 2.0 client credentials, like Acronis, but with the token endpoint on a
 * DIFFERENT HOST from the API:
 *
 *   POST {authority}/{azureTenantId}/oauth2/v2.0/token
 *   Content-Type: application/x-www-form-urlencoded
 *   client_id=…&client_secret=…&scope={graph}/.default&grant_type=client_credentials
 *     -> { access_token, token_type: 'Bearer', expires_in: <seconds> }
 *
 * That split matters for national clouds: US Gov and China have their own
 * authority AND their own Graph host, and hardcoding either would silently
 * confine this to commercial tenants. Both are configurable; both default to
 * commercial.
 *
 * The integrations row holds the client id and the Azure tenant id in
 * config_json (identifiers, not secrets) and the client SECRET in the encrypted
 * api_key column — the same single path to disk every other credential takes.
 *
 * Required app permission: SecurityEvents.Read.All (APPLICATION, with admin
 * consent). Delegated will not work: nobody is signed in during a scheduled
 * sync. A tenant that granted the delegated variant by mistake authenticates
 * perfectly and then 403s on the first read, so testConnection() reads a real
 * record rather than just exchanging a token.
 *
 * ══ THE TWO ENDPOINTS, AND WHY BOTH ══
 *
 *   GET {graph}/security/secureScores
 *     ~90 daily snapshots, newest first. Each carries currentScore, maxScore
 *     and a controlScores[] array of what was earned per control.
 *
 *   GET {graph}/security/secureScoreControlProfiles
 *     The control CATALOGUE: title, remediation text, max points, tier,
 *     threats addressed, and the tenant's own disposition of each control.
 *
 * The snapshot alone gives a gauge. The gauge is the least valuable thing here
 * — the client's own IT already sees it in the M365 admin centre. The profiles
 * are what turn it into a prioritised remediation backlog with point values
 * attached, which is the artefact worth reporting. So both, joined by
 * controlName in mergeControls().
 *
 * ══ WHAT IS VERIFIED AND WHAT IS NOT ══
 *
 * Written against the documented v1.0 shape of both resources without a live
 * tenant to call. The token exchange, the two paths and the OData paging
 * envelope are long-stable. What is NOT verified against a real tenant is the
 * exact spelling of the less-documented profile fields (remediationImpact,
 * implementationCost, controlStateUpdates) — Microsoft has shipped both camel
 * and lower spellings of some of these across API versions.
 *
 * Everything is therefore read through pick()/num(), which try the documented
 * spellings and return NULL rather than a default. A field we cannot read must
 * render as "Microsoft did not say", never as a zero that looks like a measured
 * result. Validate against a real tenant before any of this reaches a board.
 */

const https = require('https');
const http  = require('http');
const { URL } = require('url');

const DEFAULT_GRAPH_BASE = 'https://graph.microsoft.com/v1.0';
const DEFAULT_AUTHORITY  = 'https://login.microsoftonline.com';

const REQ_TIMEOUT = 30000;

// Graph pages profiles at 100 and will not serve more, whatever $top says.
const PAGE_SIZE = 100;

// Hard stop so a nextLink loop cannot run forever. ~200 profiles in a large
// tenant, so 50 pages is an order of magnitude of headroom.
const MAX_PAGES = 50;

// Snapshots to pull. Graph retains about 90 days; asking for more is harmless
// and a first sync should land the full history it can.
const DEFAULT_SNAPSHOT_DAYS = 90;

// Refresh this far before the token actually dies, so a long paged sync does
// not fail mid-flight on a token that expired between pages.
const TOKEN_SKEW_MS = 5 * 60 * 1000;

// A 429 from Graph carries Retry-After. Honour it, but never sleep absurdly —
// a scheduled sync that parks for an hour looks identical to a hung process.
const MAX_RETRY_AFTER_MS = 60 * 1000;
const MAX_THROTTLE_RETRIES = 3;

// ── HTTP ───────────────────────────────────────────────────────────────────

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * One request. `absoluteUrl` is used as-is — Graph's @odata.nextLink is a fully
 * qualified URL including its own opaque $skiptoken, and rebuilding it from
 * parts is how paging quietly starts again at page one.
 */
/**
 * Response headers ride along NON-ENUMERABLY, so the parsed body still
 * serialises and iterates exactly as before. The Office 365 Management
 * Activity API pages through a NextPageUri header rather than the body.
 */
function withHeaders(parsed, headers) {
  if (parsed && typeof parsed === 'object') {
    Object.defineProperty(parsed, '__headers', { value: headers || {}, enumerable: false });
  }
  return parsed;
}

function request(absoluteUrl, { method = 'GET', headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    let fullUrl;
    try {
      fullUrl = new URL(absoluteUrl);
    } catch (_) {
      return reject(new Error('Microsoft Graph URL is not valid: ' + absoluteUrl));
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
        if (res.statusCode === 429 || res.statusCode === 503) {
          const err = new Error('Microsoft Graph throttled the request (' + res.statusCode + ')');
          err.throttled = true;
          // Retry-After is in seconds per RFC; Graph honours that.
          const secs = Number(res.headers['retry-after']);
          err.retryAfterMs = Number.isFinite(secs) && secs > 0
            ? Math.min(secs * 1000, MAX_RETRY_AFTER_MS)
            : 5000;
          return reject(err);
        }

        if (res.statusCode >= 400) {
          /*
           * Only a slice of the error body, and the structured field first.
           * A token endpoint echoes request context on failure, and this
           * message is stored in integrations.last_sync_message and rendered
           * on the Admin screen — a secret must not be able to reach it.
           */
          let detail = '';
          try {
            const parsed = JSON.parse(raw);
            detail = parsed.error_description ||
                     (parsed.error && (parsed.error.message || parsed.error)) ||
                     parsed.message || '';
          } catch (_) { /* fall through to the slice */ }
          if (!detail) detail = raw.slice(0, 200);
          if (typeof detail !== 'string') detail = String(detail);

          const err = new Error(
            'Microsoft Graph API ' + res.statusCode + ': ' + detail.slice(0, 300));
          err.statusCode = res.statusCode;
          return reject(err);
        }

        if (!raw) return resolve(withHeaders({}, res.headers));
        try { resolve(withHeaders(JSON.parse(raw), res.headers)); }
        catch (_) { reject(new Error('Microsoft Graph returned invalid JSON')); }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Microsoft Graph request timed out'));
    });
    if (body) req.write(body);
    req.end();
  });
}

// ── Config ─────────────────────────────────────────────────────────────────

function str(v) {
  if (v === null || v === undefined) return null;
  if (typeof v === 'object') return null;
  const s = String(v).trim();
  return s === '' ? null : s;
}

/** Trailing slashes make `a + '/' + b` produce `//`, which Graph 404s. */
function trimSlash(s) {
  return String(s || '').replace(/\/+$/, '');
}

function graphBase(config) {
  return trimSlash(str(config.base_url) || DEFAULT_GRAPH_BASE);
}

function authorityBase(config) {
  return trimSlash(str(config.authority_url) || DEFAULT_AUTHORITY);
}

/**
 * The `scope` for a client-credentials token is the RESOURCE root, not the
 * versioned API path: `https://graph.microsoft.com/.default`, never
 * `https://graph.microsoft.com/v1.0/.default`. The second is a scope no
 * application has been granted, and Azure AD rejects it with an error naming
 * the client rather than the scope, which sends you looking in the wrong place.
 */
function graphScope(config) {
  const base = graphBase(config);
  let origin;
  try { origin = new URL(base).origin; }
  catch (_) { origin = 'https://graph.microsoft.com'; }
  return origin + '/.default';
}

// ── Token ──────────────────────────────────────────────────────────────────

/*
 * Keyed by authority + azure tenant + client id. Deliberately NOT by the
 * secret: a secret used as a map key is printable by anything that ever dumps
 * the cache. Rotating a secret without a restart costs one 401, after which
 * invalidateToken() drops the entry and the next call re-authenticates.
 */
const tokenCache = new Map();

/*
 * The scope is part of the key: one app registration holds a Graph token and,
 * for Managed Identity, a separate Office 365 Management API token, and each is
 * valid only for its own resource.
 */
function cacheKey(config, scope) {
  return authorityBase(config) + '|' + String(config.azure_tenant_id) + '|' +
    String(config.client_id) + '|' + (scope || graphScope(config));
}

function invalidateToken(config, scope) {
  tokenCache.delete(cacheKey(config, scope));
}

async function getToken(config, scopeOverride) {
  const scope = scopeOverride || graphScope(config);
  const key = cacheKey(config, scope);
  const hit = tokenCache.get(key);
  if (hit && hit.expiresAt - TOKEN_SKEW_MS > Date.now()) return hit.token;

  const azureTenantId = str(config.azure_tenant_id);
  const clientId      = str(config.client_id);
  const clientSecret  = str(config.api_key);

  if (!azureTenantId) throw new Error('Microsoft 365 Directory (tenant) ID is not configured.');
  if (!clientId)      throw new Error('Microsoft Graph application (client) ID is not configured.');
  if (!clientSecret)  throw new Error('Microsoft Graph client secret is not configured.');

  const form = [
    'client_id='     + encodeURIComponent(clientId),
    'client_secret=' + encodeURIComponent(clientSecret),
    'scope='         + encodeURIComponent(scope),
    'grant_type=client_credentials',
  ].join('&');

  const tokenUrl = authorityBase(config) + '/' +
    encodeURIComponent(azureTenantId) + '/oauth2/v2.0/token';

  const data = await request(tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type':   'application/x-www-form-urlencoded',
      'Content-Length': Buffer.byteLength(form),
    },
    body: form,
  });

  const token = data && data.access_token;
  if (!token) throw new Error('Azure AD did not return an access token.');

  /*
   * expires_in is a RELATIVE lifetime in seconds (Azure AD sends ~3600), unlike
   * Acronis's absolute expires_on. Where it is missing or nonsensical, fall
   * back SHORT: re-fetching needlessly costs one request, whereas trusting a
   * bad expiry means every call failing until the process restarts.
   */
  const secs = Number(data.expires_in);
  const expiresAt = Number.isFinite(secs) && secs > 0
    ? Date.now() + secs * 1000
    : Date.now() + 15 * 60 * 1000;

  tokenCache.set(key, { token, expiresAt });
  return token;
}

/**
 * Authenticated GET with three distinct recoveries, in order:
 *   401  the cached token was revoked or the secret rotated -> one retry with a
 *        fresh token, then out. A loop here hammers Azure AD with bad
 *        credentials and gets the app locked.
 *   429  Graph throttling -> honour Retry-After, bounded attempts.
 *   else surface.
 */
async function authGet(config, absoluteUrl, opts) {
  return authRequest(config, absoluteUrl, Object.assign({ method: 'GET' }, opts || {}));
}

/**
 * The authenticated request behind authGet, also used for the few POSTs
 * Managed Identity needs (starting Office 365 audit subscriptions).
 *
 * opts: { method, scope, permission, body }
 *   scope       token resource; defaults to Graph
 *   permission  the application permission this call needs, named in a 403 so
 *               the operator is told exactly what to grant
 */
async function authRequest(config, absoluteUrl, opts) {
  const o = opts || {};
  let retriedAuth = false;
  let throttleTries = 0;

  for (;;) {
    const token = await getToken(config, o.scope);
    try {
      const headers = { 'Authorization': 'Bearer ' + token };
      let body = null;
      if (o.body !== undefined && o.body !== null) {
        body = typeof o.body === 'string' ? o.body : JSON.stringify(o.body);
        headers['Content-Type'] = 'application/json';
        headers['Content-Length'] = Buffer.byteLength(body);
      } else if (o.method && o.method !== 'GET') {
        headers['Content-Length'] = 0;
      }
      return await request(absoluteUrl, { method: o.method || 'GET', headers, body });
    } catch (err) {
      if (err.statusCode === 401 && !retriedAuth) {
        retriedAuth = true;
        invalidateToken(config, o.scope);
        continue;
      }
      if (err.throttled && throttleTries < MAX_THROTTLE_RETRIES) {
        throttleTries++;
        await sleep(err.retryAfterMs);
        continue;
      }
      /*
       * 403 is the single most likely misconfiguration and the least
       * self-explanatory: Graph says "Insufficient privileges", which reads as
       * a licensing problem when it is almost always the delegated-vs-
       * application permission mistake, or consent never having been granted.
       * Say so where the operator will actually read it.
       */
      if (err.statusCode === 403) {
        err.notPermitted = true;
        err.message = err.message +
          ' — check that ' + (o.permission || 'SecurityEvents.Read.All') +
          ' is granted as an APPLICATION permission (not delegated) and that admin consent has been given.';
      }
      throw err;
    }
  }
}

/** Follow @odata.nextLink to the end, or to `opts.maxPages` (default MAX_PAGES). */
async function getAllPages(config, firstUrl, opts) {
  const o = opts || {};
  const limit = o.maxPages || MAX_PAGES;
  const items = [];
  let url = firstUrl;
  let pages = 0;
  let truncated = false;

  while (url && pages < limit) {
    const page = await authGet(config, url, o);
    pages++;
    if (page && Array.isArray(page.value)) items.push(...page.value);
    url = str(page && page['@odata.nextLink']);
    if (url && pages >= limit) truncated = true;
  }

  return { items, pages, truncated };
}

// ── Field reading ──────────────────────────────────────────────────────────

/**
 * First present value among candidate paths.
 *
 * Exists because several profile fields have shipped under more than one
 * spelling across API versions and this adapter has not been run against every
 * tenant. Returning null when nothing matches is the point: absent must read as
 * "Microsoft did not say", never as a default that looks like data.
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

/**
 * A number, or null.
 *
 * The null matters more than the number. A control whose score Microsoft did
 * not report is not a control worth zero points — it is a control we could not
 * measure, and the two must not collapse. `0` is preserved as 0; only absent,
 * empty and unparseable become null.
 */
function num(v) {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function numOf(obj, ...keys) {
  for (const k of keys) {
    if (obj && Object.prototype.hasOwnProperty.call(obj, k)) {
      const n = num(obj[k]);
      if (n !== null) return n;
    }
  }
  return null;
}

function arr(v) {
  return Array.isArray(v) ? v : [];
}

/** The UTC date part of an ISO timestamp. null for anything unparseable. */
function dateOf(v) {
  const s = str(v);
  if (!s) return null;
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d.toISOString().slice(0, 10);
}

/**
 * currentScore / maxScore as a percentage, or null.
 *
 * The one place this conversion is allowed to happen, and it is null-strict on
 * purpose. A maxScore of 0 is not a tenant at 0% — it is a tenant Graph has not
 * scored yet (no licensed workloads, or a snapshot taken mid-provisioning), and
 * dividing by it would put a red 0% on a board pack for a client with no
 * problem at all.
 */
function percentage(current, max) {
  const c = num(current);
  const m = num(max);
  if (c === null || m === null || m <= 0) return null;
  return Math.round((c / m) * 1000) / 10;
}

// ── Normalisation ──────────────────────────────────────────────────────────

/**
 * One daily snapshot.
 *
 * `controlScores` is carried through unmapped — mergeControls() joins it to the
 * profile catalogue, and doing that here would force a profile fetch on callers
 * who only want the headline trend.
 */
function mapSnapshot(s) {
  return {
    scoreDate:         dateOf(pick(s, 'createdDateTime')),
    currentScore:      numOf(s, 'currentScore'),
    maxScore:          numOf(s, 'maxScore'),
    azureTenantId:     pick(s, 'azureTenantId'),
    activeUserCount:   numOf(s, 'activeUserCount'),
    licensedUserCount: numOf(s, 'licensedUserCount'),
    enabledServices:   arr(s && s.enabledServices),
    comparative:       arr(s && s.averageComparativeScores),
    controlScores:     arr(s && s.controlScores),
    raw: s,
  };
}

/**
 * The tenant's disposition of a control, from controlStateUpdates[].
 *
 * The array is an append-only audit trail — every state change the tenant has
 * ever made — so the CURRENT state is the newest entry, not the first one.
 * Reading [0] happens to be right whenever nobody ever changed their mind,
 * which is exactly the sort of bug that survives testing and then mislabels the
 * one control an argumentative client asks about.
 */
function readControlState(profile) {
  const updates = arr(profile && profile.controlStateUpdates);
  if (!updates.length) return null;

  let newest = null;
  let newestAt = -Infinity;
  for (const u of updates) {
    const state = pick(u, 'state', 'assignedTo');
    if (!state) continue;
    const t = Date.parse(pick(u, 'updatedDateTime', 'updated_date_time') || '');
    const at = Number.isFinite(t) ? t : -Infinity;
    // >= so that, with no usable timestamps anywhere, the LAST entry wins —
    // append-only means later is newer even when undated.
    if (at >= newestAt) { newestAt = at; newest = state; }
  }
  return newest;
}

/** One entry from secureScoreControlProfiles. */
function mapProfile(p) {
  return {
    controlName:       pick(p, 'id', 'controlName'),
    title:             pick(p, 'title'),
    controlCategory:   pick(p, 'controlCategory'),
    maxScore:          numOf(p, 'maxScore'),
    rank:              numOf(p, 'rank'),
    tier:              pick(p, 'tier'),
    service:           pick(p, 'service'),
    actionType:        pick(p, 'actionType'),
    actionUrl:         pick(p, 'actionUrl'),
    remediation:       pick(p, 'remediation'),
    remediationImpact: pick(p, 'remediationImpact'),
    userImpact:        pick(p, 'userImpact'),
    implementationCost: pick(p, 'implementationCost'),
    threats:           arr(p && p.threats),
    // Absent means "not deprecated". Only an explicit true is deprecation —
    // coercing a missing field would retire every control on a tenant whose
    // Graph version omits the property.
    deprecated:        (p && p.deprecated) === true,
    controlState:      readControlState(p),
    raw: p,
  };
}

/**
 * Join a snapshot's per-control scores to the profile catalogue.
 *
 * ══ THE JOIN IS OUTER ON THE SCORE SIDE, DELIBERATELY ══
 *
 * A control that appears in the snapshot but has no profile still gets a row,
 * with every profile field null. Microsoft retires profiles while historical
 * snapshots continue to reference the control, so an inner join silently drops
 * controls — and a control missing from a remediation list is a gap nobody
 * sees, which is the worst failure mode this file has.
 *
 * The reverse (a profile with no score) is NOT emitted: it means the control
 * does not apply to this tenant's licences, and listing it would tell a client
 * to remediate something they cannot reach.
 *
 * @param {Array} controlScores  snapshot.controlScores
 * @param {Map}   profileMap     controlName (lowercased) -> mapped profile
 */
function mergeControls(controlScores, profileMap) {
  const out = [];

  for (const cs of arr(controlScores)) {
    const name = pick(cs, 'controlName', 'id');
    // Without a name there is nothing to upsert on and nothing to join to.
    if (!name) continue;

    const profile = (profileMap && profileMap.get(name.toLowerCase())) || null;

    const score = numOf(cs, 'score');
    const max   = profile ? profile.maxScore : null;

    out.push({
      controlName:      name,
      controlCategory:  pick(cs, 'controlCategory') || (profile && profile.controlCategory) || null,
      score,
      scoreInPercentage: numOf(cs, 'scoreInPercentage'),
      implementationStatus: pick(cs, 'implementationStatus'),
      description:      pick(cs, 'description'),

      title:            profile ? profile.title : null,
      maxScore:         max,
      rank:             profile ? profile.rank : null,
      tier:             profile ? profile.tier : null,
      service:          profile ? profile.service : null,
      actionType:       profile ? profile.actionType : null,
      actionUrl:        profile ? profile.actionUrl : null,
      remediation:      profile ? profile.remediation : null,
      remediationImpact: profile ? profile.remediationImpact : null,
      userImpact:       profile ? profile.userImpact : null,
      implementationCost: profile ? profile.implementationCost : null,
      threats:          profile ? profile.threats : [],
      deprecated:       profile ? profile.deprecated : false,
      controlState:     profile ? profile.controlState : null,

      /*
       * Points still on the table for this control. Null — not zero — whenever
       * either half is unknown, because "no gap" and "gap unknown" rank
       * differently in a remediation list and must not sort together.
       */
      gap: (score !== null && max !== null) ? Math.max(0, Math.round((max - score) * 1000) / 1000) : null,

      raw: cs,
    });
  }

  return out;
}

// ── Fetching ───────────────────────────────────────────────────────────────

/**
 * Daily snapshots, newest first.
 *
 * $top is a page size, not a limit — Graph keeps serving via nextLink — so the
 * caller's `days` is applied after paging rather than trusted to the query.
 */
async function fetchSecureScores(config, { days = DEFAULT_SNAPSHOT_DAYS } = {}) {
  const url = graphBase(config) + '/security/secureScores?$top=' + PAGE_SIZE;
  const { items, truncated } = await getAllPages(config, url);

  const snapshots = items
    .map(mapSnapshot)
    // A snapshot with no date cannot be stored (score_date is the upsert key)
    // or trended. Dropping it is right; inventing today's date is not.
    .filter(s => s.scoreDate !== null)
    .sort((a, b) => (a.scoreDate < b.scoreDate ? 1 : -1))
    .slice(0, days);

  return { snapshots, truncated };
}

/** The control catalogue, keyed by lowercased control name for the join. */
async function fetchControlProfiles(config) {
  const url = graphBase(config) + '/security/secureScoreControlProfiles?$top=' + PAGE_SIZE;
  const { items, truncated } = await getAllPages(config, url);

  const profiles = items.map(mapProfile).filter(p => p.controlName !== null);

  const byName = new Map();
  for (const p of profiles) byName.set(p.controlName.toLowerCase(), p);

  return { profiles, byName, truncated };
}

/**
 * Everything a sync needs, in one call.
 *
 * @returns {{ snapshots, latest, controls, profileCount, truncated, warnings }}
 *
 * `controls` belongs to `latest` only — see the migration header for why
 * per-control history is not retained.
 *
 * A profile fetch that FAILS does not fail the sync. The headline score is the
 * more important half and it is already in hand by then; losing the catalogue
 * costs the remediation text, which the warning says out loud. Silently
 * returning bare controls with no explanation would look like Microsoft having
 * stopped publishing remediation advice.
 */
async function fetchAll(config, { days = DEFAULT_SNAPSHOT_DAYS } = {}) {
  const warnings = [];

  const { snapshots, truncated: snapTruncated } = await fetchSecureScores(config, { days });
  const latest = snapshots.length ? snapshots[0] : null;

  let byName = new Map();
  let profileCount = 0;
  let profTruncated = false;

  try {
    const res = await fetchControlProfiles(config);
    byName = res.byName;
    profileCount = res.profiles.length;
    profTruncated = res.truncated;
  } catch (err) {
    warnings.push('Control profiles could not be read (' + err.message +
      ') — scores were stored, but remediation guidance is missing for this sync.');
  }

  const controls = latest ? mergeControls(latest.controlScores, byName) : [];

  if (snapTruncated) warnings.push('Snapshot paging hit the page limit — older history may be incomplete.');
  if (profTruncated) warnings.push('Control profile paging hit the page limit — some controls may lack remediation guidance.');

  // Loud, because it is the one outcome that looks like success and is not: a
  // tenant whose profiles all failed to join produces a full remediation table
  // with no remediation in it.
  if (controls.length && profileCount === 0) {
    warnings.push('No control profiles were matched, so no remediation guidance is available.');
  }

  return { snapshots, latest, controls, profileCount, truncated: snapTruncated || profTruncated, warnings };
}

/**
 * Credential check.
 *
 * Reads a real record rather than just exchanging a token, because the token
 * exchange proves only the client id and secret. The three failures that
 * actually happen — delegated instead of application permission, admin consent
 * never granted, and a tenant with no scored workloads — all produce a
 * perfectly good token and then fail or come back empty on the first read.
 *
 * Reports what it SAW, for the same reason the Acronis test does: an operator
 * told "connected, but Microsoft has published no snapshots for this tenant"
 * knows to check licensing now, rather than waiting a week for a gauge that
 * will never fill.
 */
async function testConnection(config) {
  const url = graphBase(config) + '/security/secureScores?$top=1';
  const page = await authGet(config, url);
  const items = arr(page && page.value);

  if (!items.length) {
    return {
      ok: true,
      snapshotCount: 0,
      latest: null,
      message: 'Connected, but Microsoft has published no Secure Score snapshots ' +
               'for this tenant yet. That is normal for a tenant provisioned in ' +
               'the last 24-48 hours; otherwise check that the tenant has ' +
               'licensed workloads Secure Score can assess.',
    };
  }

  const snap = mapSnapshot(items[0]);
  const pct = percentage(snap.currentScore, snap.maxScore);

  /*
   * The Azure tenant id is echoed so the operator can eyeball it against the
   * client they think they are configuring. A partner credential pointed at the
   * wrong directory connects flawlessly and reports somebody else's posture,
   * and nothing else in this flow would catch it.
   */
  return {
    ok: true,
    snapshotCount: items.length,
    azureTenantId: snap.azureTenantId,
    latest: {
      scoreDate:    snap.scoreDate,
      currentScore: snap.currentScore,
      maxScore:     snap.maxScore,
      percentage:   pct,
      controlCount: snap.controlScores.length,
    },
    message: 'Connection successful. Latest snapshot ' + (snap.scoreDate || 'undated') +
             ': ' + (snap.currentScore === null ? '?' : snap.currentScore) +
             '/' + (snap.maxScore === null ? '?' : snap.maxScore) +
             (pct === null ? '' : ' (' + pct + '%)') +
             ' across ' + snap.controlScores.length + ' control(s). ' +
             'Directory ' + (snap.azureTenantId || 'unknown') +
             ' — check this is the right client before enabling.',
  };
}

module.exports = {
  fetchAll,
  fetchSecureScores,
  fetchControlProfiles,
  testConnection,

  // Shared with lib/integrations/ms-identity.js, which reads further Graph and
  // Office 365 Management Activity resources with the same app registration.
  authGet,
  authRequest,
  getAllPages,
  graphBase,
  authorityBase,

  // Exported for tests. The join and the null handling are the parts most
  // likely to be wrong, and they must be assertable without a live tenant.
  mapSnapshot,
  mapProfile,
  mergeControls,
  readControlState,
  percentage,
  graphScope,
  pick,
  num,

  DEFAULT_GRAPH_BASE,
  DEFAULT_AUTHORITY,
  DEFAULT_SNAPSHOT_DAYS,

  _invalidateToken: invalidateToken,
};
