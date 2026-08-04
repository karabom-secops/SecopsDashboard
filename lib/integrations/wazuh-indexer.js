'use strict';

/**
 * Wazuh Indexer (OpenSearch) adapter.
 *
 * Base URL is the indexer, e.g. https://wazuh.example.com:9200
 * Auth: HTTP Basic — username from config_json.username, password is the
 * encrypted api_key on the integration row.
 *
 * We talk to the Indexer only; the Manager API (:55000) is deliberately not
 * used. Everything the Managed NDR and Managed Office 365 screens need lives in
 * the wazuh-alerts-4.x-* indices as decoded FortiGate, office365 and ms-graph
 * events.
 *
 * Endpoints used:
 *   GET  /                                        — version, connectivity
 *   GET  /_cat/indices/wazuh-alerts-4.x-*         — is anything being written
 *   GET  /wazuh-alerts-4.x-* /_field_caps          — which timestamp field exists
 *   POST /wazuh-alerts-4.x-* /_msearch             — every dashboard query
 */

const https  = require('https');
const http   = require('http');
const crypto = require('crypto');
const { URL } = require('url');

const F = require('./wazuh-fields');

const REQ_TIMEOUT = 30000;

// ignore_unavailable alone is not enough: allow_no_indices is what saves you
// when the wildcard matches nothing at all (a brand-new Wazuh, or every index
// rolled away). With both set you get an empty result instead of a 404.
const SEARCH_FLAGS = 'ignore_unavailable=true&allow_no_indices=true&rest_total_hits_as_int=true';

/** Defaults merged over config_json so every caller sees a complete config. */
function normaliseConfig(config) {
  const cfg = config || {};
  return {
    base_url:    cfg.base_url,
    api_key:     cfg.api_key,
    username:    cfg.username || 'admin',
    tsField:     cfg.tsField  || 'timestamp',
    timeZone:    cfg.timeZone || 'UTC',
    multiTenant: cfg.multiTenant === true,
    scope:       cfg.scope || {},
    preference:  cfg.preference || null,
    tlsFingerprint: cfg.tlsFingerprint || null,
  };
}

function authHeader(cfg) {
  return 'Basic ' + Buffer.from(`${cfg.username}:${cfg.api_key}`).toString('base64');
}

/**
 * One HTTP round trip to the indexer.
 *
 * `rejectUnauthorized: false` — self-hosted indexers almost always present a
 * self-signed cert. We compensate by capturing the cert fingerprint so a change
 * is at least visible (see fingerprintOf/warnOnFingerprintChange).
 */
function request(cfg, method, path, body, contentType) {
  return new Promise((resolve, reject) => {
    let fullUrl;
    try {
      fullUrl = new URL(path, cfg.base_url);
    } catch (_) {
      return reject(new Error(`Invalid Wazuh Indexer URL: ${cfg.base_url}`));
    }
    const lib = fullUrl.protocol === 'https:' ? https : http;

    const headers = {
      'Authorization': authHeader(cfg),
      'Accept':        'application/json',
      'User-Agent':    'SecOpsDashboard/1.0',
    };
    let payload = null;
    if (body !== undefined && body !== null) {
      payload = Buffer.from(body, 'utf8');
      headers['Content-Type']   = contentType || 'application/json';
      // byteLength, not .length — attack names and UPNs can be non-ASCII.
      headers['Content-Length'] = payload.length;
    }

    const req = lib.request({
      hostname: fullUrl.hostname,
      port:     fullUrl.port || (fullUrl.protocol === 'https:' ? 443 : 80),
      path:     fullUrl.pathname + fullUrl.search,
      method,
      headers,
      rejectUnauthorized: false,
      timeout: REQ_TIMEOUT,
    }, res => {
      let raw = '';
      res.setEncoding('utf8');
      res.on('data', c => { raw += c; });
      res.on('end', () => {
        if (res.statusCode === 401 || res.statusCode === 403) {
          return reject(Object.assign(
            new Error(`Wazuh Indexer rejected the credentials (${res.statusCode}). Check the username and password.`),
            { notPermitted: true }
          ));
        }
        if (res.statusCode >= 400) {
          let detail = raw.slice(0, 300);
          try {
            const p = JSON.parse(raw);
            if (p.error) detail = p.error.reason || p.error.type || detail;
          } catch (_) { /* keep the raw slice */ }
          return reject(new Error(`Wazuh Indexer ${res.statusCode}: ${detail}`));
        }
        try {
          const parsed = JSON.parse(raw);
          parsed.__fingerprint = fingerprintOf(res);
          resolve(parsed);
        } catch (_) {
          reject(new Error('Wazuh Indexer returned invalid JSON'));
        }
      });
    });

    req.on('error', err => reject(new Error(`Wazuh Indexer unreachable: ${err.message}`)));
    req.on('timeout', () => { req.destroy(); reject(new Error('Wazuh Indexer request timed out')); });
    if (payload) req.write(payload);
    req.end();
  });
}

function fingerprintOf(res) {
  try {
    const cert = res.socket && res.socket.getPeerCertificate && res.socket.getPeerCertificate();
    if (cert && cert.raw) return crypto.createHash('sha256').update(cert.raw).digest('hex');
  } catch (_) { /* plain http, or socket already gone */ }
  return null;
}

/**
 * Costs ten lines and turns a blind spot into a detection: we cannot verify the
 * cert, but we can notice when it changes underneath us.
 */
function warnOnFingerprintChange(cfg, fingerprint) {
  if (!fingerprint) return fingerprint;
  if (cfg.tlsFingerprint && cfg.tlsFingerprint !== fingerprint) {
    console.warn(
      `[wazuh] TLS certificate for ${cfg.base_url} changed ` +
      `(${cfg.tlsFingerprint.slice(0, 16)}… → ${fingerprint.slice(0, 16)}…). ` +
      'Verify this was an intentional renewal.'
    );
  }
  return fingerprint;
}

// ── _msearch ───────────────────────────────────────────────────────────────

/**
 * Run several searches in one round trip.
 *
 * NDJSON: alternating header and body line, each JSON on exactly one line,
 * terminated by a trailing newline (without it the indexer answers 400).
 * JSON.stringify never emits a raw newline, so join('\n') is safe.
 *
 * IMPORTANT: _msearch answers HTTP 200 even when individual sub-searches fail —
 * a `statusCode >= 400` check is not sufficient. Each entry is inspected and a
 * failure is turned into an unavailable panel rather than a dead screen.
 *
 * @param {Array<{name:string, body:object}>} searches
 * @returns {Promise<Object<string, {ok:boolean, result?:object, error?:string}>>}
 */
async function msearch(cfg, searches) {
  if (!searches.length) return {};

  const header = {
    index: F.ALERTS_INDEX,
    ignore_unavailable: true,
    allow_no_indices: true,
  };
  if (cfg.preference) header.preference = cfg.preference;

  const lines = [];
  searches.forEach(s => {
    lines.push(JSON.stringify(header));
    lines.push(JSON.stringify(s.body));
  });
  const ndjson = lines.join('\n') + '\n';

  // Bounded concurrency so one dashboard load cannot saturate the indexer's
  // search thread pool — Wazuh Indexer nodes are usually undersized.
  const res = await request(
    cfg, 'POST',
    `/${F.ALERTS_INDEX}/_msearch?${SEARCH_FLAGS}&max_concurrent_searches=4`,
    ndjson, 'application/x-ndjson'
  );
  warnOnFingerprintChange(cfg, res.__fingerprint);

  const responses = Array.isArray(res.responses) ? res.responses : [];
  const out = {};
  searches.forEach((s, i) => {
    const r = responses[i];
    if (!r) {
      out[s.name] = { ok: false, error: 'No response returned for this search.' };
    } else if (r.error) {
      out[s.name] = { ok: false, error: r.error.reason || r.error.type || 'Search failed.' };
    } else {
      out[s.name] = { ok: true, result: r };
    }
  });
  return out;
}

// ── Panel envelopes ────────────────────────────────────────────────────────

/**
 * Every panel is returned as an envelope, never a bare array. The distinction
 * between "this module is not ingesting" and "no events matched in this window"
 * matters operationally — rendering both as 0 tells the customer they had no
 * failed logins when the truth may be that we are blind to them.
 */
function panel(available, data, reason, lastEventAt) {
  return { available, data: data || null, reason: reason || null, lastEventAt: lastEventAt || null };
}

function unavailable(reason) { return panel(false, null, reason, null); }

/** Turn an msearch entry into an envelope, given a shaping function. */
function envelope(entry, shape) {
  if (!entry)     return unavailable('query_error');
  if (!entry.ok)  return unavailable('query_error');

  const res   = entry.result;
  const total = totalHits(res);
  const last  = lastEventOf(res.aggregations);

  if (total === 0) return panel(true, shape ? shape(res) : null, 'no_data_in_range', last);
  return panel(true, shape ? shape(res) : null, null, last);
}

function totalHits(res) {
  const t = res && res.hits && res.hits.total;
  return typeof t === 'number' ? t : (t && t.value) || 0;
}

function lastEventOf(aggs) {
  if (!aggs) return null;
  const direct = aggs.last_event;
  if (direct && direct.value_as_string) return direct.value_as_string;
  // Some bodies nest last_event under a filter agg.
  for (const k of Object.keys(aggs)) {
    const v = aggs[k];
    if (v && v.last_event && v.last_event.value_as_string) return v.last_event.value_as_string;
  }
  return null;
}

// ── Bucket shaping ─────────────────────────────────────────────────────────

const bucketsOf = agg => (agg && Array.isArray(agg.buckets) ? agg.buckets : []);
const countOf   = agg => (agg && typeof agg.doc_count === 'number' ? agg.doc_count : 0);
const valueOf   = agg => (agg && typeof agg.value === 'number' ? agg.value : 0);

/** terms buckets → [{ label, count, ... }] */
function tally(agg, extra) {
  return bucketsOf(agg).map(b => Object.assign(
    { label: String(b.key), count: b.doc_count },
    extra ? extra(b) : {}
  ));
}

/** first sub-bucket key of a nested terms agg, or null */
function firstKey(agg) {
  const b = bucketsOf(agg);
  return b.length ? String(b[0].key) : null;
}

/** date_histogram buckets → [{ date: 'YYYY-MM-DD', count, ...series }] */
function series(agg, extra) {
  return bucketsOf(agg).map(b => Object.assign(
    { date: String(b.key_as_string || '').slice(0, 10), count: b.doc_count },
    extra ? extra(b) : {}
  ));
}

/** top_hits sub-agg → the flattened _source rows */
function hits(agg) {
  const h = agg && agg.hits && agg.hits.hits;
  return Array.isArray(h) ? h.map(x => x._source) : [];
}

/**
 * Merge the parallel `by_<field>` terms aggs that stand in for a coalesced
 * runtime field — the Wazuh Indexer does not accept `runtime_mappings`, so
 * wazuh-fields.js buckets each candidate field separately and we combine here.
 *
 * A given document only populates one of the fields, so summing counts per
 * label is correct rather than double-counting.
 */
function mergeTallies(parent, prefix, limit) {
  if (!parent) return [];
  const acc = new Map();

  Object.keys(parent).forEach(key => {
    if (key.indexOf(prefix) !== 0) return;
    bucketsOf(parent[key]).forEach(b => {
      const label = String(b.key);
      if (!label) return;
      const prev = acc.get(label);
      // Distinct-source counts are HLL approximations over disjoint slices;
      // the larger of the two is the honest estimate, not the sum.
      const sources = Math.max(valueOf(b.by_remip), valueOf(b.by_srcip));
      if (prev) {
        prev.count += b.doc_count;
        prev.sources = Math.max(prev.sources, sources);
        prev.reason = prev.reason || firstKey(b.reason);
      } else {
        acc.set(label, { label, count: b.doc_count, sources, reason: firstKey(b.reason) });
      }
    });
  });

  const out = [...acc.values()].sort((a, b) => b.count - a.count);
  return limit ? out.slice(0, limit) : out;
}

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Verify connectivity and credentials, and work out which timestamp field this
 * cluster uses. The Wazuh template maps both `timestamp` (the alert's own time,
 * from analysisd) and `@timestamp` (Filebeat ingest time); the Wazuh Dashboard
 * uses `timestamp`, so we prefer it but never assume it.
 */
async function testConnection(config) {
  const cfg  = normaliseConfig(config);
  if (!cfg.base_url) throw new Error('Indexer URL is required.');
  if (!cfg.api_key)  throw new Error('Password is required.');

  const root = await request(cfg, 'GET', '/');
  const fingerprint = warnOnFingerprintChange(cfg, root.__fingerprint);
  const version = (root.version && root.version.number) || 'unknown';
  const distribution = (root.version && root.version.distribution) || 'opensearch';

  let indices = 0;
  try {
    const cat = await request(cfg, 'GET', `/_cat/indices/${F.ALERTS_INDEX}?format=json&h=index`);
    indices = Array.isArray(cat) ? cat.length : 0;
  } catch (_) {
    // A read-only role without cluster:monitor still lets us search — not fatal.
    indices = null;
  }

  const tsField = await detectTsField(cfg);

  return {
    ok: true,
    version,
    distribution,
    indices,
    tsField,
    tlsFingerprint: fingerprint,
    message: indices === 0
      ? `Connected to ${distribution} ${version}, but no ${F.ALERTS_INDEX} indices exist yet.`
      : `Connected to ${distribution} ${version}.`,
  };
}

async function detectTsField(cfg) {
  try {
    const caps = await request(
      cfg, 'GET',
      `/${F.ALERTS_INDEX}/_field_caps?fields=timestamp,@timestamp&ignore_unavailable=true&allow_no_indices=true`
    );
    const fields = caps.fields || {};
    if (fields['timestamp'])  return 'timestamp';
    if (fields['@timestamp']) return '@timestamp';
  } catch (_) { /* fall through to the default */ }
  return 'timestamp';
}

/**
 * Which sources are actually ingesting. Run on save and hourly, never on page
 * load — the answer drives whether a panel renders a chart or a reasoned
 * placeholder, and it changes on the order of days, not seconds.
 */
async function detectModules(config) {
  const cfg   = normaliseConfig(config);
  const range = { from: 'now-7d', to: 'now' };

  const searches = F.SOURCES.map(src => {
    let body;
    try {
      body = F.probeSearch(src, cfg, range);
    } catch (err) {
      // A scope-guard failure for one source must not blind the others.
      body = null;
      console.warn(`[wazuh] probe skipped for ${src}: ${err.message}`);
    }
    return body ? { name: src, body } : null;
  }).filter(Boolean);

  const res = await msearch(cfg, searches);

  const detected = { probedAt: new Date().toISOString() };
  F.SOURCES.forEach(src => {
    const entry = res[src];
    if (!entry || !entry.ok) {
      detected[src] = { ingesting: false, events: 0, error: entry ? entry.error : 'not probed' };
      return;
    }
    const total = totalHits(entry.result);
    detected[src] = {
      ingesting: total > 0,
      events: total,
      lastEventAt: lastEventOf(entry.result.aggregations),
    };
    if (src === 'ms-graph') {
      const rels = bucketsOf(entry.result.aggregations && entry.result.aggregations.relationships)
        .map(b => String(b.key));
      detected[src].relationships = rels;
      detected[src].alerts     = rels.includes('alerts_v2');
      detected[src].riskyUsers = rels.includes('riskyUsers');
      detected[src].signIns    = rels.includes('signIns');
    }
  });

  return detected;
}

/**
 * Managed NDR data — FortiGate traffic, IPS threats, geo and VPN/admin.
 * Every panel comes back as an envelope; `_partial` names the panels that
 * failed so the caller can surface a reason instead of a zero.
 */
async function fetchNdr(config, opts) {
  const cfg   = normaliseConfig(config);
  const range = { from: opts.from, to: opts.to };
  if (opts.tz) cfg.timeZone = opts.tz;

  const searches = [];
  const skipped  = {};
  const add = (name, build) => {
    try { searches.push({ name, body: build(cfg, range) }); }
    catch (err) { skipped[name] = err.message; }
  };

  add('traffic',  F.ndrTraffic);
  add('threats',  F.ndrThreats);
  add('geo',      F.ndrGeo);
  add('vpnAdmin', F.ndrVpnAdmin);

  const res = await msearch(cfg, searches);
  const partial = [];
  const take = (name) => {
    if (skipped[name]) { partial.push(name); return unavailable('not_permitted'); }
    if (!res[name] || !res[name].ok) { partial.push(name); return unavailable('query_error'); }
    return null;
  };

  const out = {};

  // ── traffic ──
  out.traffic = take('traffic') || envelope(res.traffic, r => {
    const a = r.aggregations || {};
    return {
      allowed: countOf(a.total_allowed),
      denied:  countOf(a.total_denied),
      trend: series(a.over_time, b => ({
        allowed: countOf(b.decision && b.decision.buckets && b.decision.buckets.allowed),
        denied:  countOf(b.decision && b.decision.buckets && b.decision.buckets.denied),
        sources: valueOf(b.unique_sources),
      })),
      topPorts:    tally(a.top_dst_port, b => ({ service: firstKey(b.service) })),
      topServices: tally(a.top_service),
      topPolicies: tally(a.top_policy, b => ({ name: firstKey(b.name) })),
      topSources:  tally(a.top_src, b => ({ country: firstKey(b.country) })),
      topTargets:  tally(a.top_dst),
    };
  });

  // ── threats ──
  out.threats = take('threats') || envelope(res.threats, r => {
    const a   = r.aggregations || {};
    const ips = a.ips || {};
    return {
      total:   countOf(ips),
      blocked: countOf(ips.blocked),
      allowed: countOf(ips.allowed),
      uniqueSources: valueOf(ips.unique_sources),
      topAttacks: tally(ips.top_attacks, b => ({
        severity: firstKey(b.severity),
        blocked:  countOf(b.blocked),
        allowed:  countOf(b.allowed),
        targets:  valueOf(b.targets),
      })),
      bySeverity: tally(ips.by_severity),
      byAction:   tally(ips.by_action),
      topSources: tally(ips.top_sources, b => ({ country: firstKey(b.country) })),
      topTargets: tally(ips.top_targets),
      trend: series(ips.trend, b => ({ blocked: countOf(b.blocked) })),
      virus:     { total: countOf(a.virus),     top: tally(a.virus && a.virus.top) },
      webfilter: { total: countOf(a.webfilter), top: tally(a.webfilter && a.webfilter.top_category) },
      appctrl:   { total: countOf(a.appctrl),   top: tally(a.appctrl && a.appctrl.top_app, b => ({ category: firstKey(b.category) })) },
    };
  });

  // ── geo ──
  out.geo = take('geo') || envelope(res.geo, r => {
    const a = r.aggregations || {};
    const primary = tally(a.by_country && a.by_country.countries, b => ({
      sources: valueOf(b.unique_sources),
      denied:  countOf(b.denied),
    }));
    // FortiOS emits srccountry itself; GeoLocation.* needs an ingest processor
    // that is off by default, so it is only ever a fallback.
    if (primary.length) return { countries: primary, source: 'fortigate' };
    return { countries: tally(a.by_geoip), source: 'geoip' };
  });

  // ── vpn + admin ──
  out.vpnAdmin = take('vpnAdmin') || envelope(res.vpnAdmin, r => {
    const a     = r.aggregations || {};
    const vpn   = a.vpn   || {};
    const admin = a.admin || {};
    const outcome = (vpn.outcome && vpn.outcome.buckets) || {};
    const logins  = admin.logins || {};
    const changes = admin.config_changes || {};
    return {
      vpn: {
        total:   countOf(vpn),
        success: countOf(outcome.success),
        failed:  countOf(outcome.failed),
        failedUsers: mergeTallies(vpn.failed_users, 'by_', 10),
        trend: series(vpn.trend, b => ({ failed: countOf(b.failed) })),
      },
      admin: {
        logins:       countOf(logins),
        failedLogins: countOf(logins.failed),
        topAdmins:    tally(logins.by_user, b => ({ via: firstKey(b.via) })),
        configChanges: countOf(changes),
        changesByPath: tally(changes.by_path),
        changesByAdmin: tally(changes.by_admin),
      },
    };
  });

  out._partial = partial;
  return out;
}

/**
 * Managed Office 365 data — the office365 wodle plus whatever ms-graph offers.
 * The two halves are independent: ms-graph needs a separate Azure app
 * registration with admin consent, so expect it absent more often than present
 * and never let that blank the O365 half.
 */
async function fetchO365(config, opts) {
  const cfg   = normaliseConfig(config);
  const range = { from: opts.from, to: opts.to };
  if (opts.tz) cfg.timeZone = opts.tz;

  const searches = [];
  const skipped  = {};
  const add = (name, build) => {
    try { searches.push({ name, body: build(cfg, range) }); }
    catch (err) { skipped[name] = err.message; }
  };

  add('o365',  F.o365Main);
  add('graph', F.o365Graph);

  const res = await msearch(cfg, searches);
  const partial = [];
  const failed = (name) => {
    if (skipped[name]) { partial.push(name); return unavailable('not_permitted'); }
    if (!res[name] || !res[name].ok) { partial.push(name); return unavailable('query_error'); }
    return null;
  };

  const out = {};
  const o365Bad  = failed('o365');
  const graphBad = failed('graph');

  const shapeO365 = r => {
    const a  = r.aggregations || {};
    const si = a.signins || {};
    const fl = a.failed_logins || {};
    const ac = a.admin_changes || {};
    const mr = a.mailbox_rules || {};
    const sh = a.external_sharing || {};
    const dl = a.dlp || {};

    // ClientIP arrives with and without a :port suffix — merge before counting.
    const byIp = F.mergeBuckets(bucketsOf(fl.by_ip), F.normaliseClientIp)
      .slice(0, 15)
      .map(b => ({
        label: b.key,
        count: b.doc_count,
        targetedUsers: valueOf(b.targeted_users),
        // A single source hitting many distinct accounts is the password-spray
        // shape; flag it rather than making the reader eyeball the table.
        spray: valueOf(b.targeted_users) > 5,
      }));

    return {
      signins: {
        success: countOf(si.total_success),
        failed:  countOf(si.total_failed),
        uniqueUsers: valueOf(si.unique_users),
        trend: series(si.over_time, b => ({
          success: countOf(b.success),
          failed:  countOf(b.failed),
          users:   valueOf(b.users),
        })),
      },
      failedLogins: {
        byReason: tally(fl.by_reason),
        byUser:   tally(fl.by_user, b => ({ distinctIps: valueOf(b.distinct_ips) })),
        byIp,
      },
      admin: {
        total:       countOf(ac),
        byOperation: tally(ac.by_operation),
        byActor:     tally(ac.by_actor),
        recent: hits(ac.recent).map(s => ({
          when:      s[cfg.tsField],
          operation: deep(s, 'data.office365.Operation'),
          actor:     deep(s, 'data.office365.UserId'),
          target:    deep(s, 'data.office365.TargetUserOrGroupName'),
          clientIp:  F.normaliseClientIp(deep(s, 'data.office365.ClientIP')),
          ok:        F.resultOk(deep(s, 'data.office365.ResultStatus')),
        })),
      },
      mailboxRules: {
        total:       countOf(mr),
        byOperation: tally(mr.by_operation),
        byMailbox:   tally(mr.by_mailbox),
        recent: hits(mr.recent).map(s => ({
          when:      s[cfg.tsField],
          operation: deep(s, 'data.office365.Operation'),
          mailbox:   deep(s, 'data.office365.MailboxOwnerUPN'),
          actor:     deep(s, 'data.office365.UserId'),
          clientIp:  F.normaliseClientIp(deep(s, 'data.office365.ClientIPAddress')),
        })),
      },
      sharing: {
        total:       countOf(sh),
        byOperation: tally(sh.by_operation),
        bySite:      tally(sh.by_site),
        byUser:      tally(sh.by_user),
      },
      dlp: {
        total:      countOf(dl),
        byPolicy:   tally(dl.by_policy),
        byInfoType: tally(dl.by_info_type),
        trend:      series(dl.trend),
      },
      byWorkload: tally(a.by_workload),
    };
  };

  const shapeGraph = r => {
    const a  = r.aggregations || {};
    const al = a.alerts || {};
    const ru = a.risky_users || {};
    const rd = a.risk_detections || {};
    const si = a.signins || {};

    return {
      alerts: {
        total:       countOf(al),
        high:        countOf(al.high),
        bySeverity:  tally(al.by_severity),
        byStatus:    tally(al.by_status),
        bySource:    tally(al.by_source),
        byTechnique: tally(al.by_technique),
        trend: series(al.trend, b => ({ high: countOf(b.high) })),
        recent: hits(al.recent).map(s => ({
          when:     s[cfg.tsField],
          title:    deep(s, 'data.ms-graph.title'),
          severity: deep(s, 'data.ms-graph.severity'),
          status:   deep(s, 'data.ms-graph.status'),
          source:   deep(s, 'data.ms-graph.serviceSource'),
          category: deep(s, 'data.ms-graph.category'),
        })),
      },
      riskyUsers: {
        distinct: valueOf(ru.distinct),
        // Latest state per user — riskyUsers is a state resource that Wazuh
        // re-emits on every poll, so raw counts mean nothing.
        users: bucketsOf(ru.users).map(b => {
          const latest = hits(b.latest)[0] || {};
          return {
            label:  String(b.key),
            level:  deep(latest, 'data.ms-graph.riskLevel'),
            state:  deep(latest, 'data.ms-graph.riskState'),
            detail: deep(latest, 'data.ms-graph.riskDetail'),
            updatedAt: deep(latest, 'data.ms-graph.riskLastUpdatedDateTime'),
          };
        }),
      },
      riskDetections: { byType: tally(rd.by_type), byCountry: tally(rd.by_country) },
      signins: {
        total: countOf(si),
        byCountry: tally(si.by_country, b => ({
          failed: countOf(b.failed),
          users:  valueOf(b.users),
        })),
        legacyAuth: {
          total:  countOf(si.legacy_auth),
          byUser: tally(si.legacy_auth && si.legacy_auth.by_user),
        },
        caFailures: countOf(si.ca_failures),
      },
    };
  };

  out.o365  = o365Bad  || envelope(res.o365,  shapeO365);
  out.graph = graphBad || envelope(res.graph, shapeGraph);
  out._partial = partial;
  return out;
}

/**
 * _source comes back with dotted keys when the mapping is flat and nested
 * objects when it is not — read both shapes.
 */
function deep(src, path) {
  if (!src) return null;
  if (src[path] !== undefined) return src[path];
  let cur = src;
  for (const part of path.split('.')) {
    if (cur == null || typeof cur !== 'object') return null;
    cur = cur[part];
  }
  return cur === undefined ? null : cur;
}

module.exports = {
  testConnection,
  detectModules,
  detectTsField,
  fetchNdr,
  fetchO365,
  msearch,
  normaliseConfig,
};
