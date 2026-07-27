'use strict';

// Arctic Wolf deck metrics — supplies the Overview tiles the dashboard cannot
// derive from its own data (Observations, Investigations, Secure Culture Score).
//
// Sits above the transport in ./arctic-wolf-reports.js (generate -> poll ->
// presigned download), which it reaches through fetchReportBody().

const reports = require('./arctic-wolf-reports');

const PROVIDER = 'arctic_wolf_reports';

/* ════════════════════════════════════════════════════════════════════════════
 * Report -> metric mapping.
 *
 * One report can supply several tiles, so this is keyed by report, not by metric.
 * `provides` is documentation and drives the "which tiles are still unmapped"
 * warning; `extract` does the actual work and returns { metricId: value }.
 *
 * TODO(arctic-wolf-metrics): the exact column headers / JSON keys of
 * MONTHLY_EXECUTIVE_TICKET_SUMMARY are not yet confirmed, so extraction matches
 * headers by regex rather than by fixed name — the same tolerant approach the
 * CSV parsers in lib/awareness-parser.js and lib/vuln-parser.js already use.
 * Once the real shape is known, tighten FIELD_PATTERNS (or replace extract()).
 * Use `POST /api/reports/metrics/sync?debug=1` to see the raw payload.
 *
 * Also unconfirmed: the `period` request shape. See periodSpec() below.
 * ════════════════════════════════════════════════════════════════════════════ */

// Ordered most- to least-specific: the first pattern that matches a header wins,
// and each metric claims at most one column.
const FIELD_PATTERNS = {
  observations:      [/^observations?$/i, /data\s*points?/i, /observations?/i, /telemetry/i],
  investigations:    [/^investigations?$/i, /investigations?/i, /examined/i],
  ticketedIncidents: [/ticketed\s*incidents?/i, /^incidents?$/i, /escalat/i],
  openTickets:       [/open\s*tickets?/i, /tickets?\s*open/i],
};

const REPORT_SOURCES = [
  {
    reportType: 'MONTHLY_EXECUTIVE_TICKET_SUMMARY',
    fileFormat: 'CSV',
    scope:      'TENANT',
    provides:   ['observations', 'investigations', 'ticketedIncidents', 'openTickets'],
    extract:    extractSummary,
  },
  {
    // Still unmapped — the Secure Culture Score is not part of the ticket summary.
    reportType: null,
    fileFormat: 'CSV',
    scope:      'TENANT',
    provides:   ['cultureScore'],
    extract:    () => ({}),
  },
];

/** Every tile this module is expected to be able to supply. */
const ALL_METRICS = REPORT_SOURCES.reduce((acc, r) => acc.concat(r.provides), []);

/** Build the period object for a 'YYYY-MM' period string. */
function periodSpec(period) {
  // TODO(arctic-wolf-metrics): confirm against the API docs. The alternatives
  // seen on this API are an explicit { startDate, endDate } pair, or
  // { periodType: 'PREVIOUS_MONTH' } with no explicit month.
  return { periodType: 'MONTH', month: period };
}

// ── Payload parsing ─────────────────────────────────────────────────────────

/** RFC 4180 row splitter (quoted fields may contain commas). */
function splitCsvRow(line) {
  const out = [];
  let cur = '', inQuote = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuote) {
      if (ch === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (ch === '"') { inQuote = false; }
      else { cur += ch; }
    } else {
      if (ch === '"') { inQuote = true; }
      else if (ch === ',') { out.push(cur); cur = ''; }
      else { cur += ch; }
    }
  }
  out.push(cur);
  return out;
}

/** Strip thousands separators / units so '223,000,000' and '223 M' both parse. */
function cleanValue(raw) {
  const s = String(raw == null ? '' : raw).trim();
  if (!s || /^(n\/?a|-|—)$/i.test(s)) return null;
  return s;
}

/**
 * Flatten an arbitrary JSON payload into { lowercased leaf key: value }, so a
 * nested response is matchable by the same patterns as CSV headers.
 */
function flattenJson(obj, out = {}, depth = 0) {
  if (!obj || typeof obj !== 'object' || depth > 6) return out;
  if (Array.isArray(obj)) {
    // For arrays of records, the last entry is the most recent period.
    if (obj.length) flattenJson(obj[obj.length - 1], out, depth + 1);
    return out;
  }
  Object.keys(obj).forEach(k => {
    const v = obj[k];
    if (v && typeof v === 'object') flattenJson(v, out, depth + 1);
    else if (v != null && out[k.toLowerCase()] === undefined) out[k.toLowerCase()] = v;
  });
  return out;
}

/** Match a { key: value } bag against FIELD_PATTERNS. */
function matchFields(bag) {
  const keys  = Object.keys(bag);
  const taken = new Set();
  const out   = {};

  Object.keys(FIELD_PATTERNS).forEach(metricId => {
    for (const re of FIELD_PATTERNS[metricId]) {
      const key = keys.find(k => !taken.has(k) && re.test(k));
      if (key === undefined) continue;
      const val = cleanValue(bag[key]);
      if (val === null) continue;
      taken.add(key);
      out[metricId] = val;
      return;
    }
  });

  return out;
}

/**
 * Extract tile values from a MONTHLY_EXECUTIVE_TICKET_SUMMARY payload.
 * Accepts JSON or a header+row CSV; returns { metricId: value } (possibly empty).
 */
function extractSummary(body) {
  const text = String(body == null ? '' : body).trim();
  if (!text) return {};

  // JSON first — the API can return either depending on fileFormat.
  if (text[0] === '{' || text[0] === '[') {
    try { return matchFields(flattenJson(JSON.parse(text))); }
    catch (_) { /* fall through to CSV */ }
  }

  const lines = text.split(/\r?\n/).filter(l => l.trim().length > 0);
  if (lines.length < 2) return {};

  const headers = splitCsvRow(lines[0]).map(h => h.trim());

  // Wide form: one header row, one (or more) data rows — use the last, which is
  // the most recent period in every Arctic Wolf export seen so far.
  const cells = splitCsvRow(lines[lines.length - 1]);
  const wide  = {};
  headers.forEach((h, i) => { if (h) wide[h.toLowerCase()] = cells[i]; });
  const fromWide = matchFields(wide);
  if (Object.keys(fromWide).length) return fromWide;

  // Tall form: a two-column metric/value sheet.
  if (headers.length <= 3) {
    const tall = {};
    lines.slice(1).forEach(l => {
      const c = splitCsvRow(l);
      const name = (c[0] || '').trim();
      if (name) tall[name.toLowerCase()] = c[1];
    });
    return matchFields(tall);
  }

  return {};
}

// ── Credentials ─────────────────────────────────────────────────────────────

/** Load and decrypt the tenant's Reports API credentials, or null if absent. */
async function loadConfig(pool, tenantId, decrypt) {
  const { rows } = await pool.query(
    `SELECT base_url, api_key_enc, api_key_iv, config_json
       FROM integrations
      WHERE tenant_id = $1 AND provider = $2 AND is_enabled = TRUE`,
    [tenantId, PROVIDER]
  );
  if (!rows.length) return null;
  const row = rows[0];
  return {
    base_url:         row.base_url,
    api_key:          decrypt(row.api_key_enc, row.api_key_iv),
    organizationUuid: (row.config_json || {}).organizationUuid,
  };
}

/**
 * Read the cached Arctic Wolf metrics for a tenant + period out of report_metrics.
 * Returns {} when the table is absent (migration not yet run) or empty.
 */
async function readCached(pool, tenantId, period) {
  try {
    const { rows } = await pool.query(
      `SELECT metric_id, value, updated_at
         FROM report_metrics
        WHERE tenant_id = $1 AND period = $2 AND source = 'arctic_wolf'`,
      [tenantId, period]
    );
    const out = {};
    rows.forEach(r => {
      if (r.value != null && r.value !== '') {
        out[r.metric_id] = { value: r.value, fetchedAt: r.updated_at };
      }
    });
    return out;
  } catch (_) { return {}; }
}

// ── Public API ──────────────────────────────────────────────────────────────

/**
 * Fetch the deck metrics that only Arctic Wolf can supply.
 *
 * MUST NOT throw and MUST NOT block report generation — it returns whatever it
 * has plus warnings explaining any gaps.
 *
 * `refresh` defaults to false so interactive report generation reads the cache
 * instead of blocking on the API's poll window (up to 120s per report). Live
 * fetching belongs in syncDeckMetrics().
 *
 * @param   {object}   deps
 * @param   {import('pg').Pool} deps.pool
 * @param   {number}   deps.tenantId
 * @param   {string}   deps.period      'YYYY-MM'
 * @param   {(enc: string, iv: string) => string} deps.decrypt
 * @param   {boolean} [deps.refresh]    force a live API call
 * @param   {boolean} [deps.debug]      include the raw payload in the result
 * @returns {Promise<{ metrics: Object<string, {value: string, fetchedAt: any}>,
 *                     warnings: string[], raw?: Object<string, string> }>}
 */
async function fetchDeckMetrics(deps) {
  const { pool, tenantId, period, decrypt, refresh = false, debug = false } = deps;
  const warnings = [];
  const raw = {};

  const metrics = await readCached(pool, tenantId, period);

  const unmapped = REPORT_SOURCES
    .filter(r => !r.reportType)
    .reduce((acc, r) => acc.concat(r.provides), [])
    .filter(m => !metrics[m]);
  if (unmapped.length) {
    warnings.push(
      'No Arctic Wolf report is mapped yet for: ' + unmapped.join(', ') +
      '. Enter these manually.'
    );
  }

  if (!refresh) return { metrics, warnings };

  let config;
  try {
    config = await loadConfig(pool, tenantId, decrypt);
  } catch (err) {
    warnings.push('Could not read Arctic Wolf Reports credentials: ' + err.message);
    return { metrics, warnings };
  }
  if (!config) {
    warnings.push('No enabled Arctic Wolf Reports integration for this client.');
    return { metrics, warnings };
  }

  for (const src of REPORT_SOURCES) {
    if (!src.reportType) continue;
    try {
      const body = await reports.fetchReportBody(config, {
        reportType: src.reportType,
        period:     periodSpec(period),
        scope:      src.scope || 'TENANT',
        fileFormat: src.fileFormat || 'CSV',
      });

      if (debug) raw[src.reportType] = String(body == null ? '' : body).slice(0, 4000);

      const found = src.extract(body);
      const names = Object.keys(found);
      if (!names.length) {
        warnings.push(
          `${src.reportType} returned no recognisable columns. Run the sync with ` +
          '?debug=1 to inspect the payload and tighten the field mapping.'
        );
        continue;
      }
      names.forEach(id => {
        metrics[id] = { value: String(found[id]), fetchedAt: new Date().toISOString() };
      });

      const missing = src.provides.filter(m => !metrics[m]);
      if (missing.length) {
        warnings.push(`${src.reportType} did not supply: ${missing.join(', ')}.`);
      }
    } catch (err) {
      if (err.stillGenerating) {
        warnings.push(`${src.reportType} is still generating — try the sync again shortly.`);
      } else {
        warnings.push(`${src.reportType} fetch failed: ${err.message}`);
      }
    }
  }

  return debug ? { metrics, warnings, raw } : { metrics, warnings };
}

/**
 * Warm report_metrics with a live fetch. Called by the scheduled sync and by the
 * manual sync route — never during interactive report generation, because the
 * API poll can take up to two minutes per report.
 * Returns the number of metrics written.
 */
async function syncDeckMetrics(deps) {
  const { pool, tenantId, period } = deps;
  const result = await fetchDeckMetrics({ ...deps, refresh: true });
  const { metrics, warnings } = result;

  let written = 0;
  for (const [metricId, m] of Object.entries(metrics)) {
    try {
      await pool.query(
        `INSERT INTO report_metrics (tenant_id, period, metric_id, value, source, updated_at)
              VALUES ($1, $2, $3, $4, 'arctic_wolf', NOW())
         ON CONFLICT (tenant_id, period, metric_id, source)
           DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
        [tenantId, period, metricId, m.value]
      );
      written++;
    } catch (err) {
      warnings.push(`Could not persist ${metricId}: ${err.message}`);
    }
  }

  return { written, metrics, warnings, raw: result.raw };
}

module.exports = {
  REPORT_SOURCES,
  FIELD_PATTERNS,
  ALL_METRICS,
  extractSummary,
  fetchDeckMetrics,
  syncDeckMetrics,
};
