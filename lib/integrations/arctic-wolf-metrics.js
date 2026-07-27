'use strict';

// Arctic Wolf deck metrics — supplies the Overview tiles the dashboard cannot
// derive from its own data (Observations, Secure Culture Score).
//
// Sits above the transport in ./arctic-wolf-reports.js (generate -> poll ->
// presigned download), which it reaches through fetchReportBody().

const reports = require('./arctic-wolf-reports');

const PROVIDER = 'arctic_wolf_reports';

/* ════════════════════════════════════════════════════════════════════════════
 * TODO(arctic-wolf-metrics): DROP-IN POINT.
 *
 * When the Arctic Wolf Reports API docs arrive, the ONLY things that change in
 * this file are:
 *   (a) the `reportType` strings below, and
 *   (b) the `extract()` bodies.
 * Nothing outside this file needs to be touched — /api/reports/metrics already
 * speaks the tile vocabulary that fetchDeckMetrics() returns.
 *
 * Unknowns still to fill in:
 *   - the reportType enum value that yields sensor/observation volume
 *   - the reportType enum value that yields the Secure Culture score
 *   - the `period` shape: { periodType: 'MONTH', month: 'YYYY-MM' }?
 *     or explicit start/end timestamps?
 *   - fileFormat: CSV column headers, or switch to JSON
 *
 * While `reportType` is null the whole module is a working no-op: it reports the
 * gap through `warnings` and every tile falls back to derived-or-manual.
 * ════════════════════════════════════════════════════════════════════════════ */
const METRIC_REPORTS = {
  observations: {
    reportType: null,          // e.g. 'SENSOR_TELEMETRY_SUMMARY'
    fileFormat: 'CSV',
    scope:      'TENANT',
    /** @returns {string|null} the display value, e.g. '223 M' */
    extract(_body) { return null; },
  },
  cultureScore: {
    reportType: null,          // e.g. 'SECURE_CULTURE_SCORE'
    fileFormat: 'CSV',
    scope:      'TENANT',
    extract(_body) { return null; },
  },
};

/** Build the { periodType, ... } object for a 'YYYY-MM' period string. */
function periodSpec(period) {
  // TODO(arctic-wolf-metrics): confirm the real shape against the API docs.
  return { periodType: 'MONTH', month: period };
}

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

/**
 * Fetch the deck metrics that only Arctic Wolf can supply.
 *
 * MUST NOT throw and MUST NOT block report generation — it returns whatever it
 * has plus a list of warnings explaining any gaps.
 *
 * `refresh` defaults to false so interactive report generation reads the cache
 * instead of blocking on the API's 120s poll window. Live fetching belongs in
 * syncDeckMetrics(), driven by the scheduler.
 *
 * @param   {object}   deps
 * @param   {import('pg').Pool} deps.pool
 * @param   {number}   deps.tenantId
 * @param   {string}   deps.period      'YYYY-MM'
 * @param   {(enc: string, iv: string) => string} deps.decrypt
 * @param   {boolean} [deps.refresh]    force a live API call
 * @returns {Promise<{ metrics: Object<string, {value: string, fetchedAt: any}>, warnings: string[] }>}
 */
async function fetchDeckMetrics(deps) {
  const { pool, tenantId, period, decrypt, refresh = false } = deps;
  const warnings = [];

  const metrics = await readCached(pool, tenantId, period);

  const unmapped = Object.keys(METRIC_REPORTS).filter(k => !METRIC_REPORTS[k].reportType);
  if (unmapped.length) {
    warnings.push(
      'Awaiting Arctic Wolf report mapping for: ' + unmapped.join(', ') +
      '. Enter these manually until the report types are configured.'
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

  for (const [metricId, cfg] of Object.entries(METRIC_REPORTS)) {
    if (!cfg.reportType) continue;
    try {
      const body = await reports.fetchReportBody(config, {
        reportType: cfg.reportType,
        period:     periodSpec(period),
        scope:      cfg.scope || 'TENANT',
        fileFormat: cfg.fileFormat || 'CSV',
      });
      const value = cfg.extract(body);
      if (value == null || value === '') {
        warnings.push(`Arctic Wolf returned no usable value for ${metricId}.`);
        continue;
      }
      metrics[metricId] = { value: String(value), fetchedAt: new Date().toISOString() };
    } catch (err) {
      warnings.push(`Arctic Wolf ${metricId} fetch failed: ${err.message}`);
    }
  }

  return { metrics, warnings };
}

/**
 * Warm report_metrics with a live fetch. Called by the scheduled sync, never
 * from an interactive request — the API poll can take up to two minutes.
 * Returns the number of metrics written.
 */
async function syncDeckMetrics(deps) {
  const { pool, tenantId, period } = deps;
  const { metrics, warnings } = await fetchDeckMetrics({ ...deps, refresh: true });

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
  return { written, warnings };
}

module.exports = { METRIC_REPORTS, fetchDeckMetrics, syncDeckMetrics };
