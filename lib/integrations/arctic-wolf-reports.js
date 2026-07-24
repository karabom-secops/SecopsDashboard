'use strict';

// Arctic Wolf Reports API adapter
// Spec: /api/v1/organizations/{organizationUuid}/reports
// Auth: Authorization: Bearer {token}
// Servers: msp-reporting.managedgw.{region}-prod.arcticwolf.net

const https = require('https');
const http  = require('http');
const { URL } = require('url');

const ARCTIC_WOLF_REPORTS_REGIONS = {
  us001: 'https://msp-reporting.managedgw.us001-prod.arcticwolf.net',
  us002: 'https://msp-reporting.managedgw.us002-prod.arcticwolf.net',
  us003: 'https://msp-reporting.managedgw.us003-prod.arcticwolf.net',
  eu001: 'https://msp-reporting.managedgw.eu001-prod.arcticwolf.net',
  au001: 'https://msp-reporting.managedgw.au001-prod.arcticwolf.net',
  ca001: 'https://msp-reporting.managedgw.ca001-prod.arcticwolf.net',
};

module.exports.REGIONS = ARCTIC_WOLF_REPORTS_REGIONS;

function apiRequest(baseUrl, path, apiKey, method = 'GET', body = null) {
  return new Promise((resolve, reject) => {
    const fullUrl = new URL(path, baseUrl);
    const lib     = fullUrl.protocol === 'https:' ? https : http;
    const payload = body ? JSON.stringify(body) : null;
    const headers = {
      'Authorization': `Bearer ${apiKey}`,
      'Accept':        'application/json',
      'Content-Type':  'application/json',
      'User-Agent':    'SecOpsDashboard/1.0',
    };
    if (payload) headers['Content-Length'] = Buffer.byteLength(payload);

    const opts = {
      hostname: fullUrl.hostname,
      port:     fullUrl.port || (fullUrl.protocol === 'https:' ? 443 : 80),
      path:     fullUrl.pathname + fullUrl.search,
      method,
      headers,
      timeout: 20000,
    };

    const req = lib.request(opts, res => {
      let respBody = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { respBody += chunk; });
      res.on('end', () => {
        if (res.statusCode >= 400) {
          let detail = respBody.slice(0, 300);
          try { detail = JSON.parse(respBody).description || detail; } catch (_) {}
          return reject(new Error(`Arctic Wolf Reports API ${res.statusCode}: ${detail}`));
        }
        if (!respBody) return resolve({});
        try { resolve(JSON.parse(respBody)); }
        catch (e) { reject(new Error('Arctic Wolf Reports API returned invalid JSON')); }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Arctic Wolf Reports API request timed out')); });
    if (payload) req.write(payload);
    req.end();
  });
}

// Downloads a pre-signed URL (e.g. S3) and returns the raw text body.
// No Authorization header — pre-signed URLs are self-authenticating.
function downloadFile(url) {
  return new Promise((resolve, reject) => {
    const fullUrl = new URL(url);
    const lib     = fullUrl.protocol === 'https:' ? https : http;
    const opts = {
      hostname: fullUrl.hostname,
      port:     fullUrl.port || (fullUrl.protocol === 'https:' ? 443 : 80),
      path:     fullUrl.pathname + fullUrl.search,
      method:   'GET',
      timeout:  30000,
    };

    const req = lib.request(opts, res => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => {
        if (res.statusCode >= 400) {
          return reject(new Error(`Report download failed: HTTP ${res.statusCode}`));
        }
        resolve(body);
      });
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Report download timed out')); });
    req.end();
  });
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Verify credentials without generating a report.
 * config: { base_url, api_key, organizationUuid }
 */
async function testConnection(config) {
  const { base_url, api_key, organizationUuid } = config;
  if (!organizationUuid) {
    throw new Error('organizationUuid is required for Arctic Wolf Reports integration.');
  }
  const path = `/api/v1/organizations/${encodeURIComponent(organizationUuid)}/reports/configs?limit=1`;
  await apiRequest(base_url, path, api_key);
}

/**
 * Generate a FULL_SESSION_HISTORY (CSV, TENANT scope, ALL_TIME) report,
 * poll until it's ready, then download and return the CSV text.
 * config: { base_url, api_key, organizationUuid }
 */
async function fetchSessionHistoryCsv(config, opts = {}) {
  const { base_url, api_key, organizationUuid } = config;
  const { maxWaitMs = 120000, pollIntervalMs = 3000 } = opts;

  if (!organizationUuid) {
    throw new Error('organizationUuid is required for Arctic Wolf Reports integration.');
  }

  const genPath = `/api/v1/organizations/${encodeURIComponent(organizationUuid)}/reports`;
  const genRes = await apiRequest(base_url, genPath, api_key, 'POST', {
    reportType: 'FULL_SESSION_HISTORY',
    period:     { periodType: 'ALL_TIME' },
    scope:      'TENANT',
    fileFormat: 'CSV',
  });

  const reportUuid = genRes.reportUuid;
  if (!reportUuid) {
    throw new Error('Arctic Wolf Reports API did not return a reportUuid.');
  }

  const statusPath = `/api/v1/organizations/${encodeURIComponent(organizationUuid)}/reports/${encodeURIComponent(reportUuid)}/status`;
  const start = Date.now();
  let status;
  while (true) {
    const statusRes = await apiRequest(base_url, statusPath, api_key);
    status = statusRes.status;

    if (status === 'AVAILABLE') break;
    if (status === 'FAILED') {
      const msg = (statusRes.error && statusRes.error.message) || 'Report generation failed.';
      throw new Error(msg);
    }

    if (Date.now() - start >= maxWaitMs) {
      const err = new Error('Report is still generating.');
      err.stillGenerating = true;
      err.reportUuid = reportUuid;
      throw err;
    }

    await sleep(pollIntervalMs);
  }

  const downloadPath = `/api/v1/organizations/${encodeURIComponent(organizationUuid)}/reports/${encodeURIComponent(reportUuid)}/download`;
  const downloadRes = await apiRequest(base_url, downloadPath, api_key);
  if (!downloadRes.url) {
    throw new Error('Arctic Wolf Reports API did not return a download URL.');
  }

  return downloadFile(downloadRes.url);
}

module.exports = { REGIONS: ARCTIC_WOLF_REPORTS_REGIONS, testConnection, fetchSessionHistoryCsv };
