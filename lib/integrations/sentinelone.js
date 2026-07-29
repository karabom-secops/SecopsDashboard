'use strict';

// SentinelOne Management API adapter (v2.1)
// Docs: {base_url}/api-doc/overview
// Auth: Authorization: ApiToken {token}
// Base URL is the tenant console, e.g. https://euce1-101.sentinelone.net
//
// Endpoints used:
//   GET /web/api/v2.1/threats     — detections, with mitigation + analyst verdict
//   GET /web/api/v2.1/activities  — audit/console activity stream
//   GET /web/api/v2.1/agents      — endpoint fleet health

const https = require('https');
const http  = require('http');
const { URL } = require('url');

const PAGE_LIMIT   = 1000; // API maximum per page
const MAX_PAGES    = 50;   // hard stop so a misconfigured filter can't loop forever
const REQ_TIMEOUT  = 30000;

function apiRequest(baseUrl, path, apiKey) {
  return new Promise((resolve, reject) => {
    const fullUrl = new URL(path, baseUrl);
    const lib     = fullUrl.protocol === 'https:' ? https : http;
    const opts = {
      hostname: fullUrl.hostname,
      port:     fullUrl.port || (fullUrl.protocol === 'https:' ? 443 : 80),
      path:     fullUrl.pathname + fullUrl.search,
      method:   'GET',
      headers:  {
        'Authorization': `ApiToken ${apiKey}`,
        'Accept':        'application/json',
        'Content-Type':  'application/json',
        'User-Agent':    'SecOpsDashboard/1.0',
      },
      timeout: REQ_TIMEOUT,
    };

    const req = lib.request(opts, res => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => {
        if (res.statusCode >= 400) {
          let detail = body.slice(0, 300);
          try {
            const parsed = JSON.parse(body);
            if (Array.isArray(parsed.errors) && parsed.errors.length) {
              detail = parsed.errors.map(e => e.detail || e.title).filter(Boolean).join('; ') || detail;
            }
          } catch (_) { /* keep raw body slice */ }
          return reject(new Error(`SentinelOne API ${res.statusCode}: ${detail}`));
        }
        try { resolve(JSON.parse(body)); }
        catch (e) { reject(new Error('SentinelOne API returned invalid JSON')); }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('SentinelOne API request timed out')); });
    req.end();
  });
}

/** Build the scoping query string shared by every endpoint. */
function scopeParams({ siteIds, accountIds }) {
  const parts = [];
  if (siteIds)    parts.push(`siteIds=${encodeURIComponent(siteIds)}`);
  if (accountIds) parts.push(`accountIds=${encodeURIComponent(accountIds)}`);
  return parts;
}

/**
 * Walk a cursor-paginated v2.1 collection.
 * Returns the concatenated `data` arrays.
 */
async function fetchPaged(config, endpoint, extraParams = [], testOnly = false) {
  const { base_url, api_key } = config;
  const out    = [];
  let cursor   = null;
  let pages    = 0;

  while (pages < MAX_PAGES) {
    const params = [`limit=${testOnly ? 1 : PAGE_LIMIT}`, ...scopeParams(config), ...extraParams];
    if (cursor) params.push(`cursor=${encodeURIComponent(cursor)}`);

    const data = await apiRequest(base_url, `${endpoint}?${params.join('&')}`, api_key);
    const rows = Array.isArray(data.data) ? data.data : [];
    out.push(...rows);
    pages++;

    cursor = data.pagination && data.pagination.nextCursor;
    if (testOnly || !cursor || rows.length === 0) break;
  }

  return out;
}

// ── Normalisers ────────────────────────────────────────────────────────────

function str(v) {
  if (v === null || v === undefined) return null;
  const s = String(v).trim();
  return s === '' ? null : s;
}

function ts(v) {
  if (!v) return null;
  const d = new Date(v);
  return isNaN(d.getTime()) ? null : d.toISOString();
}

/**
 * SentinelOne reports mitigation as an array of per-action records, e.g.
 * [{ action: 'kill', status: 'success', lastUpdate: '…' }, …].
 * The threat counts as mitigated once threatInfo.mitigationStatus says so; we
 * take the latest successful action timestamp as the mitigation time.
 */
function deriveMitigatedAt(threat) {
  const actions = Array.isArray(threat.mitigationStatus) ? threat.mitigationStatus : [];
  let latest = null;
  actions.forEach(a => {
    if ((a.status || '').toLowerCase() !== 'success') return;
    const t = ts(a.lastUpdate);
    if (t && (!latest || t > latest)) latest = t;
  });
  return latest;
}

function mapThreat(t) {
  const info   = t.threatInfo          || {};
  const rt     = t.agentRealtimeInfo   || {};
  const det    = t.agentDetectionInfo  || {};

  const mitigationStatus = str(info.mitigationStatus);
  const incidentStatus   = str(info.incidentStatus);
  const isMitigated      = mitigationStatus === 'mitigated';
  const isResolved       = incidentStatus === 'resolved';

  const engines = Array.isArray(info.detectionEngines)
    ? info.detectionEngines.map(e => e.title || e.key).filter(Boolean).join(', ')
    : null;

  return {
    threatId:            String(t.id),
    threatName:          str(info.threatName) || '(unnamed threat)',
    classification:      str(info.classification),
    classificationSource: str(info.classificationSource),
    confidenceLevel:     str(info.confidenceLevel),
    analystVerdict:      str(info.analystVerdict),
    incidentStatus:      incidentStatus,
    mitigationStatus:    mitigationStatus,
    detectionType:       str(info.detectionType),
    detectionEngines:    engines,
    endpointName:        str(rt.agentComputerName) || str(det.agentComputerName),
    endpointId:          str(rt.agentId) || str(t.agentId),
    osName:              str(rt.agentOsName) || str(det.agentOsName),
    agentVersion:        str(rt.agentVersion) || str(det.agentVersion),
    siteName:            str(rt.siteName) || str(det.siteName),
    groupName:           str(rt.groupName) || str(det.groupName),
    filePath:            str(info.filePath),
    fileHash:            str(info.sha1) || str(info.sha256) || str(info.md5),
    initiatedBy:         str(info.initiatedBy),
    detectedAt:          ts(info.identifiedAt) || ts(info.createdAt),
    mitigatedAt:         isMitigated ? deriveMitigatedAt(t) : null,
    resolvedAt:          isResolved ? ts(info.updatedAt) : null,
    updatedAt:           ts(info.updatedAt) || ts(info.createdAt),
    raw:                 t,
  };
}

function mapActivity(a, typeNames) {
  const data = a.data || {};
  return {
    activityId:          String(a.id),
    activityType:        a.activityType != null ? parseInt(a.activityType, 10) : null,
    activityTypeName:    typeNames[a.activityType] || str(a.description) || null,
    primaryDescription:  str(a.primaryDescription),
    secondaryDescription: str(a.secondaryDescription),
    endpointName:        str(data.computerName) || str(a.agentName),
    endpointId:          str(a.agentId),
    siteName:            str(a.siteName) || str(data.siteName),
    groupName:           str(a.groupName) || str(data.groupName),
    userName:            str(a.userName) || str(data.username) || str(data.userName),
    threatId:            a.threatId != null ? String(a.threatId) : null,
    createdAt:           ts(a.createdAt),
    raw:                 a,
  };
}

function mapAgent(a) {
  return {
    agentId:       String(a.id),
    computerName:  str(a.computerName),
    osName:        str(a.osName),
    osType:        str(a.osType),
    agentVersion:  str(a.agentVersion),
    machineType:   str(a.machineType),
    domain:        str(a.domain),
    siteName:      str(a.siteName),
    groupName:     str(a.groupName),
    isActive:      a.isActive === true,
    isInfected:    a.infected === true,
    isUpToDate:    a.isUpToDate === true,
    networkStatus: str(a.networkStatus),
    scanStatus:    str(a.scanStatus),
    activeThreats: parseInt(a.activeThreats, 10) || 0,
    lastActiveAt:  ts(a.lastActiveDate),
    registeredAt:  ts(a.registeredAt) || ts(a.createdAt),
  };
}

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Fetch threats. `since` (ISO string) switches to an incremental pull on
 * updatedAt so repeat syncs stay cheap — a threat whose verdict or mitigation
 * status changed still comes back and overwrites the stored row.
 */
async function fetchThreats(config, { since = null, testOnly = false } = {}) {
  const params = ['sortBy=createdAt', 'sortOrder=asc'];
  if (since && !testOnly) params.push(`updatedAt__gte=${encodeURIComponent(since)}`);
  const rows = await fetchPaged(config, '/web/api/v2.1/threats', params, testOnly);
  return rows.map(mapThreat);
}

/** Activity type id → human label, so the feed reads without a lookup table. */
async function fetchActivityTypes(config) {
  try {
    const data = await apiRequest(config.base_url, '/web/api/v2.1/activities/types', config.api_key);
    const map  = {};
    (Array.isArray(data.data) ? data.data : []).forEach(t => {
      if (t.id != null) map[t.id] = t.descriptionTemplate || t.action || null;
    });
    return map;
  } catch (_) {
    return {}; // labels are cosmetic — never fail a sync over them
  }
}

async function fetchActivities(config, { since = null, testOnly = false } = {}) {
  const params = ['sortBy=createdAt', 'sortOrder=asc'];
  if (since && !testOnly) params.push(`createdAt__gt=${encodeURIComponent(since)}`);

  const typeNames = testOnly ? {} : await fetchActivityTypes(config);
  const rows = await fetchPaged(config, '/web/api/v2.1/activities', params, testOnly);
  return rows.map(a => mapActivity(a, typeNames));
}

async function fetchAgents(config, { testOnly = false } = {}) {
  const rows = await fetchPaged(config, '/web/api/v2.1/agents', [], testOnly);
  return rows.map(mapAgent);
}

/** Cheap credential check — one threat page, or the system status if none exist. */
async function testConnection(config) {
  await apiRequest(config.base_url, '/web/api/v2.1/system/info', config.api_key);
  return true;
}

module.exports = {
  fetchThreats,
  fetchActivities,
  fetchAgents,
  testConnection,
};
