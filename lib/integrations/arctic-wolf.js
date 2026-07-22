'use strict';

// Arctic Wolf Ticket API adapter
// Spec: /api/v1/organizations/{organizationUuid}/tickets
// Auth: Authorization: Bearer {token}
// Servers: ticket-api.managedgw.{region}-prod.arcticwolf.net

const https = require('https');
const http  = require('http');
const { URL } = require('url');

const LIMIT = 100; // API maximum per page

const ARCTIC_WOLF_REGIONS = {
  us001: 'https://ticket-api.managedgw.us001-prod.arcticwolf.net',
  us002: 'https://ticket-api.managedgw.us002-prod.arcticwolf.net',
  us003: 'https://ticket-api.managedgw.us003-prod.arcticwolf.net',
  eu001: 'https://ticket-api.managedgw.eu001-prod.arcticwolf.net',
  au001: 'https://ticket-api.managedgw.au001-prod.arcticwolf.net',
  ca001: 'https://ticket-api.managedgw.ca001-prod.arcticwolf.net',
};

module.exports.REGIONS = ARCTIC_WOLF_REGIONS;

// OPEN/NEW/HOLD = With Arctic Wolf → open
// PENDING = With Customer → pending
// CLOSED  = resolved       → closed
function normaliseStatus(s) {
  const u = (s || '').toUpperCase();
  if (u === 'CLOSED')  return 'closed';
  if (u === 'PENDING') return 'pending';
  return 'open';
}

// URGENT/HIGH → HIGH, NORMAL → MEDIUM, LOW → LOW
function normaliseSeverity(priority) {
  const p = (priority || '').toUpperCase();
  if (p === 'URGENT' || p === 'HIGH') return 'HIGH';
  if (p === 'NORMAL')                 return 'MEDIUM';
  return 'LOW';
}

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
        'Authorization': `Bearer ${apiKey}`,
        'Accept':        'application/json',
        'Content-Type':  'application/json',
        'User-Agent':    'SecOpsDashboard/1.0',
      },
      timeout: 20000,
    };

    const req = lib.request(opts, res => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => {
        if (res.statusCode >= 400) {
          let detail = body.slice(0, 300);
          try { detail = JSON.parse(body).description || detail; } catch (_) {}
          return reject(new Error(`Arctic Wolf API ${res.statusCode}: ${detail}`));
        }
        try { resolve(JSON.parse(body)); }
        catch (e) { reject(new Error('Arctic Wolf API returned invalid JSON')); }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Arctic Wolf API request timed out')); });
    req.end();
  });
}

/**
 * Fetch all tickets for the configured organisation.
 * config: { base_url, api_key, organizationUuid }
 * testOnly: if true, fetch only the first page (for connection testing)
 */
async function fetchTickets(config, testOnly = false) {
  const { base_url, api_key, organizationUuid } = config;

  if (!organizationUuid) {
    throw new Error('organizationUuid is required for Arctic Wolf integration.');
  }

  const tickets = [];
  let offset = 0;
  let total  = null;

  while (true) {
    const path = `/api/v1/organizations/${encodeURIComponent(organizationUuid)}/tickets?offset=${offset}&limit=${LIMIT}`;
    const data = await apiRequest(base_url, path, api_key);

    const results = data.results || [];
    if (total === null) total = (data.meta && data.meta.total != null) ? data.meta.total : results.length;

    results.forEach(t => {
      const isClosed = (t.status || '').toUpperCase() === 'CLOSED';
      const assignee = t.assignee
        ? (t.assignee.email || [t.assignee.firstName, t.assignee.lastName].filter(Boolean).join(' ') || null)
        : null;

      tickets.push({
        ticketNumber: String(t.id),
        subject:      t.title || '(no subject)',
        status:       normaliseStatus(t.status),
        ticketType:   t.type ? t.type.toLowerCase() : null,
        severity:     normaliseSeverity(t.priority),
        createdAt:    t.createdAt || null,
        resolvedAt:   isClosed ? (t.updatedAt || null) : null,
        updatedAt:    t.updatedAt || null,
        assignedTo:   assignee,
      });
    });

    if (testOnly || results.length < LIMIT || tickets.length >= total) break;
    offset += LIMIT;
  }

  return tickets;
}

module.exports = { fetchTickets };
