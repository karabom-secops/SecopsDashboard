'use strict';

// DFIR-IRIS (dfir-iris/iris-web) REST API adapter
// Docs: {base_url}/api/v2/cases  — Bearer token auth

const https = require('https');
const http  = require('http');
const { URL } = require('url');

function normaliseStatus(stateName) {
  const s = (stateName || '').toLowerCase();
  if (s === 'closed' || s === 'resolved') return 'closed';
  if (s === 'open'   || s === 'in progress' || s === 'active') return 'open';
  return 'pending';
}

// IRIS severity IDs: 1=Unknown, 2=Informational, 3=Low, 4=Medium, 5=High, 6=Critical
function normaliseSeverity(severityId) {
  const id = parseInt(severityId, 10);
  if (id >= 5) return 'HIGH';    // High + Critical
  if (id === 4) return 'MEDIUM'; // Medium
  return 'LOW';                  // Unknown, Informational, Low
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
      },
      // Accept self-signed certs for self-hosted instances
      rejectUnauthorized: false,
      timeout: 15000,
    };

    const req = lib.request(opts, res => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => {
        if (res.statusCode >= 400) {
          return reject(new Error(`IrisDFIR API returned ${res.statusCode}: ${body.slice(0, 200)}`));
        }
        try { resolve(JSON.parse(body)); }
        catch (e) { reject(new Error('IrisDFIR API returned invalid JSON')); }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('IrisDFIR API request timed out')); });
    req.end();
  });
}

async function fetchTickets({ base_url, api_key }, testOnly = false) {
  const tickets = [];
  let page = 1;
  const perPage = 100;

  // eslint-disable-next-line no-constant-condition
  while (true) {
    const path = `/api/v2/cases?page=${page}&per_page=${perPage}`;
    const data = await apiRequest(base_url, path, api_key);

    // IRIS wraps results: { data: { cases: [...] } } or { cases: [...] }
    const rows = (data.data && data.data.cases)
      || data.cases
      || (Array.isArray(data.data) ? data.data : [])
      || [];

    rows.forEach(c => {
      const caseId = c.case_id || c.id;
      tickets.push({
        ticketNumber: `IRIS-${caseId}`,
        subject:      c.case_name  || c.name        || `Case ${caseId}`,
        status:       normaliseStatus(c.state_name  || c.status),
        ticketType:   'dfir_case',
        severity:     normaliseSeverity(c.severity_id || c.case_severity_id),
        createdAt:    c.case_open_date      || c.open_date        || c.created_at  || null,
        resolvedAt:   c.case_close_date     || c.close_date       || c.closed_at   || null,
        updatedAt:    c.modification_date   || c.last_activity_at || c.updated_at  || null,
        assignedTo:   c.owner_username      || c.assigned_to      || null,
      });
    });

    if (testOnly || rows.length < perPage) break;
    page++;
  }

  return tickets;
}

module.exports = { fetchTickets };
