'use strict';

const { XMLParser } = require('fast-xml-parser');

// ── Risk normalisation ────────────────────────────────────────────────────────

const RISK_MAP = {
  critical:      'Critical',
  high:          'High',
  medium:        'Medium',
  low:           'Low',
  info:          'Info',
  informational: 'Info',
  none:          'Info',
};

function normaliseRisk(raw) {
  if (!raw) return 'Info';
  return RISK_MAP[String(raw).toLowerCase()] || 'Info';
}

// ── CSV parser ────────────────────────────────────────────────────────────────

/**
 * parseNessusCSV(csvText)
 * Parses a Nessus-exported CSV into a normalised findings array.
 * Handles the standard Nessus CSV column layout (and minor variations).
 */
function parseNessusCSV(csvText) {
  if (!csvText || typeof csvText !== 'string') return [];

  const lines = stripBom(csvText).split(/\r?\n/).filter(l => l.trim().length > 0);
  if (lines.length < 2) return [];

  // Parse header row (handle quoted fields)
  const headers = splitCsvRow(lines[0]).map(h => h.trim());

  // Map column indices by header pattern
  const idx = {
    pluginId:  findCol(headers, /^plugin\s*id$/i),
    name:      findCol(headers, /^name$/i) ?? findCol(headers, /plugin\s*name/i),
    risk:      findCol(headers, /^risk$/i) ?? findCol(headers, /severity/i),
    host:      findCol(headers, /^host$/i) ?? findCol(headers, /host\s*ip/i) ?? findCol(headers, /^ip/i),
    port:      findCol(headers, /^port$/i),
    protocol:  findCol(headers, /^protocol$/i),
    cve:       findCol(headers, /^cve$/i),
    cvssV2:    findCol(headers, /cvss\s*v2/i) ?? findCol(headers, /^cvss\s*base\s*score$/i),
    cvssV3:    findCol(headers, /cvss\s*v3/i),
    synopsis:  findCol(headers, /^synopsis$/i),
    solution:  findCol(headers, /^solution$/i),
    description: findCol(headers, /^description$/i),
  };

  const findings = [];
  for (let i = 1; i < lines.length; i++) {
    const cols = splitCsvRow(lines[i]);
    if (cols.length < 2) continue;

    const risk = normaliseRisk(idx.risk !== null ? cols[idx.risk] : '');
    if (risk === 'Info') continue; // skip informational by default

    findings.push({
      pluginId:    idx.pluginId !== null ? cols[idx.pluginId] || '' : '',
      name:        idx.name !== null ? cols[idx.name] || 'Unknown' : 'Unknown',
      risk,
      host:        idx.host !== null ? cols[idx.host] || '' : '',
      port:        idx.port !== null ? cols[idx.port] || '' : '',
      protocol:    idx.protocol !== null ? cols[idx.protocol] || '' : '',
      cve:         idx.cve !== null ? cols[idx.cve] || '' : '',
      cvssV2:      idx.cvssV2 !== null ? parseFloat(cols[idx.cvssV2]) || null : null,
      cvssV3:      idx.cvssV3 !== null ? parseFloat(cols[idx.cvssV3]) || null : null,
      synopsis:    idx.synopsis !== null ? cols[idx.synopsis] || '' : '',
      solution:    idx.solution !== null ? cols[idx.solution] || '' : '',
      status:      'open',
    });
  }

  return findings;
}

// ── .nessus XML parser ────────────────────────────────────────────────────────

/**
 * parseNessusXML(xmlText)
 * Parses a .nessus v2 XML file into a normalised findings array.
 */
function parseNessusXML(xmlText) {
  if (!xmlText || typeof xmlText !== 'string') return [];

  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '@_',
    isArray: (name) => ['ReportHost', 'ReportItem', 'tag'].includes(name),
  });

  let doc;
  try {
    doc = parser.parse(xmlText);
  } catch {
    return [];
  }

  const report = doc?.NessusClientData_v2?.Report;
  if (!report) return [];

  const hosts = Array.isArray(report.ReportHost) ? report.ReportHost : [report.ReportHost].filter(Boolean);
  const findings = [];

  for (const host of hosts) {
    const hostName = host['@_name'] || '';

    // Extract host-ip from HostProperties tags
    let hostIp = hostName;
    if (host.HostProperties && Array.isArray(host.HostProperties.tag)) {
      const ipTag = host.HostProperties.tag.find(t => t['@_name'] === 'host-ip');
      if (ipTag) hostIp = ipTag['#text'] || ipTag || hostName;
    }

    const items = Array.isArray(host.ReportItem) ? host.ReportItem : [host.ReportItem].filter(Boolean);

    for (const item of items) {
      const risk = normaliseRisk(item.risk_factor || item['@_severity']);
      if (risk === 'Info') continue;

      findings.push({
        pluginId: String(item['@_pluginID'] || ''),
        name:     item['@_pluginName'] || item.plugin_name || 'Unknown',
        risk,
        host:     hostIp,
        port:     String(item['@_port'] || ''),
        protocol: item['@_protocol'] || '',
        cve:      Array.isArray(item.cve) ? item.cve.join(', ') : (item.cve || ''),
        cvssV2:   parseFloat(item.cvss_base_score) || null,
        cvssV3:   parseFloat(item.cvss3_base_score) || null,
        synopsis: item.synopsis || '',
        solution: item.solution || '',
        status:   'open',
      });
    }
  }

  return findings;
}

// ── Summary computation ───────────────────────────────────────────────────────

/**
 * computeVulnSummary(findings)
 * Returns aggregate counts, top vulns by host count, and per-host summary.
 */
function computeVulnSummary(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const statusCounts = { open: 0, 'in-progress': 0, fixed: 0, accepted: 0 };
  const vulnMap  = {};   // pluginId → { name, risk, hosts: Set, cve, solution }
  const hostMap  = {};   // host → { critical, high, medium, low }

  for (const f of findings) {
    const status = String(f.status || 'open');
    if (statusCounts[status] !== undefined) {
      statusCounts[status]++;
    }

    const isActive = status === 'open' || status === 'in-progress';
    if (!isActive) continue;

    const r = String(f.risk || 'info').toLowerCase();
    if (counts[r] !== undefined) counts[r]++;

    // Per-vuln aggregation
    const key = f.pluginId || f.name;
    if (!vulnMap[key]) {
      vulnMap[key] = { pluginId: f.pluginId, name: f.name, risk: f.risk, hosts: new Set(), cve: f.cve, solution: f.solution };
    }
    if (f.host) vulnMap[key].hosts.add(f.host);

    // Per-host aggregation
    if (f.host) {
      if (!hostMap[f.host]) hostMap[f.host] = { host: f.host, critical: 0, high: 0, medium: 0, low: 0 };
      const hr = String(f.risk || 'info').toLowerCase();
      if (hostMap[f.host][hr] !== undefined) hostMap[f.host][hr]++;
    }
  }

  const topVulns = Object.values(vulnMap)
    .map(v => ({ pluginId: v.pluginId, name: v.name, risk: v.risk, hostCount: v.hosts.size, cve: v.cve, solution: v.solution }))
    .sort((a, b) => b.hostCount - a.hostCount)
    .slice(0, 20);

  const hostSummary = Object.values(hostMap)
    .map(h => ({ ...h, total: h.critical + h.high + h.medium + h.low }))
    .sort((a, b) => b.total - a.total);

  return {
    critical: counts.critical,
    high:     counts.high,
    medium:   counts.medium,
    low:      counts.low,
    info:     counts.info,
    activeTotal: counts.critical + counts.high + counts.medium + counts.low + counts.info,
    statusCounts,
    total:    findings.length,
    topVulns,
    hostSummary,
  };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Strips a UTF-8 byte-order mark so the first header cell matches cleanly. */
function stripBom(text) {
  return typeof text === 'string' && text.charCodeAt(0) === 0xFEFF ? text.slice(1) : text;
}

function findCol(headers, pattern) {
  const i = headers.findIndex(h => pattern.test(h));
  return i >= 0 ? i : null;
}

/**
 * RFC 4180-compliant CSV row splitter.
 * Handles quoted fields with embedded commas and escaped quotes.
 */
function splitCsvRow(line) {
  const fields = [];
  let cur = '';
  let inQuote = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuote) {
      if (ch === '"' && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else if (ch === '"') {
        inQuote = false;
      } else {
        cur += ch;
      }
    } else {
      if (ch === '"') {
        inQuote = true;
      } else if (ch === ',') {
        fields.push(cur);
        cur = '';
      } else {
        cur += ch;
      }
    }
  }
  fields.push(cur);
  return fields;
}

// ── Arctic Wolf Managed Risk CSV parser ────────────────────────────────────────────

/**
 * isArcticWolfCSV(csvText)
 * Returns true for either Arctic Wolf Managed Risk export layout:
 *   - the original export, identified by the 'CISA KEV' column
 *   - the Risk Export layout, identified by the 'Risk ID' + 'Asset ID' column pair
 */
function isArcticWolfCSV(csvText) {
  if (!csvText || typeof csvText !== 'string') return false;
  const firstLine = stripBom(csvText.split(/\r?\n/)[0] || '');
  if (/CISA\s+KEV/i.test(firstLine)) return true;
  return /(^|,)\s*"?Risk\s*ID"?\s*(,|$)/i.test(firstLine) &&
         /(^|,)\s*"?Asset\s*ID"?\s*(,|$)/i.test(firstLine);
}

/**
 * parseArcticWolfCSV(csvText)
 * Parses an Arctic Wolf Managed Risk export CSV into a normalised findings array.
 *
 * Column mapping:
 *   Title               -> name + pluginId (carry-forward key)
 *   Asset Name          -> host (Risk Export layout only)
 *   CVEs                -> cve
 *   Risk Severity       -> risk
 *   CVSSv3 Score        -> cvssV3 (preferred); Score -> cvssV3 (fallback)
 *   First Detected Time -> firstSeenAt
 *   Description         -> synopsis
 *   Remediation…        -> solution (header may carry a suffix, e.g. "(Powered by Aurora AI)")
 *   port / protocol     -> '' (not present in Arctic Wolf exports)
 *
 * Rows the export marks as resolved are skipped — they are closed on the Arctic
 * Wolf side and should not be counted as active findings.
 */
function parseArcticWolfCSV(csvText) {
  if (!csvText || typeof csvText !== 'string') return [];

  const lines = stripBom(csvText).split(/\r?\n/).filter(l => l.trim().length > 0);
  if (lines.length < 2) return [];

  const headers = splitCsvRow(lines[0]).map(h => h.trim());

  const idx = {
    title:         findCol(headers, /^title$/i),
    assetName:     findCol(headers, /^asset\s*name$/i),
    cves:          findCol(headers, /^cves?$/i),
    riskSev:       findCol(headers, /^risk\s*severity$/i),
    score:         findCol(headers, /^score$/i),
    cvssV3:        findCol(headers, /cvss\s*v3\s*score/i),
    firstDetected: findCol(headers, /^first\s*detected/i),
    description:   findCol(headers, /^description$/i),
    remediation:   findCol(headers, /^remediation\b/i),
    status:        findCol(headers, /^status$/i),
  };

  const findings = [];

  for (let i = 1; i < lines.length; i++) {
    const cols = splitCsvRow(lines[i]);
    if (cols.length < 2) continue;

    // Risk Export carries a Status column — drop rows already resolved upstream
    if (idx.status !== null && /^resolved$/i.test((cols[idx.status] || '').trim())) continue;

    const rawRisk = idx.riskSev !== null ? cols[idx.riskSev] : '';
    const risk = normaliseRisk(rawRisk);
    if (risk === 'Info') continue;

    const title = idx.title !== null ? (cols[idx.title] || '').trim() : '';
    if (!title) continue;

    // Prefer explicit CVSSv3 Score column; fall back to the generic Score column
    const rawCvssV3 = idx.cvssV3 !== null ? cols[idx.cvssV3] : '';
    const rawScore  = idx.score  !== null ? cols[idx.score]  : '';
    const cvssV3 = parseFloat(rawCvssV3) || parseFloat(rawScore) || null;

    // Use First Detected Time from the export if present
    const rawDate = idx.firstDetected !== null ? (cols[idx.firstDetected] || '').trim() : '';
    const firstSeenAt = rawDate ? new Date(rawDate) : null;

    findings.push({
      pluginId:  title,
      name:      title,
      risk,
      host:      idx.assetName !== null ? (cols[idx.assetName] || '').trim() : '',
      port:      '',
      protocol:  '',
      cve:       idx.cves !== null ? (cols[idx.cves] || '').trim() : '',
      cvssV2:    null,
      cvssV3,
      synopsis:  idx.description !== null ? (cols[idx.description] || '').trim() : '',
      solution:  idx.remediation !== null ? (cols[idx.remediation] || '').trim() : '',
      status:    'open',
      firstSeenAt,
    });
  }

  return findings;
}

// ── Format dispatch ───────────────────────────────────────────────────────────

const VULN_FORMATS = ['auto', 'nessus_csv', 'nessus_xml', 'arctic_wolf_csv'];

/**
 * parseVulnFile(fileText, { format, fileName, mimeType })
 * Routes an upload to the right parser. `format` is one of VULN_FORMATS;
 * 'auto' (or anything unrecognised) falls back to content sniffing.
 * Returns { findings, format } where format is the parser actually used.
 */
function parseVulnFile(fileText, { format = 'auto', fileName = '', mimeType = '' } = {}) {
  const requested = VULN_FORMATS.includes(format) ? format : 'auto';
  const name = String(fileName).toLowerCase();
  const mime = String(mimeType).toLowerCase();

  let chosen = requested;
  if (chosen === 'auto') {
    if (name.endsWith('.nessus') || mime.includes('xml')) chosen = 'nessus_xml';
    else if (isArcticWolfCSV(fileText))                   chosen = 'arctic_wolf_csv';
    else                                                  chosen = 'nessus_csv';
  }

  let findings;
  if      (chosen === 'nessus_xml')      findings = parseNessusXML(fileText);
  else if (chosen === 'arctic_wolf_csv') findings = parseArcticWolfCSV(fileText);
  else                                   findings = parseNessusCSV(fileText);

  return { findings, format: chosen };
}

module.exports = {
  parseNessusCSV,
  parseNessusXML,
  parseArcticWolfCSV,
  isArcticWolfCSV,
  parseVulnFile,
  VULN_FORMATS,
  computeVulnSummary,
};
