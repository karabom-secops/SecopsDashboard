'use strict';

/**
 * parseReport(reportText, csvText?)
 * Parses a plain-text weekly SecOps report and optional CSV into structured data.
 * Returns { weekKey, weekCommencing, orgs, sysmon, containment } or { error }.
 */
function parseReport(reportText, csvText) {
  try {
    if (!reportText || typeof reportText !== 'string') {
      return { error: 'Report text is required.' };
    }

    const lines = reportText.split(/\r?\n/);

    // ── Week Commencing ─────────────────────────────────────────────────────
    const wcMatch = reportText.match(/Week\s+Commencing\s*:\s*(.+)/i);
    if (!wcMatch) {
      return { error: 'Could not find Week Commencing date in the report.' };
    }
    const weekCommencing = wcMatch[1].trim();
    const weekKey = normaliseDate(weekCommencing);
    if (!weekKey) {
      return { error: `Could not parse date from: "${weekCommencing}"` };
    }

    // ── Sysmon / Containment fractions ───────────────────────────────────────
    const sysmonMatch = reportText.match(/Sysmon\s+Agents\s*:\s*(\d+)\s*\/\s*(\d+)/i);
    const sysmon = sysmonMatch
      ? { deployed: parseInt(sysmonMatch[1], 10), total: parseInt(sysmonMatch[2], 10) }
      : null;

    const containmentMatch = reportText.match(/Containment\s+Drivers\s*:\s*(\d+)\s*\/\s*(\d+)/i);
    const containment = containmentMatch
      ? { deployed: parseInt(containmentMatch[1], 10), total: parseInt(containmentMatch[2], 10) }
      : null;

    // ── Orgs from OVERALL STATS section ─────────────────────────────────────
    let orgs = parseOrgsFromText(lines);

    // ── CSV override ─────────────────────────────────────────────────────────
    if (csvText && typeof csvText === 'string' && csvText.trim().length > 0) {
      const csvOrgs = parseOrgsFromCsv(csvText);
      if (csvOrgs.length > 0) {
        orgs = csvOrgs;
      }
    }

    return { weekKey, weekCommencing, orgs, sysmon, containment };
  } catch (err) {
    return { error: err.message };
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Normalise a variety of date strings to YYYY-MM-DD.
 * Handles: "1 April 2025", "April 1, 2025", "01/04/2025", "2025-04-01", etc.
 */
function normaliseDate(str) {
  try {
    // Already ISO
    if (/^\d{4}-\d{2}-\d{2}$/.test(str.trim())) return str.trim();

    // Try native Date parse (handles most common formats)
    const d = new Date(str);
    if (!isNaN(d.getTime())) {
      const y = d.getFullYear();
      const m = String(d.getMonth() + 1).padStart(2, '0');
      const day = String(d.getDate()).padStart(2, '0');
      return `${y}-${m}-${day}`;
    }

    // "1 April 2025" / "01 Apr 2025"
    const longMatch = str.match(/^(\d{1,2})\s+([A-Za-z]+)\s+(\d{4})$/);
    if (longMatch) {
      const months = { jan:1,feb:2,mar:3,apr:4,may:5,jun:6,jul:7,aug:8,sep:9,oct:10,nov:11,dec:12 };
      const mon = months[longMatch[2].slice(0,3).toLowerCase()];
      if (mon) {
        const y = longMatch[3];
        const m = String(mon).padStart(2, '0');
        const day = longMatch[1].padStart(2, '0');
        return `${y}-${m}-${day}`;
      }
    }

    return null;
  } catch (_) {
    return null;
  }
}

/**
 * Parse OVERALL STATS section from lines.
 * Expects a heading line containing "OVERALL STATS" followed by a header row
 * then data rows — tab or multiple-space delimited.
 */
function parseOrgsFromText(lines) {
  let statsStart = -1;
  for (let i = 0; i < lines.length; i++) {
    if (/overall\s+stats/i.test(lines[i])) {
      statsStart = i + 1;
      break;
    }
  }
  if (statsStart === -1) return [];

  // Find the header row (non-empty line after section heading)
  let headerIdx = -1;
  for (let i = statsStart; i < lines.length; i++) {
    if (lines[i].trim()) { headerIdx = i; break; }
  }
  if (headerIdx === -1) return [];

  const headers = splitDelimited(lines[headerIdx]).map(h => h.trim().toLowerCase());
  const colIdx = mapHeaders(headers);

  const orgs = [];
  for (let i = headerIdx + 1; i < lines.length; i++) {
    const row = lines[i].trim();
    if (!row) continue;
    // Stop at next section heading (all-caps or starts with ==)
    if (/^={3,}|^-{3,}/.test(row)) break;
    if (/^[A-Z\s]{5,}$/.test(row) && !/\d/.test(row)) break;

    const cols = splitDelimited(lines[i]);
    if (cols.length < 2) break; // no more table data

    const org = extractOrgFromCols(cols, colIdx);
    if (org && org.orgName) orgs.push(org);
  }

  return orgs;
}

/**
 * Parse orgs from CSV string.
 */
function parseOrgsFromCsv(csvText) {
  const rows = csvText.trim().split(/\r?\n/).filter(l => l.trim());
  if (rows.length < 2) return [];

  const headers = parseCSVLine(rows[0]).map(h => h.trim().toLowerCase());
  const colIdx = mapHeaders(headers);

  const orgs = [];
  for (let i = 1; i < rows.length; i++) {
    const cols = parseCSVLine(rows[i]);
    const org = extractOrgFromCols(cols, colIdx);
    if (org && org.orgName) orgs.push(org);
  }
  return orgs;
}

/**
 * Map flexible header names to column index object.
 */
function mapHeaders(headers) {
  const idx = { orgName: -1, alerts: -1, escalated: -1, coverageScore: -1, irPlan: -1 };
  headers.forEach((h, i) => {
    if (/org.*(name)?|name/i.test(h)) idx.orgName = i;
    else if (/^alerts$/i.test(h) || /total.*alert|alert.*count/i.test(h)) idx.alerts = i;
    else if (/escalat/i.test(h)) idx.escalated = i;
    else if (/coverage/i.test(h)) idx.coverageScore = i;
    else if (/ir\s*plan|incident.*response/i.test(h)) idx.irPlan = i;
  });
  // fallback positional: assume orgName=0 if not found
  if (idx.orgName === -1) idx.orgName = 0;
  return idx;
}

/**
 * Extract one org object from a cols array using the colIdx map.
 */
function extractOrgFromCols(cols, colIdx) {
  const get = (i) => (i >= 0 && i < cols.length) ? cols[i].trim() : '';

  const orgName = get(colIdx.orgName);
  if (!orgName) return null;

  const alerts = parseIntOrNull(get(colIdx.alerts));
  const escalated = parseIntOrNull(get(colIdx.escalated));
  const rawCoverage = get(colIdx.coverageScore);
  const coverageScore = rawCoverage === '' ? null : parseIntOrNull(rawCoverage);
  const irPlanRaw = get(colIdx.irPlan);
  const irPlan = irPlanRaw === '' ? false : !/^(no|false|0|n|none)$/i.test(irPlanRaw);

  return { orgName, alerts: alerts || 0, escalated: escalated || 0, coverageScore, irPlan };
}

/**
 * Split a line by tab or 2+ spaces (for text-based table rows).
 */
function splitDelimited(line) {
  return line.split(/\t|  +/).filter(s => s !== undefined);
}

/**
 * Parse a single CSV line respecting quoted fields.
 */
function parseCSVLine(line) {
  const result = [];
  let field = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') { field += '"'; i++; }
      else { inQuotes = !inQuotes; }
    } else if (ch === ',' && !inQuotes) {
      result.push(field); field = '';
    } else {
      field += ch;
    }
  }
  result.push(field);
  return result;
}

function parseIntOrNull(str) {
  const n = parseInt(str, 10);
  return isNaN(n) ? null : n;
}

module.exports = { parseReport };
