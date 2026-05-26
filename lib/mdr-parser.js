'use strict';

/**
 * parseMdrTicketsCSV(csvText)
 * Parses an Arctic Wolf MDR ticket export CSV.
 *
 * Expected columns (case-insensitive, order flexible):
 *   Ticket #, Subject, Status, Ticket Type, To, CC, Created, Last Updated
 *
 * Severity is extracted from subject line via regex: [HIGH], [MEDIUM], [LOW]
 * If not found in subject, defaults to 'MEDIUM'.
 *
 * Returns:
 *   { tickets: [ { ticketNumber, subject, status, ticketType, severity,
 *                  createdAt, resolvedAt, updatedAt, assignedTo, notes } ],
 *     stats: { total, resolved, pending, avgResolutionHours } }
 * or throws on bad input.
 */
function parseMdrTicketsCSV(csvText) {
  if (!csvText || typeof csvText !== 'string') {
    throw new Error('No CSV content provided.');
  }

  const lines = csvText.split(/\r?\n/).filter(l => l.trim().length > 0);
  if (lines.length < 2) {
    throw new Error('CSV must have a header row and at least one data row.');
  }

  // Parse header
  const headers = splitCsvRow(lines[0]).map(h => h.trim().toLowerCase());

  const idx = {
    ticketNum:  findCol(headers, /^ticket\s*#$/i),
    subject:    findCol(headers, /^subject$/i),
    status:     findCol(headers, /^status$/i),
    type:       findCol(headers, /^ticket\s*type$/i),
    to:         findCol(headers, /^to$/i),
    cc:         findCol(headers, /^cc$/i),
    created:    findCol(headers, /^created$/i),
    updated:    findCol(headers, /^last\s*updated$/i),
  };

  if (idx.ticketNum === null || idx.subject === null || idx.status === null) {
    throw new Error('CSV is missing required columns: Ticket #, Subject, Status.');
  }

  const rows = [];
  let totalResolutionHours = 0;
  let resolvedCount = 0;

  for (let i = 1; i < lines.length; i++) {
    const cols = splitCsvRow(lines[i]);

    const ticketNum = (idx.ticketNum !== null ? cols[idx.ticketNum] : '').trim();
    const subject   = (idx.subject !== null ? cols[idx.subject] : '').trim();
    const status    = (idx.status !== null ? cols[idx.status] : '').trim().toLowerCase();

    // Skip rows missing required fields
    if (!ticketNum || !subject || !status) continue;

    // Extract severity from subject line
    const severity = extractSeverity(subject);

    // Parse dates
    const createdRaw = idx.created !== null ? (cols[idx.created] || '').trim() : '';
    const updatedRaw = idx.updated !== null ? (cols[idx.updated] || '').trim() : '';
    const createdAt  = createdRaw ? _parseDate(createdRaw) : null;
    const updatedAt  = updatedRaw ? _parseDate(updatedRaw) : null;

    // Determine if resolved
    const isResolved = status === 'solved' || status === 'closed';
    let resolvedAt = null;
    let resolutionHours = null;

    if (isResolved && createdAt && updatedAt) {
      resolvedAt = updatedAt;
      const createdMs = new Date(createdAt).getTime();
      const resolvedMs = new Date(updatedAt).getTime();
      resolutionHours = (resolvedMs - createdMs) / (1000 * 60 * 60);
      totalResolutionHours += resolutionHours;
      resolvedCount++;
    }

    const ticketType = idx.type !== null ? (cols[idx.type] || '').trim() || null : null;
    const assignedTo = idx.to !== null ? (cols[idx.to] || '').trim() || null : null;

    rows.push({
      ticketNumber: ticketNum,
      subject,
      status,
      ticketType,
      severity,
      createdAt,
      resolvedAt,
      updatedAt,
      assignedTo,
      resolutionHours,
    });
  }

  if (rows.length === 0) {
    throw new Error('No valid ticket rows found in CSV.');
  }

  const pendingCount = rows.filter(t => t.status === 'pending').length;
  const avgResolutionHours = resolvedCount > 0 ? (totalResolutionHours / resolvedCount).toFixed(2) : null;

  return {
    tickets: rows,
    stats: {
      total: rows.length,
      resolved: resolvedCount,
      pending: pendingCount,
      avgResolutionHours: avgResolutionHours ? parseFloat(avgResolutionHours) : null,
    },
  };
}

// ── Helpers ───────────────────────────────────────────────────────────────

function findCol(headers, pattern) {
  const i = headers.findIndex(h => pattern.test(h));
  return i >= 0 ? i : null;
}

/**
 * RFC 4180-compliant CSV row splitter (handles quoted fields with embedded commas).
 */
function splitCsvRow(line) {
  const fields = [];
  let cur = '';
  let inQuote = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuote) {
      if (ch === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (ch === '"') { inQuote = false; }
      else { cur += ch; }
    } else {
      if (ch === '"') { inQuote = true; }
      else if (ch === ',') { fields.push(cur); cur = ''; }
      else { cur += ch; }
    }
  }
  fields.push(cur);
  return fields;
}

/**
 * Extract severity from subject line.
 * Looks for [HIGH], [MEDIUM], [LOW] patterns.
 * Returns the first match found, or 'MEDIUM' as default.
 */
function extractSeverity(subject) {
  if (!subject || typeof subject !== 'string') return 'MEDIUM';
  const match = subject.match(/\[(HIGH|MEDIUM|LOW)\]/i);
  if (match) {
    return match[1].toUpperCase();
  }
  return 'MEDIUM';
}

/**
 * Parse date string to ISO string.
 * Handles various date formats; returns null for invalid/empty values.
 */
function _parseDate(raw) {
  if (!raw || raw === 'N/A') return null;
  const d = new Date(raw);
  return isNaN(d.getTime()) ? null : d.toISOString();
}

module.exports = { parseMdrTicketsCSV };
