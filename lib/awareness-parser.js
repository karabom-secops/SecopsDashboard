'use strict';

/**
 * parseAwarenessCSV(csvText)
 * Parses a security-awareness "User Dashboard" CSV export.
 *
 * Expected columns (case-insensitive, order flexible):
 *   Manager First Name, Manager Last Name, Manager Email,
 *   User First Name,    User Last Name,    User Email,
 *   Total Incomplete Sessions
 *
 * Returns:
 *   { rows: [ { managerFirstName, managerLastName, managerEmail,
 *               userFirstName, userLastName, userEmail,
 *               incompleteSessions } ], totalUsers, totalIncomplete }
 * or throws on bad input.
 */
function parseAwarenessCSV(csvText) {
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
    managerFirst: findCol(headers, /manager\s*first\s*(name)?/i),
    managerLast:  findCol(headers, /manager\s*last\s*(name)?/i),
    managerEmail: findCol(headers, /manager\s*email/i),
    userFirst:    findCol(headers, /^user\s*first\s*(name)?$/i),
    userLast:     findCol(headers, /^user\s*last\s*(name)?$/i),
    userEmail:    findCol(headers, /^user\s*email$/i),
    incomplete:   findCol(headers, /incomplete/i),
  };

  if (idx.userFirst === null || idx.userLast === null || idx.userEmail === null) {
    throw new Error('CSV is missing required columns: User First Name, User Last Name, User Email.');
  }
  if (idx.incomplete === null) {
    throw new Error('CSV is missing required column: Total Incomplete Sessions.');
  }

  const rows = [];
  let totalIncomplete = 0;

  for (let i = 1; i < lines.length; i++) {
    const cols = splitCsvRow(lines[i]);

    const userFirst = (idx.userFirst !== null ? cols[idx.userFirst] : '').trim();
    const userLast  = (idx.userLast  !== null ? cols[idx.userLast]  : '').trim();
    const userEmail = (idx.userEmail !== null ? cols[idx.userEmail] : '').trim();

    // Skip rows missing required user fields
    if (!userFirst && !userLast && !userEmail) continue;

    const incomplete = parseInt(cols[idx.incomplete] || '0', 10) || 0;

    const managerFirst = idx.managerFirst !== null ? (cols[idx.managerFirst] || '').trim() || null : null;
    const managerLast  = idx.managerLast  !== null ? (cols[idx.managerLast]  || '').trim() || null : null;
    const managerEmail = idx.managerEmail !== null ? (cols[idx.managerEmail] || '').trim() || null : null;

    rows.push({
      managerFirstName:  managerFirst,
      managerLastName:   managerLast,
      managerEmail:      managerEmail,
      userFirstName:     userFirst,
      userLastName:      userLast,
      userEmail:         userEmail,
      incompleteSessions: incomplete,
    });

    totalIncomplete += incomplete;
  }

  if (rows.length === 0) {
    throw new Error('No valid user rows found in CSV.');
  }

  return {
    rows,
    totalUsers:      rows.length,
    totalIncomplete,
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

module.exports = { parseAwarenessCSV };
