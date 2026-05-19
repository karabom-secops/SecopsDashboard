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

/**
 * detectAwarenessFormat(csvText)
 * Returns 'history' if the CSV looks like a UserSessionHistory export
 * (has a 'sent date' header column), otherwise returns 'summary'.
 */
function detectAwarenessFormat(csvText) {
  if (!csvText || typeof csvText !== 'string') return 'summary';
  const firstLine = csvText.split(/\r?\n/)[0] || '';
  const headers   = splitCsvRow(firstLine).map(h => h.trim().toLowerCase());
  return headers.some(h => /sent\s*date/i.test(h)) ? 'history' : 'summary';
}

/**
 * parseSessionHistoryCSV(csvText)
 * Parses an Arctic Wolf "UserSessionHistory" CSV export.
 *
 * Expected columns (case-insensitive, order flexible):
 *   User First Name, User Last Name, User Email,
 *   Sent Date (UTC), Type, Title, Managed By, Scheduled By,
 *   Status, Completed Date (UTC), Elapsed Seconds, Clicked (UTC),
 *   Quiz Score, Manager First Name, Manager Last Name, Manager Email
 *
 * Returns:
 *   { rows: [...], stats: { totalRows, uniqueUsers } }
 */
function parseSessionHistoryCSV(csvText) {
  if (!csvText || typeof csvText !== 'string') {
    throw new Error('No CSV content provided.');
  }

  const lines = csvText.split(/\r?\n/).filter(l => l.trim().length > 0);
  if (lines.length < 2) {
    throw new Error('CSV must have a header row and at least one data row.');
  }

  const headers = splitCsvRow(lines[0]).map(h => h.trim().toLowerCase());

  const idx = {
    userFirst:      findCol(headers, /^user\s*first\s*(name)?$/i),
    userLast:       findCol(headers, /^user\s*last\s*(name)?$/i),
    userEmail:      findCol(headers, /^user\s*email$/i),
    sentDate:       findCol(headers, /sent\s*date/i),
    type:           findCol(headers, /^type$/i),
    title:          findCol(headers, /^title$/i),
    status:         findCol(headers, /^status$/i),
    completedDate:  findCol(headers, /completed\s*date/i),
    elapsedSeconds: findCol(headers, /elapsed\s*seconds/i),
    clicked:        findCol(headers, /clicked/i),
    quizScore:      findCol(headers, /quiz\s*score/i),
    managerFirst:   findCol(headers, /manager\s*first\s*(name)?/i),
    managerLast:    findCol(headers, /manager\s*last\s*(name)?/i),
    managerEmail:   findCol(headers, /manager\s*email/i),
  };

  if (idx.userEmail === null) {
    throw new Error('CSV is missing required column: User Email.');
  }
  if (idx.sentDate === null) {
    throw new Error('CSV is missing required column: Sent Date (UTC).');
  }

  const rows       = [];
  const emailsSeen = new Set();

  for (let i = 1; i < lines.length; i++) {
    const cols = splitCsvRow(lines[i]);

    const userEmail = (idx.userEmail !== null ? cols[idx.userEmail] : '').trim();
    if (!userEmail) continue;

    const rawSentDate   = idx.sentDate       !== null ? (cols[idx.sentDate]       || '').trim() : '';
    const rawCompDate   = idx.completedDate  !== null ? (cols[idx.completedDate]  || '').trim() : '';
    const rawClicked    = idx.clicked        !== null ? (cols[idx.clicked]        || '').trim() : '';
    const rawElapsed    = idx.elapsedSeconds !== null ? (cols[idx.elapsedSeconds] || '').trim() : '';
    const rawQuizScore  = idx.quizScore      !== null ? (cols[idx.quizScore]      || '').trim() : '';

    const sentDate      = _parseDate(rawSentDate);
    const completedDate = _parseDate(rawCompDate);
    const clickedAt     = _parseDate(rawClicked);
    const elapsedSec    = rawElapsed && rawElapsed !== 'N/A' ? (parseInt(rawElapsed, 10) || null) : null;
    const quizScore     = rawQuizScore && rawQuizScore !== 'N/A' ? (parseFloat(rawQuizScore) || null) : null;

    emailsSeen.add(userEmail.toLowerCase());

    rows.push({
      userFirstName:     (idx.userFirst    !== null ? (cols[idx.userFirst]    || '').trim() : ''),
      userLastName:      (idx.userLast     !== null ? (cols[idx.userLast]     || '').trim() : ''),
      userEmail,
      managerFirstName:  (idx.managerFirst !== null ? (cols[idx.managerFirst] || '').trim() || null : null),
      managerLastName:   (idx.managerLast  !== null ? (cols[idx.managerLast]  || '').trim() || null : null),
      managerEmail:      (idx.managerEmail !== null ? (cols[idx.managerEmail] || '').trim() || null : null),
      sentDate,
      sessionType:       (idx.type  !== null ? (cols[idx.type]  || '').trim() : null),
      title:             (idx.title !== null ? (cols[idx.title] || '').trim() : null),
      status:            (idx.status !== null ? (cols[idx.status] || '').trim() : null),
      completedDate,
      elapsedSeconds:    elapsedSec,
      clickedAt,
      quizScore,
    });
  }

  if (rows.length === 0) {
    throw new Error('No valid session rows found in CSV.');
  }

  return {
    rows,
    stats: { totalRows: rows.length, uniqueUsers: emailsSeen.size },
  };
}

/** Parse a date string, returning ISO string or null for empty / 'N/A' values. */
function _parseDate(raw) {
  if (!raw || raw === 'N/A') return null;
  const d = new Date(raw);
  return isNaN(d.getTime()) ? null : d.toISOString();
}

module.exports = { parseAwarenessCSV, detectAwarenessFormat, parseSessionHistoryCSV };
