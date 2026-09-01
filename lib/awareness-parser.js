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
    // Two different things can be called "clicked": a timestamp column
    // ("Clicked (UTC)") and a yes/no column ("Clicked Link"). Prefer the
    // timestamp, because it carries strictly more information, but fall back
    // to whatever "clicked" column exists rather than losing the signal.
    clickedAt:      findCol(headers, /clicked.*\((utc|gmt)\)|clicked\s*(at|date|time|on)\b|date\s*clicked/i),
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
    const rawClickedAt  = idx.clickedAt      !== null ? (cols[idx.clickedAt]      || '').trim() : '';
    const rawClicked    = idx.clicked        !== null ? (cols[idx.clicked]        || '').trim() : '';
    const rawElapsed    = idx.elapsedSeconds !== null ? (cols[idx.elapsedSeconds] || '').trim() : '';
    const rawQuizScore  = idx.quizScore      !== null ? (cols[idx.quizScore]      || '').trim() : '';

    const sentDate      = _parseDate(rawSentDate);
    const completedDate = _parseDate(rawCompDate);
    /*
     * A timestamp column proves a click and dates it. A flag column proves a
     * click and does not. Both are supported; neither is invented from the
     * other, so `clicked` is the fact and `clickedAt` is the detail.
     *
     * Where only a flag exists, clickedAt stays null — inventing a time from
     * the sent date would fabricate evidence in a report that goes to clients.
     */
    const rawClickCell  = rawClickedAt || rawClicked;
    const hasClickCol   = idx.clickedAt !== null || idx.clicked !== null;
    const clickedAt     = _parseDate(rawClickCell);
    const clickedFlag   = _parseFlag(rawClickCell);

    let clicked;
    if (!hasClickCol)          clicked = null;   // no click column in the export
    else if (clickedAt)        clicked = true;   // dated click
    else if (clickedFlag !== null) clicked = clickedFlag;
    else if (_isBlank(rawClickCell)) clicked = false;  // empty cell means no click
    else                       clicked = null;   // present but unreadable — say so
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
      clicked,
      quizScore,
    });
  }

  if (rows.length === 0) {
    throw new Error('No valid session rows found in CSV.');
  }

  /*
   * How the click signal was read, so the UI can distinguish "nobody clicked"
   * from "this export never told us". The previous version had no way to say
   * the second thing, which is how a broken column read as a 99% click rate
   * and would now read as a flawless 0%.
   */
  const clickSource = idx.clickedAt !== null ? 'timestamp'
                    : idx.clicked   !== null ? 'flag'
                    : 'absent';

  return {
    rows,
    stats: {
      totalRows: rows.length,
      uniqueUsers: emailsSeen.size,
      clickSource,
      clickUnknown: rows.filter(r => r.clicked === null).length,
    },
  };
}

/**
 * Parse a date string, returning an ISO string or null.
 *
 * WHY THE BARE-NUMBER GUARD
 *
 * `new Date()` is far more permissive than it looks. It accepts a plain integer
 * as a YEAR, so a column holding 0/1 flags parses cleanly:
 *
 *   new Date('0')  -> 2000-01-01     new Date('1') -> 2001-01-01
 *
 * A phishing export whose "Clicked" column is a flag rather than a timestamp
 * therefore produced a valid clicked_at for EVERY row — including the rows
 * where the flag said 0, meaning not clicked. The click rate read 99% because
 * essentially every recipient had a date attached, and the one value that
 * should have meant "no" produced the year 1999.
 *
 * A bare number is never a timestamp in these exports, so it is refused. That
 * turns a plausible wrong answer into no answer, which the caller can see.
 */
/** Empty, or one of the placeholders an export uses to mean "nothing here". */
function _isBlank(raw) {
  const s = String(raw === null || raw === undefined ? '' : raw).trim();
  return !s || /^(n\/a|na|-|--|none|null|unknown)$/i.test(s);
}

function _parseDate(raw) {
  if (!raw) return null;

  const s = String(raw).trim();
  if (!s || /^(n\/a|na|-|--|none|null|unknown)$/i.test(s)) return null;

  // 0, 1, 45352, 3.5 — a flag or a spreadsheet serial, not a date we can trust.
  if (/^[+-]?\d+(\.\d+)?$/.test(s)) return null;

  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d.toISOString();
}

/**
 * Read a yes/no style value as a tri-state.
 *
 * Returns true, false, or null when the cell says nothing either way — because
 * "we were not told" and "they did not click" must not look the same. Counting
 * an unknown as a non-click is how a reporting gap turns into a clean bill of
 * health.
 */
function _parseFlag(raw) {
  if (raw === null || raw === undefined) return null;

  const s = String(raw).trim().toLowerCase();
  if (!s || /^(n\/a|na|-|--|none|null|unknown)$/.test(s)) return null;

  if (/^(y|yes|true|t|1|clicked|click)$/.test(s)) return true;
  if (/^(n|no|false|f|0|not clicked|no click)$/.test(s)) return false;

  return null;
}

module.exports = { parseAwarenessCSV, detectAwarenessFormat, parseSessionHistoryCSV };
