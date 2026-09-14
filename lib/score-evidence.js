'use strict';

/**
 * lib/score-evidence.js — the facts behind one month of the Secure Score.
 *
 * A trend line says the score moved. It does not say WHY, and "72 → 78" is the
 * one sentence a board cannot act on. This module gathers, for a month, the
 * underlying numbers each component was computed from — findings by severity,
 * training completion, incidents raised and resolved — so a change can be
 * explained in terms of what happened rather than in terms of arithmetic.
 *
 * ONE IMPLEMENTATION, TWO CALLERS. /api/secure-score/history (staff) and
 * /api/portal/secure-score (client) both explain the same months. Two copies
 * of "what counts as completed by the month end" is how the portal and the
 * dashboard end up telling a client two different stories about one August.
 * reconstructComponents() in server.js reads the awareness counts from here
 * for the same reason.
 *
 * Pure: no database. Callers query; this counts.
 */

const mdrMetrics = require('../public/js/mdr-metrics');

/** Last instant of a 'YYYY-MM' month, as an ISO string (UTC, like every period filter). */
function monthEnd(monthKey) {
  const [y, m] = String(monthKey).split('-').map(Number);
  return new Date(Date.UTC(y, m, 1) - 1).toISOString();
}

function isoOrNull(v) {
  if (v === null || v === undefined || v === '') return null;
  const d = v instanceof Date ? v : new Date(String(v));
  return isNaN(d.getTime()) ? null : d.toISOString();
}

const n = v => (Number.isFinite(Number(v)) ? Number(v) : 0);

/**
 * The scan in force for a month: that month's, or the most recent before it.
 *
 * Findings persist until the next scan, which is how the history route already
 * scores a month with no scan. `carried` says so, because "critical findings
 * unchanged" means something very different when nobody scanned.
 *
 * CAVEAT: vuln_scans.summary is rebuilt whenever a finding's status changes, so
 * an old scan's counts reflect what has been closed SINCE, not what was open at
 * the time. The same caveat already applies to the reconstructed score.
 */
function vulnerabilityEvidence(scans, monthKey) {
  let found = null;
  (Array.isArray(scans) ? scans : []).forEach((s) => {
    const key = s && (s.month_key || s.monthKey);
    if (!key || key > monthKey) return;
    if (!found || key > (found.month_key || found.monthKey)) found = s;
  });
  if (!found) return null;
  const sum = found.summary || {};
  const scanMonth = found.month_key || found.monthKey;
  return {
    scanMonth,
    carried: scanMonth !== monthKey,
    critical: n(sum.critical),
    high: n(sum.high),
    medium: n(sum.medium),
    low: n(sum.low),
  };
}

/**
 * Training assigned and completed by the month end.
 *
 * Phishing simulations are expected to have been excluded by the caller's
 * query, matching the live score. Returns null, not zeroes, when nothing had
 * been sent yet — not recorded is not none.
 */
function awarenessEvidence(sessions, monthKey) {
  const end = monthEnd(monthKey);
  let assigned = 0;
  let completed = 0;
  (Array.isArray(sessions) ? sessions : []).forEach((s) => {
    const sent = isoOrNull(s && (s.sent_date || s.sentDate));
    if (!sent || sent > end) return;
    assigned++;
    const done = isoOrNull(s.completed_date || s.completedDate);
    if (done && done <= end) completed++;
  });
  if (!assigned) return null;
  return { assigned, completed, pct: Math.round((completed / assigned) * 100) };
}

/**
 * That month's incident cohort — the same function the score and the report
 * KPIs use, trimmed to what an explanation needs.
 *
 * Null when the feed has nothing raised in the month AND nothing at all, so a
 * client with no MDR feed is not told they had "no incidents".
 */
function incidentEvidence(tickets, monthKey, opts) {
  const list = Array.isArray(tickets) ? tickets : [];
  if (!list.length && !(opts && opts.feedExists)) return null;
  const s = mdrMetrics.cohortStats(list, monthKey);
  return {
    raised: s.raised,
    resolved: s.resolved,
    stillOpen: s.stillOpen,
    resolutionRate: s.resolutionRate,
    meanHours: s.meanHours == null ? null : Math.round(s.meanHours * 10) / 10,
    typeFiltered: s.typeFiltered,
  };
}

/**
 * Everything for one month, keyed by the Secure Score component names.
 *
 * @param {Object} src       { scans, sessions, tickets, feedExists }
 * @param {string} monthKey  'YYYY-MM'
 */
function evidenceFor(src, monthKey) {
  const s = src || {};
  return {
    vulnerabilities:  vulnerabilityEvidence(s.scans, monthKey),
    awareness:        awarenessEvidence(s.sessions, monthKey),
    incidentResponse: incidentEvidence(s.tickets, monthKey, { feedExists: s.feedExists }),
  };
}

module.exports = {
  monthEnd,
  vulnerabilityEvidence,
  awarenessEvidence,
  incidentEvidence,
  evidenceFor,
};
