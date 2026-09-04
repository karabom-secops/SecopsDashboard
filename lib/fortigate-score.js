'use strict';

/**
 * lib/fortigate-score.js — a posture score from a set of check results.
 *
 * THE RULE THAT MATTERS: `not-assessable` LEAVES THE DENOMINATOR.
 *
 * It is not a pass and it is not a fail. A check we could not evaluate — the
 * section was absent, the field does not exist on this model, or "Password
 * mask" blanked the value — contributes nothing in either direction, and the
 * result reports how much of the benchmark it was actually able to cover.
 *
 * Scoring an unassessable check as a failure would mean a client who masked
 * their config, which is the responsible way to send one, was penalised for it.
 * Scoring it as a pass would mean a config we could barely read came back
 * clean. Both are worse than saying "22 of 30, and here is what we could not
 * see".
 *
 * WHAT THIS DOES NOT PROMISE, because the arithmetic will not carry it:
 * a masked config does not always score the SAME as the unmasked original.
 * Dropping a check from the denominator moves the percentage in whichever
 * direction that check was pointing — lose a pass from a mostly-failing config
 * and the score falls slightly. That is a different subset being scored, not a
 * penalty, and `coverage` is reported beside the score so the reader can see
 * it happened.
 *
 * The guarantee that IS made, and is tested: masking never turns a pass into a
 * fail and never introduces a failure. Anything it hides becomes
 * not-assessable, and the finding says to confirm it on the device.
 *
 * This is the same rule lib/grc-score.js applies to `na` answers, and it
 * borrows that module's severity weights rather than inventing a second scale —
 * a "high" finding here and a "high" control there should mean the same thing
 * when they land on the same page.
 */

const { WEIGHT_POINTS, DEFAULT_POINTS } = require('./grc-score');
const { SEVERITIES } = require('./fortigate-checks');

/** Points a check is worth, by severity. Falls back exactly as GRC does. */
function pointsFor(severity) {
  const p = WEIGHT_POINTS[String(severity || '').toLowerCase()];
  return p === undefined ? DEFAULT_POINTS : p;
}

/** Bands for a posture score. Same shape as the Secure Score's. */
function band(score) {
  if (score == null) return { key: 'unknown', label: 'Not assessed' };
  if (score >= 90) return { key: 'excellent', label: 'Excellent' };
  if (score >= 75) return { key: 'good',      label: 'Good' };
  if (score >= 50) return { key: 'fair',      label: 'Fair' };
  return { key: 'poor', label: 'Poor' };
}

/**
 * Score a set of results from runChecks().
 *
 * @returns {Object} score (0-100 or null), coverage, counts and severity rollup
 */
function scoreResults(results) {
  const list = Array.isArray(results) ? results : [];

  let earned = 0;
  let possible = 0;
  let passed = 0;
  let failed = 0;
  let notAssessable = 0;

  const bySeverity = {};
  SEVERITIES.forEach((s) => { bySeverity[s] = { pass: 0, fail: 0, 'not-assessable': 0 }; });

  list.forEach((r) => {
    const sev = SEVERITIES.indexOf(r.severity) >= 0 ? r.severity : 'medium';
    const pts = pointsFor(sev);

    if (r.status === 'not-assessable') {
      notAssessable++;
      bySeverity[sev]['not-assessable']++;
      return;                       // out of the denominator entirely
    }

    possible += pts;
    if (r.status === 'pass') { earned += pts; passed++; bySeverity[sev].pass++; }
    else                     { failed++;              bySeverity[sev].fail++; }
  });

  const assessed = passed + failed;

  // NULL, NOT ZERO. A config where nothing could be assessed has no score —
  // reporting 0 would say the firewall failed everything, which is the opposite
  // of what happened.
  const score = possible > 0 ? Math.round((earned / possible) * 100) : null;

  return {
    score,
    band: band(score),
    total: list.length,
    assessed,
    passed,
    failed,
    notAssessable,
    // What share of the benchmark this config actually answered. A low coverage
    // with a high score is not a good result, and the page has to be able to
    // say so.
    coverage: list.length ? Math.round((assessed / list.length) * 100) : 0,
    points: { earned, possible },
    bySeverity,
    // Failures worth leading with, worst first, then by the order they were
    // defined so the same config always reports in the same order.
    topFailures: list
      .filter(r => r.status === 'fail')
      .sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity))
      .map(r => ({ id: r.id, title: r.title, severity: r.severity, detail: r.detail })),
  };
}

/**
 * The client-facing projection of a finding.
 *
 * WHAT IS DELIBERATELY LEFT OUT: `evidence`.
 *
 * A finding's evidence names policy ids, interface names and tunnel names —
 * together, a working map of where this client's firewall is weakest. The
 * portal withholds the vulnerability finding list for exactly this reason, and
 * this is the same document in a different format.
 *
 * What the client gets is the finding, how serious it is, and what to do about
 * it: everything needed to act, nothing that helps somebody else act first.
 * Built as an allowlist, so a field added to a finding later is withheld by
 * default rather than published because nobody updated a blocklist.
 */
function publicFinding(r) {
  return {
    id: r.id,
    title: r.title,
    severity: r.severity,
    status: r.status,
    cis: r.cis || null,
    source: r.source,
    rationale: r.rationale,
    remediation: r.remediation,
  };
}

module.exports = { scoreResults, publicFinding, pointsFor, band };
