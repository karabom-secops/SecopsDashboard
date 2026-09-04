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
const { SEVERITIES, CATEGORIES } = require('./fortigate-checks');

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
function scoreResults(results, opts) {
  const list = Array.isArray(results) ? results : [];
  /*
   * The per-category rollup calls this function again on a filtered list. That
   * inner call MUST NOT roll up again: a single-category subset still matches
   * its own category, so without this the recursion never terminates. It did
   * not, the first time this was written — the comment said "one level" and
   * nothing enforced it, which is exactly the kind of claim a flag should make
   * true rather than a comment assert.
   */
  const withCategories = !(opts && opts.skipCategories);

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

  /*
   * Per-category scores, computed by the SAME function on a filtered list.
   *
   * Recursion of one level, deliberately: a category score that used different
   * arithmetic from the overall score is how a report ends up with five
   * categories that do not reconcile with the headline. Everything that is true
   * of the overall score — not-assessable leaves the denominator, null is not
   * zero, coverage travels with it — is true of each category because it is
   * literally the same code.
   *
   * A category with nothing assessable scores null and says so, rather than
   * appearing as a zero the client will read as a failure in that area.
   */
  const byCategory = !withCategories ? [] : CATEGORIES.map((c) => {
    const subset = list.filter(r => r.category === c.key);
    if (!subset.length) return null;
    const s = scoreResults(subset, { skipCategories: true });
    return {
      key: c.key,
      label: c.label,
      blurb: c.blurb,
      order: c.order,
      score: s.score,
      band: s.band,
      total: s.total,
      assessed: s.assessed,
      passed: s.passed,
      failed: s.failed,
      notAssessable: s.notAssessable,
      coverage: s.coverage,
      bySeverity: s.bySeverity,
    };
  }).filter(Boolean).sort((a, b) => a.order - b.order);

  /*
   * Findings whose check carries no category at all. Surfaced rather than
   * dropped: a check that matches no prefix is a naming mistake, and a rollup
   * that quietly omits it is how it stays a mistake.
   */
  const uncategorised = list.filter(r => !r.category).map(r => r.id);

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
    byCategory,
    uncategorised,
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
    // The category is the finding's heading, not part of the map — it says
    // WHICH KIND of weakness this is, which the client needs in order to read
    // the report, and tells an attacker nothing they could not guess.
    category: r.category || null,
    cis: r.cis || null,
    source: r.source,
    rationale: r.rationale,
    remediation: r.remediation,
  };
}

module.exports = { scoreResults, publicFinding, pointsFor, band };
