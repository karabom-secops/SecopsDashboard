'use strict';

/**
 * lib/arctic-wolf-coverage.js — one client's Arctic Wolf coverage score.
 *
 * ══ WHAT THIS NUMBER IS ══
 *
 * Arctic Wolf reports, per organisation, how completely its sensors and log
 * sources actually reach that org's estate. It arrives in the weekly SecOps
 * report, is parsed by lib/parser.js into data/weeks.json as `coverageScore` on
 * each org row, and is rendered as a bar on the Operations tab
 * (public/js/tab-orgs.js).
 *
 * It is a DEPLOYMENT-COMPLETENESS measure, not a performance one and not ours.
 *
 * ══ WHY IT IS READ HERE ══
 *
 * The Secure Score's `coverage` figure credits the FULL MDR weight to any
 * client recorded as buying MDR, however much of their estate Arctic Wolf can
 * actually see. For a client at 70% reach, roughly a third of the MDR weight
 * sits in estate the service is not onboarded against, and the board pack
 * reported it as fully covered — a claim the vendor's own number contradicts.
 *
 * This module supplies the figure that corrects it. See the `credit` block in
 * lib/secure-score.js, which multiplies the MDR WEIGHT by it and leaves every
 * SCORE alone.
 *
 * ══ NO FILE I/O, ON PURPOSE ══
 *
 * The caller reads data/weeks.json — server.js already has `readData` for it —
 * and passes the object in. Same reason lib/mdr-ingest.js takes an explicit
 * client: a module that opens files cannot be tested without a filesystem, and
 * this one decides how much of a client's posture counts as covered.
 *
 * ══ UNAVAILABLE IS NEVER ZERO ══
 *
 * The governing rule. A client we cannot find a score for must lose NOTHING:
 * `available:false` carries `credit:null`, the engine leaves the MDR weight
 * whole, and the page says why. Reading an absent score as 0 would wipe a
 * client's entire MDR coverage because somebody mistyped an organisation name,
 * which is the most damaging thing this file could do.
 *
 * A `coverageScore` of 0 that Arctic Wolf actually reported is a different
 * thing and does count. lib/parser.js:277 already keeps the two apart — a blank
 * column parses to null, never to zero — and that distinction is carried
 * through here unchanged.
 */

/** Attribution. Carried on every result so no caller has to hardcode it. */
const SOURCE = 'Arctic Wolf';
const METRIC = 'Coverage Score';

/**
 * Every way this can come back with no usable score. Each needs different
 * advice from whoever reads it, so they are never collapsed into one "no data".
 */
const REASONS = {
  NOT_LINKED:         'not_linked',
  NO_REPORT:          'no_report',
  ORG_NOT_FOUND:      'org_not_found',
  NO_SCORE_IN_REPORT: 'no_score_in_report',
};

/** Ordered list, so a UI can assert it has copy for every reason. */
const REASON_LIST = Object.keys(REASONS).map(k => REASONS[k]);

/**
 * Bands the Operations tab already uses (coverageCell in tab-orgs.js: <75 bad,
 * 75-89 warn, >=90 good). Restated here so the Secure Score tile and the
 * Organisations table cannot drift apart about what counts as poor reach.
 */
const BANDS = { low: 75, good: 90 };

/**
 * Age past which the figure is FLAGGED but still applied.
 *
 * Three weeks — two missed reports. Advisory only: the score is a real,
 * attributed measurement whatever its age, and suppressing it would silently
 * restore a discount the evidence does not support. Stating the age lets the
 * reader judge it, which is the same choice the firewall audit makes about a
 * stale config.
 */
const STALE_AFTER_DAYS = 21;

function bandFor(score) {
  if (score === null || score === undefined) return null;
  if (score < BANDS.low) return 'low';
  if (score < BANDS.good) return 'fair';
  return 'good';
}

/** Matching key ONLY — never stored, never displayed. See findOrg. */
function normaliseOrgKey(s) {
  return String(s == null ? '' : s).trim().toLowerCase().replace(/\s+/g, ' ');
}

/**
 * The profile field normaliser: trim and collapse, blank becomes null.
 *
 * `null` is the single representation of "not linked", so an empty string can
 * never sit in the column looking like a link that resolves to nothing.
 * Over-long input returns null so the caller can reject it rather than silently
 * truncating somebody's organisation name.
 */
const MAX_ORG_NAME = 200;
function orgNameField(v) {
  if (v === null || v === undefined) return null;
  const s = String(v).trim().replace(/\s+/g, ' ');
  if (!s) return null;
  return s.length > MAX_ORG_NAME ? null : s;
}

/** Org names in the newest week, for the profile form's datalist. */
function orgNamesInLatest(weeksData) {
  if (!weeksData || typeof weeksData !== 'object' || Array.isArray(weeksData)) return [];
  const keys = Object.keys(weeksData).sort().reverse();
  for (const k of keys) {
    const w = weeksData[k];
    if (w && Array.isArray(w.orgs) && w.orgs.length) {
      return w.orgs.map(o => o && o.orgName).filter(Boolean).map(String).sort();
    }
  }
  return [];
}

function emptyResult(reason, extra) {
  return Object.assign({
    linked: false,
    available: false,
    score: null,
    credit: null,
    band: null,
    requestedOrg: null,
    matchedOrg: null,
    matchedBy: null,
    weekKey: null,
    weekCommencing: null,
    ageDays: null,
    stale: false,
    candidates: [],
    reason,
    source: SOURCE,
    metric: METRIC,
  }, extra || {});
}

/**
 * Find an org row in one week.
 *
 * EXACT, after case-folding and whitespace collapse. Deliberately NOT fuzzy —
 * no prefix, substring or edit-distance matching. A loose match here attributes
 * one client's Arctic Wolf posture to another client's board report, which is a
 * cross-tenant data error wearing a convenience feature's clothes. `candidates`
 * exists so a human can fix a typo instead of the code guessing.
 */
function findOrg(week, key) {
  const orgs = (week && Array.isArray(week.orgs)) ? week.orgs : [];
  for (const o of orgs) {
    if (!o || o.orgName == null) continue;
    if (normaliseOrgKey(o.orgName) === key) return o;
  }
  return null;
}

/** Names sharing a first token with what was typed, to help correct it. */
function nearNames(weeksData, requested) {
  const first = normaliseOrgKey(requested).split(' ')[0];
  if (!first) return [];
  const seen = new Set();
  const out = [];
  Object.keys(weeksData).sort().reverse().forEach((k) => {
    const w = weeksData[k];
    if (!w || !Array.isArray(w.orgs)) return;
    w.orgs.forEach((o) => {
      if (!o || o.orgName == null || out.length >= 5) return;
      const name = String(o.orgName);
      if (seen.has(name)) return;
      if (normaliseOrgKey(name).split(' ')[0] === first) { seen.add(name); out.push(name); }
    });
  });
  return out;
}

/**
 * The newest coverage score recorded for one organisation.
 *
 * @param {object} weeksData  the whole data/weeks.json object, keyed by weekKey
 * @param {string} orgName    the org name recorded on the client's profile
 * @param {object} [opts]     { now } — injectable so age is testable
 *
 * WEEK SELECTION. Weeks are keyed `YYYY-MM-DD`, so a lexical descending sort is
 * a chronological one. The newest week carrying a SCORE for this org wins — not
 * simply the newest week — because one blank column in this week's export
 * should not silently remove a discount that a dated, attributed figure from
 * last week still supports. The week that produced the number is always
 * returned and displayed, so nothing is presented as more current than it is.
 *
 * `credit` is the only field the scoring engine consumes: score/100, in [0,1].
 */
function coverageForOrg(weeksData, orgName, opts) {
  const o = opts || {};
  const now = o.now instanceof Date ? o.now : new Date();

  const requested = orgNameField(orgName);
  if (!requested) return emptyResult(REASONS.NOT_LINKED);

  const linkedBase = { linked: true, requestedOrg: requested };

  if (!weeksData || typeof weeksData !== 'object' || Array.isArray(weeksData)) {
    return emptyResult(REASONS.NO_REPORT, linkedBase);
  }
  const weekKeys = Object.keys(weeksData).sort().reverse();
  if (!weekKeys.length) return emptyResult(REASONS.NO_REPORT, linkedBase);

  const key = normaliseOrgKey(requested);

  /*
   * Two different failures, kept apart: the org appears nowhere (fix the name)
   * versus the org appears with no score (chase the report). Collapsing them
   * sends somebody to correct a name that was already right.
   */
  let sawOrg = false;

  for (const weekKey of weekKeys) {
    const week = weeksData[weekKey];
    const org = findOrg(week, key);
    if (!org) continue;

    sawOrg = true;

    const raw = org.coverageScore;
    // null/undefined is "the report did not say" — keep looking at older weeks.
    // A numeric 0 is a real reported zero and stops the search.
    if (raw === null || raw === undefined || raw === '') continue;

    const n = Number(raw);
    if (!Number.isFinite(n)) continue;

    const score = Math.round(Math.min(100, Math.max(0, n)));

    // Age from the week the report COVERS — the date a reader recognises — not
    // from whenever the file happened to be written.
    const stamp = Date.parse(weekKey + 'T00:00:00Z');
    const ageDays = Number.isFinite(stamp)
      ? Math.max(0, Math.floor((now.getTime() - stamp) / 86400000))
      : null;

    return {
      linked: true,
      available: true,
      score,
      credit: score / 100,
      band: bandFor(score),
      requestedOrg: requested,
      // The name AS THE REPORT SPELLS IT, so a case-folded match is visible
      // rather than echoing back what the operator typed and looking exact.
      matchedOrg: String(org.orgName),
      matchedBy: String(org.orgName) === requested ? 'exact' : 'name-folded',
      weekKey,
      weekCommencing: week && week.weekCommencing ? String(week.weekCommencing) : null,
      ageDays,
      stale: ageDays !== null && ageDays >= STALE_AFTER_DAYS,
      candidates: [],
      reason: null,
      source: SOURCE,
      metric: METRIC,
    };
  }

  return sawOrg
    ? emptyResult(REASONS.NO_SCORE_IN_REPORT, linkedBase)
    : emptyResult(REASONS.ORG_NOT_FOUND,
        Object.assign({ candidates: nearNames(weeksData, requested) }, linkedBase));
}

/**
 * One sentence a human can read.
 *
 * Every branch names OUR data or OUR link, never the client's security: "we
 * could not find this org" is a statement about our records and must not read
 * as "this client has no coverage".
 */
function describe(cov) {
  if (!cov) return 'Arctic Wolf coverage was not looked up.';
  if (cov.available) {
    return SOURCE + ' reported ' + cov.score + '% coverage for "' + cov.matchedOrg +
      '" in the week of ' + (cov.weekCommencing || cov.weekKey) + '.' +
      (cov.stale ? ' That figure is ' + cov.ageDays + ' days old.' : '');
  }
  switch (cov.reason) {
    case REASONS.NOT_LINKED:
      return 'No Arctic Wolf organisation is linked to this client, so no MDR ' +
             'coverage discount is applied. Set it on the Client Profile.';
    case REASONS.NO_REPORT:
      return 'No weekly Arctic Wolf report has been uploaded, so no MDR coverage ' +
             'discount is applied.';
    case REASONS.ORG_NOT_FOUND:
      return 'The linked Arctic Wolf organisation was not found in any uploaded ' +
             'weekly report, so no MDR coverage discount is applied. Check the ' +
             'name matches the report exactly.' +
             (cov.candidates && cov.candidates.length
               ? ' Did you mean: ' + cov.candidates.join(', ') + '?' : '');
    case REASONS.NO_SCORE_IN_REPORT:
      return 'The linked Arctic Wolf organisation appears in the weekly report ' +
             'but carries no Coverage Score, so no MDR coverage discount is applied.';
    default:
      return 'Arctic Wolf coverage is unavailable.';
  }
}

module.exports = {
  coverageForOrg,
  describe,
  bandFor,
  normaliseOrgKey,
  orgNameField,
  orgNamesInLatest,
  REASONS,
  REASON_LIST,
  BANDS,
  STALE_AFTER_DAYS,
  MAX_ORG_NAME,
  SOURCE,
  METRIC,
};
