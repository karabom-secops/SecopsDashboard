'use strict';

/**
 * Third-party (vendor) inherent and residual risk scoring — the one
 * authoritative implementation.
 *
 * Same arrangement as lib/grc-score.js: the server computes the score on every
 * write and stores it, the API returns it, and both the Third-Party Risk tab
 * and the board report only read. The report deck runs in the browser and
 * cannot require() this file, so having the server own the number is the only
 * way the tab and the deck can never disagree.
 *
 * Scale is 1-25, the same as the Risk Register's likelihood x impact, so a
 * board reads both registers off one scale and the existing >=15 red / >=8
 * amber badge thresholds transfer unchanged.
 *
 * This is INHERENT risk derived from what the relationship owner recorded —
 * business criticality, the data the vendor touches, and the assurance
 * evidence held. It is not a tested assessment of the vendor's controls.
 */

/** Business impact if the vendor fails or is breached. */
const IMPACT_POINTS = { critical: 5, high: 4, medium: 3, low: 1 };

/** Exposure created by the data the vendor can reach. */
const EXPOSURE_POINTS = { regulated: 5, pii: 4, confidential: 3, internal: 2, none: 1 };

/** How much held assurance evidence reduces inherent risk. */
const ASSURANCE_FACTOR = {
  both:          0.6,
  soc2:          0.6,
  iso27001:      0.6,
  questionnaire: 0.8,
  none:          1.0,
};

/** Used when a field holds a value outside its CHECK list — score it worst-case. */
const DEFAULT_IMPACT   = 3;
const DEFAULT_EXPOSURE = 1;

/**
 * YYYY-MM-DD for a Date, a date string, or a Postgres DATE (which node-pg
 * hands back as a Date at local midnight). Returns null if unparseable.
 *
 * Comparison has to be date-only. `today` is a real timestamp in production
 * but the stored dates are midnight, so comparing the raw values would make a
 * certificate expire at one second past midnight on the day it is still valid.
 */
function dateKey(value) {
  if (!value) return null;
  if (typeof value === 'string') {
    // Already ISO-ish (a plain DATE, or a timestamp) — the first 10 chars are
    // the calendar day, with no timezone shift applied.
    if (/^\d{4}-\d{2}-\d{2}/.test(value)) return value.slice(0, 10);
  }
  const d = new Date(value);
  if (isNaN(d.getTime())) return null;
  const pad = (n) => String(n).padStart(2, '0');
  return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
}

/**
 * Is this vendor's assurance evidence still valid?
 *
 * A missing expiry date means the evidence does not expire (or nobody recorded
 * one), so it counts. An expiry in the past does not — an attestation nobody
 * renewed is the situation the date exists to surface, and treating it as
 * current would hide exactly the vendors worth chasing.
 */
function assuranceIsCurrent(vendor, today) {
  const exp = dateKey((vendor || {}).assurance_expires);
  if (!exp) return true;
  const ref = dateKey(today) || dateKey(new Date());
  return exp >= ref;
}

/**
 * scoreVendor — { inherent, residual }, both 1-25.
 *
 * @param {object} vendor  criticality, data_access, network_access, assurance,
 *                         assurance_expires
 * @param {string|Date} [today]  injected so tests are not date-dependent
 */
function scoreVendor(vendor, today) {
  const v = vendor || {};

  const impact = IMPACT_POINTS[v.criticality] || DEFAULT_IMPACT;

  // Network or system integration adds a step of exposure on top of the data
  // classification, because it is a path in regardless of what data is held.
  let exposure = EXPOSURE_POINTS[v.data_access] || DEFAULT_EXPOSURE;
  if (v.network_access) exposure += 1;
  if (exposure > 5) exposure = 5;

  const inherent = impact * exposure;

  const factor = assuranceIsCurrent(v, today)
    ? (ASSURANCE_FACTOR[v.assurance] != null ? ASSURANCE_FACTOR[v.assurance] : 1.0)
    : 1.0;

  // Floor at 1: the schema is NOT NULL and a vendor under management is never
  // zero risk, however good the paperwork.
  const residual = Math.max(1, Math.round(inherent * factor));

  return { inherent, residual };
}

/**
 * Is the vendor's scheduled review in the past?
 * Terminated vendors are excluded — chasing a review of a relationship that
 * has ended is noise.
 */
function isReviewOverdue(vendor, today) {
  const v = vendor || {};
  if (v.status === 'terminated') return false;
  const due = dateKey(v.next_review_date);
  if (!due) return false;
  return due < (dateKey(today) || dateKey(new Date()));
}

module.exports = {
  IMPACT_POINTS,
  EXPOSURE_POINTS,
  ASSURANCE_FACTOR,
  DEFAULT_IMPACT,
  DEFAULT_EXPOSURE,
  dateKey,
  assuranceIsCurrent,
  scoreVendor,
  isReviewOverdue,
};
