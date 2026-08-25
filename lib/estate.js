'use strict';

/**
 * lib/estate.js — what a client actually has.
 *
 * WHY THIS EXISTS
 *
 * The Secure Score used to judge every client against the same yardstick: an
 * absolute count of vulnerability findings. That is wrong in both directions.
 *
 *   - A client with three servers and a dozen laptops scored zero on 40% of
 *     their posture for not running an infrastructure scan they have little
 *     reason to run. The nought said "you have failed" when the truth was
 *     "this control does not apply to you".
 *
 *   - A client with two thousand assets scored zero as well, because the old
 *     penalty (critical x20, high x10, medium x5, low x1) saturates almost
 *     immediately. One hundred LOW findings alone scored zero. At that point
 *     the metric stops distinguishing anything: a small shop with five
 *     criticals and an enterprise with five criticals, twenty highs, a hundred
 *     mediums and three hundred lows both read 0/100.
 *
 * Both problems have the same root: the score never knew how big the estate
 * was. This module is that missing denominator.
 *
 * DECLARED vs DERIVED
 *
 * Endpoints and scanned hosts are already knowable — edr_agents holds one row
 * per endpoint, and an uploaded scan names the hosts it touched. Servers,
 * public-facing assets and cloud tenancies are not recorded anywhere, so they
 * have to be declared. Declared always wins over derived: someone who has
 * typed a number is asserting something the telemetry cannot see (an
 * unmanaged server, a site behind a CDN), and silently overriding them with a
 * count of EDR agents would be worse than useless.
 */

/** Fields an admin declares. */
const DECLARED_FIELDS = ['servers', 'publicAssets', 'endpoints', 'cloudTenancies'];

const FIELD_LABELS = {
  servers:        'Servers',
  publicAssets:   'Public-facing assets / apps',
  endpoints:      'Endpoints',
  cloudTenancies: 'Cloud tenancies',
};

/**
 * Assets an infrastructure vulnerability scan is expected to cover. Endpoints
 * are deliberately excluded: laptop patch state is endpoint management, and
 * counting them here would make every client look like they need a Nessus run.
 */
const INFRA_FIELDS = ['servers', 'publicAssets', 'cloudTenancies'];

/** A non-negative integer, or null when nothing usable was supplied. */
function count(v) {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0) return null;
  return Math.floor(n);
}

/**
 * resolveEstate — merge what was declared with what was derived.
 *
 * @param {Object} declared  admin-entered row (may be null)
 * @param {Object} derived   { endpoints, scannedHosts } from telemetry
 * @returns {Object} the effective estate plus provenance for each field
 */
function resolveEstate(declared, derived) {
  const d = declared || {};
  const t = derived || {};

  const out = { sources: {} };

  DECLARED_FIELDS.forEach((f) => {
    const dec = count(d[f]);
    const der = count(t[f]);
    if (dec !== null) { out[f] = dec; out.sources[f] = 'declared'; }
    else if (der !== null) { out[f] = der; out.sources[f] = 'derived'; }
    else { out[f] = null; out.sources[f] = 'unknown'; }
  });

  // Not declarable — it is a fact about the last scan, not about the estate.
  out.scannedHosts = count(t.scannedHosts);

  out.infraAssets = INFRA_FIELDS.reduce(
    (sum, f) => (out[f] === null ? sum : sum + out[f]), 0);

  // "Declared as zero" and "never filled in" are different claims and the score
  // treats them differently, so the distinction has to survive to the caller.
  out.infraDeclared = INFRA_FIELDS.some(f => out.sources[f] === 'declared');
  out.anyDeclared   = DECLARED_FIELDS.some(f => out.sources[f] === 'declared');
  out.isEmpty       = DECLARED_FIELDS.every(f => out[f] === null);

  return out;
}

/**
 * Which yardstick applies to this client?
 *
 *   'infrastructure'  — servers, public-facing assets or cloud in scope, so an
 *                       infrastructure scan is the right measure.
 *   'endpoint'        — endpoints only. Measured on patch currency and agent
 *                       health, which is what endpoint hygiene actually means.
 *   'unknown'         — nothing declared and no telemetry. Cannot be judged.
 *
 * A scan that has been uploaded always counts as infrastructure scope, whatever
 * the estate says: someone has scanned something, and ignoring the result
 * because a form was left blank would be perverse.
 */
function vulnBasis(estate, opts) {
  const e = estate || {};
  const o = opts || {};

  if (o.hasScan) return 'infrastructure';
  if ((e.infraAssets || 0) > 0) return 'infrastructure';

  // Explicitly declared as having no infrastructure, but does have endpoints.
  if (e.infraDeclared && (e.endpoints || 0) > 0) return 'endpoint';

  // Not declared, but EDR shows endpoints and nothing suggests infrastructure.
  if (!e.infraDeclared && (e.endpoints || 0) > 0 && o.hasEdr) return 'endpoint';

  return 'unknown';
}

/**
 * The denominator for finding density.
 *
 * Prefers the hosts the scan actually touched — a scan of 4 of 50 servers says
 * more about those 4 than about the estate — but never lets a tiny scan of a
 * large declared estate flatter the density, and never divides by zero.
 */
function scanDenominator(estate) {
  const e = estate || {};
  const hosts = count(e.scannedHosts);
  const declared = e.infraAssets || 0;
  return Math.max(1, hosts || 0, declared);
}

/** How much of the declared infrastructure the last scan actually reached. */
function scanCoverage(estate) {
  const e = estate || {};
  const declared = e.infraAssets || 0;
  const hosts = count(e.scannedHosts);
  if (!declared || hosts === null) return null;
  return Math.min(1, hosts / declared);
}

/** One-line description of the estate for a report or a tooltip. */
function describeEstate(estate) {
  const e = estate || {};
  const parts = DECLARED_FIELDS
    .filter(f => e[f] !== null && e[f] !== undefined)
    .map(f => e[f] + ' ' + FIELD_LABELS[f].toLowerCase());
  return parts.length ? parts.join(', ') : 'not recorded';
}

module.exports = {
  DECLARED_FIELDS, INFRA_FIELDS, FIELD_LABELS,
  resolveEstate, vulnBasis, scanDenominator, scanCoverage, describeEstate, count,
};
