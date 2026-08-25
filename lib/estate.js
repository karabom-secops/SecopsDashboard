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
const DECLARED_FIELDS = [
  'servers', 'publicAssets', 'endpoints', 'cloudTenancies', 'users',
  'serversPatched', 'endpointsPatched',
];

const FIELD_LABELS = {
  servers:          'Servers',
  publicAssets:     'Public-facing assets / apps',
  endpoints:        'Endpoints',
  cloudTenancies:   'Cloud tenancies',
  users:            'Users',
  serversPatched:   'Servers under managed patching',
  endpointsPatched: 'Endpoints under managed patching',
};

/** Fields that describe a quantity of estate rather than a control over it. */
const SIZE_FIELDS = ['servers', 'publicAssets', 'endpoints', 'cloudTenancies', 'users'];

/** A managed-patching count can never exceed the population it covers. */
const PATCH_COVER = { serversPatched: 'servers', endpointsPatched: 'endpoints' };

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

  // Not declarable — facts about the data we hold, not about the estate.
  out.scannedHosts   = count(t.scannedHosts);
  out.trainedUsers   = count(t.trainedUsers);

  // A patched count above its population is a typo, and left alone it would
  // manufacture coverage above 100% and relief the client has not earned.
  Object.keys(PATCH_COVER).forEach((f) => {
    const pop = out[PATCH_COVER[f]];
    if (out[f] !== null && pop !== null && out[f] > pop) out[f] = pop;
  });

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

/**
 * EXPOSURE — how much of this client's risk an attacker can actually reach.
 *
 * Drives how heavily vulnerability management is WEIGHTED, which is a different
 * question from how well they are doing at it. A client whose entire external
 * surface is one website, with endpoints patched by an RMM, does not have forty
 * per cent of their security posture riding on infrastructure scanning — their
 * real risk sits with their people and their ability to respond. A client with
 * a dozen public applications and fifty servers very much does.
 *
 * Public-facing assets score highest because they are reachable from the
 * internet without a foothold. Servers and cloud tenancies score lower: real
 * exposure, but usually one step behind something else. Endpoints score zero —
 * they are assessed by the endpoint yardstick, and counting them here would
 * push every client with a laptop estate toward an infrastructure weighting
 * they have no use for.
 */
const EXPOSURE_POINTS = { publicAssets: 3, servers: 2, cloudTenancies: 2 };

/**
 * Managed patching is a real compensating control against exactly the risk the
 * vulnerability component measures — known, patchable software flaws — so it
 * reduces how much exposure a server represents.
 *
 * It reduces it by half at full coverage, not to nothing. Patching closes known
 * CVEs; it does nothing for misconfiguration, weak credentials, exposed
 * services or an unpatched appliance nobody put in the RMM. A control that
 * zeroed the weighting would be a control that could be declared away.
 */
const PATCH_RELIEF = 0.5;

/** What share of a population is under managed patching (null when unknown). */
function patchCoverage(estate, field) {
  const e = estate || {};
  const managed = e[field];
  const pop = e[PATCH_COVER[field]];
  if (managed === null || managed === undefined || !pop) return null;
  return Math.min(1, managed / pop);
}

function exposurePoints(estate) {
  const e = estate || {};
  const serverRelief = 1 - PATCH_RELIEF * (patchCoverage(e, 'serversPatched') || 0);

  return Object.keys(EXPOSURE_POINTS).reduce((sum, f) => {
    if (!e[f]) return sum;
    // Public-facing assets get no patch relief: an RMM patches operating
    // systems, not the application logic that makes a public app worth
    // attacking. Cloud tenancies likewise.
    const relief = f === 'servers' ? serverRelief : 1;
    return sum + e[f] * EXPOSURE_POINTS[f] * relief;
  }, 0);
}

/**
 * HEADCOUNT — how much of the remaining weight belongs to human risk.
 *
 * Exposure decides the vulnerability weight; headcount decides how what is left
 * splits between awareness and incident response. Ten people and ten thousand
 * people are not the same phishing target, and awareness completion is a
 * percentage, so scale cannot show up in the score itself — only in the weight.
 *
 * Returns awareness's share of the non-vulnerability remainder. An unknown
 * headcount returns null, and the caller keeps the historical 35:25 split.
 */
const HEADCOUNT_SHARE = { min: 0.45, max: 0.70, k: 150 };

function humanShare(estate) {
  const e = estate || {};
  const users = e.users;
  if (users === null || users === undefined) return null;
  const { min, max, k } = HEADCOUNT_SHARE;
  return min + (max - min) * (users / (users + k));
}

/** Share of the declared headcount that training actually reached. */
function trainingCoverage(estate) {
  const e = estate || {};
  if (!e.users || e.trainedUsers === null || e.trainedUsers === undefined) return null;
  return Math.min(1, e.trainedUsers / e.users);
}

/** One-line description of the estate for a report or a tooltip. */
function describeEstate(estate) {
  const e = estate || {};
  const parts = SIZE_FIELDS
    .filter(f => e[f] !== null && e[f] !== undefined)
    .map(f => e[f] + ' ' + FIELD_LABELS[f].toLowerCase());
  return parts.length ? parts.join(', ') : 'not recorded';
}

module.exports = {
  DECLARED_FIELDS, INFRA_FIELDS, SIZE_FIELDS, FIELD_LABELS,
  EXPOSURE_POINTS, PATCH_RELIEF, HEADCOUNT_SHARE, PATCH_COVER,
  exposurePoints, patchCoverage, humanShare, trainingCoverage,
  resolveEstate, vulnBasis, scanDenominator, scanCoverage, describeEstate, count,
};
