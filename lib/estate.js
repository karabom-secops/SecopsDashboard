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
  'serversPatched',
];

/*
 * `endpointsPatched` USED TO BE HERE and was removed.
 *
 * It was validated, clamped against its population, stored, echoed back to the
 * admin who typed it — and read by no scoring path whatsoever. The endpoint
 * yardstick is scoreEndpoints() in lib/secure-score.js, which measures agent
 * currency straight off the EDR feed and never looked at this number.
 *
 * A form field that changes nothing is worse than a missing one: it spends an
 * analyst's attention and buys a false sense that the estate is fully recorded.
 * EDR telemetry is better evidence for endpoint patch state than a typed count
 * in any case, so there was nothing to wire it into.
 */

const FIELD_LABELS = {
  servers:          'Servers',
  publicAssets:     'Public-facing assets / apps',
  endpoints:        'Endpoints',
  cloudTenancies:   'Cloud tenancies',
  users:            'Users',
  serversPatched:   'Servers under managed patching',
};

/**
 * AWARENESS PROGRAMME — who runs the training, when it is not run through us.
 *
 *   'platform' — run through this platform. Records land in awareness_uploads
 *                and are scored normally. Nothing special to do.
 *   'internal' — the client runs their own programme (an HR LMS, an in-house
 *                curriculum). The control plausibly exists; we have not seen it.
 *   'none'     — no programme. A zero here is earned, not an artefact.
 *   null       — not recorded. Behaves exactly as it did before this existed.
 *
 * WHY IT MATTERS
 *
 * calculateAwarenessScore only ever read awareness_uploads, so a client running
 * a perfectly good internal programme had no row, scored 0, and was told to
 * "upload training records" — advice for someone else's problem. Since headcount
 * began driving the split, awareness can carry ~45 of the 100 points for a large
 * client, so that mistake cost them close to half their posture for the offence
 * of not using our tooling.
 */
const AWARENESS_PROGRAMS = ['platform', 'internal', 'none'];

/**
 * What an unevidenced internal programme is worth.
 *
 * Deliberately the same shape as PATCH_RELIEF, and for the same reason: an
 * attestation may change how heavily a control WEIGHS, never what it SCORES. A
 * client who says "we train our people" and shows nothing gets the weight
 * halved — they are no longer judged as if they had no programme at all — but
 * they earn no points they have not evidenced. A relief of 1.0 would make
 * awareness a control that could be declared away in a dropdown.
 *
 * It lapses the moment figures exist: once the programme is measured it is
 * scored on its own numbers at full weight, so there is no double credit.
 */
const AWARENESS_RELIEF = 0.5;

/** Fields that describe a quantity of estate rather than a control over it. */
const SIZE_FIELDS = ['servers', 'publicAssets', 'endpoints', 'cloudTenancies', 'users'];

/** A managed-patching count can never exceed the population it covers. */
const PATCH_COVER = { serversPatched: 'servers' };

/**
 * Assets that constitute "infrastructure" for choosing a yardstick. Endpoints
 * are deliberately excluded: laptop patch state is endpoint management, and
 * counting them here would make every client look like they need a Nessus run.
 */
const INFRA_FIELDS = ['servers', 'publicAssets', 'cloudTenancies'];

/**
 * Assets the vulnerability scan ACTUALLY REACHES.
 *
 * The scan is external-facing only. Servers and cloud tenancies are in the
 * estate and carry real exposure, but this feed never touches them — their
 * posture is covered by managed patching instead (see PATCH_RELIEF).
 *
 * This distinction is load-bearing for scan coverage. Measuring the scan
 * against INFRA_FIELDS held clients who had scanned every external asset they
 * own at a coverage ceiling for owning internal servers:
 *
 *   3 public + 10 servers,  all 3 scanned -> read as 23% covered, capped at 23
 *   5 public + 40 servers,  all 5 scanned -> read as 11% covered, capped at 11
 *   2 public + 80 servers,  all 2 scanned -> read as  2% covered, capped at  2
 *
 * Every one of those had 100% coverage of what the scan can see. Coverage now
 * measures the scan against the population it addresses; the internal estate is
 * a genuine visibility gap, but a DIFFERENT one, and it is reported separately
 * rather than misattributed to a scan that was never in scope for it.
 */
const SCANNED_FIELDS = ['publicAssets'];

/** Assets in scope for the external scan (0 when none are recorded). */
function scannedAssets(estate) {
  const e = estate || {};
  return SCANNED_FIELDS.reduce((sum, f) => (e[f] === null || e[f] === undefined ? sum : sum + e[f]), 0);
}

/**
 * Infrastructure the vulnerability scan cannot reach: servers and cloud
 * tenancies. Their vulnerability posture rests on managed patching, so an
 * uncovered internal estate is a visibility gap in its own right.
 */
function unscannableAssets(estate) {
  const e = estate || {};
  return INFRA_FIELDS
    .filter(f => SCANNED_FIELDS.indexOf(f) < 0)
    .reduce((sum, f) => (e[f] === null || e[f] === undefined ? sum : sum + e[f]), 0);
}

/** One of AWARENESS_PROGRAMS, or null for "not recorded". */
function awarenessProgram(v) {
  if (v === null || v === undefined) return null;
  const s = String(v).trim().toLowerCase();
  return AWARENESS_PROGRAMS.indexOf(s) >= 0 ? s : null;
}

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

  const out = { sources: {}, declared: {}, derived: {} };

  DECLARED_FIELDS.forEach((f) => {
    const dec = count(d[f]);
    const der = count(t[f]);

    /*
     * BOTH HALVES ARE KEPT, not just the winner.
     *
     * This used to drop the derived figure on the floor the moment a
     * declaration existed, which is why nothing in this codebase could ever
     * notice the two disagreeing. A headcount typed eighteen months ago beat
     * today's EDR count silently, and "declared 120 endpoints, EDR protects
     * 50" — seventy machines with no agent — was not merely unreported, it
     * was unrepresentable.
     *
     * Declared still WINS: see the module header. Keeping the loser is what
     * makes reconcile() possible, and reconcile reports rather than adjusts.
     */
    out.declared[f] = dec;
    out.derived[f]  = der;

    if (dec !== null) { out[f] = dec; out.sources[f] = 'declared'; }
    else if (der !== null) { out[f] = der; out.sources[f] = 'derived'; }
    else { out[f] = null; out.sources[f] = 'unknown'; }
  });

  // When the declaration was last touched, and when someone last confirmed it
  // is still true. Not counts, so they bypass count(); both may be absent on a
  // database that predates the column.
  out.updatedAt  = d.updatedAt  || null;
  out.reviewedAt = d.reviewedAt || null;

  // Not a quantity, so it does not go through count(). Deliberately excluded
  // from anyDeclared below: declaring an awareness programme must not switch a
  // client onto exposure weighting while their asset counts are still blank —
  // an exposure of zero would hand them the 10% floor for free.
  out.awarenessProgram = awarenessProgram(d.awarenessProgram);

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

  // Split out for the score and for the report: what the external scan can
  // reach, and what it cannot. The second is not covered by this feed at all.
  out.scannableAssets   = scannedAssets(out);
  out.unscannableAssets = unscannableAssets(out);

  // The scan found MORE external hosts than the client says they have.
  //
  // Only meaningful against a DECLARED figure — where publicAssets is derived
  // from the scan the two are equal by construction. A declared count below the
  // scan's reach is not a rounding error: it is external assets that are not in
  // the client's own inventory, which is worth naming on its own terms.
  out.undeclaredExternal =
    (out.sources.publicAssets === 'declared' && out.scannedHosts !== null &&
     out.scannedHosts > out.publicAssets)
      ? out.scannedHosts - out.publicAssets
      : 0;

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
  // Only assets the scan can REACH make the scan yardstick applicable. Owning
  // forty internal servers is not a reason to be told to upload an external
  // scan — nothing in that scan would ever look at them.
  if (scannedAssets(e) > 0) return 'infrastructure';

  // Explicitly declared as having no infrastructure, but does have endpoints.
  if (e.infraDeclared && (e.endpoints || 0) > 0) return 'endpoint';

  // Not declared, but EDR shows endpoints and nothing suggests infrastructure.
  if (!e.infraDeclared && (e.endpoints || 0) > 0 && o.hasEdr) return 'endpoint';

  return 'unknown';
}

/**
 * The denominator for finding density: what the scan actually looked at.
 *
 * THIS USED TO TAKE THE LARGER of scanned hosts and the declared estate, and it
 * had the effect its own comment promised to prevent. With 20 weighted findings
 * from a scan of 4 hosts:
 *
 *   declared 4, scanned 4    -> density 6.25 -> score 32
 *   declared 50, scanned 4   -> density 0.50 -> score 86
 *
 * The client who scanned everything they own scored 32. The client who looked
 * at 8% of theirs scored 86 — the same as if they had scanned all 50. Declaring
 * more assets and scanning fewer of them RAISED the score, because unexamined
 * assets inflated the denominator without contributing any findings.
 *
 * That is backwards, and it contradicts the rule the rest of this engine runs
 * on: an unmeasured asset is an unmanaged one, not a clean one. So density is
 * now measured against the hosts that were genuinely examined, which is the
 * only population the findings say anything about. The unexamined remainder is
 * not diluted away here — it is charged for separately, as a coverage cap in
 * scoreInfrastructure(), where it is visible and explainable.
 *
 * Falls back to the declared estate only when scan scope is unknown (a scan
 * uploaded before scanned_hosts existed, or an Arctic Wolf register), which
 * preserves the old behaviour exactly for those.
 */
function scanDenominator(estate) {
  const e = estate || {};
  const hosts = count(e.scannedHosts);
  if (hosts !== null && hosts > 0) return hosts;
  // Unknown scope: fall back to the assets the scan ADDRESSES, never the whole
  // estate. Dividing external findings by a server count the scan never touched
  // was always wrong — it simply used to be invisible.
  return Math.max(1, scannedAssets(e));
}

/**
 * How much of the EXTERNAL-FACING estate the last scan actually reached.
 *
 * Measured against SCANNED_FIELDS, not the whole estate: a client with three
 * public assets and forty servers who scans all three has full coverage of what
 * the scan can see, and capping them at 7% for owning servers would be charging
 * them for a control that was never in scope.
 *
 * Null means UNKNOWN and must stay distinguishable from zero: a scan uploaded
 * before scope was recorded, or an Arctic Wolf register that never carries it,
 * is not a client with no coverage. The caller applies no cap on null.
 */
function scanCoverage(estate) {
  const e = estate || {};
  const declared = scannedAssets(e);
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

/**
 * How much of the awareness weight survives, given what the client has declared
 * and whether we actually have figures.
 *
 * Returns 1 in every case except the one this exists for: an internal programme
 * with nothing measured. Notably `none` gets no relief — a client who tells us
 * they run no training has told us the zero is real.
 *
 * @param {Object} estate
 * @param {Object} opts   { measured: boolean } — is awareness scored from data?
 */
function awarenessRelief(estate, opts) {
  const e = estate || {};
  const o = opts || {};
  if (o.measured) return 1;
  return e.awarenessProgram === 'internal' ? AWARENESS_RELIEF : 1;
}

/** Share of the declared headcount that training actually reached. */
function trainingCoverage(estate) {
  const e = estate || {};
  if (!e.users || e.trainedUsers === null || e.trainedUsers === undefined) return null;
  return Math.min(1, e.trainedUsers / e.users);
}

/*
 * ─────────────────────────────────────────────────────────────────────────────
 * STALENESS, RECONCILIATION AND GAPS
 *
 * Three questions an analyst looking at a client profile actually has, and
 * which the seven-box form it replaced could not answer:
 *
 *   estateAge     is this still true?
 *   reconcile     does it agree with what we can see?
 *   profileGaps   what is missing, and what is that costing them?
 *
 * THE RULE THAT GOVERNS ALL THREE: they report, they never adjust. Nothing
 * here changes a score, a weight or an effective value. A stale declaration
 * still wins over telemetry; a conflict is raised and the declared number is
 * left standing.
 *
 * That is not timidity, it is the whole point. This module exists because the
 * Secure Score moved for reasons nobody could point at. Replacing a silent
 * override with a silent expiry would reproduce the defect with a new name —
 * a client's score dropping because a date passed, which is even harder to
 * explain in a room than a number someone typed.
 * ─────────────────────────────────────────────────────────────────────────────
 */

/**
 * How long a declaration is trusted before it is flagged for review.
 *
 * Six months: long enough not to nag, short enough that a headcount or a
 * server count has not quietly doubled. Flagging only — see the rule above.
 */
const STALE_AFTER_DAYS = 180;

/**
 * When the estate was last confirmed, and whether that was too long ago.
 *
 * Reads `reviewedAt` in preference to `updatedAt`, so "I checked, it is still
 * correct" counts without anyone having to fake an edit.
 *
 * An estate nobody has ever recorded is NOT stale — it is absent, which is a
 * different problem with a different fix, and profileGaps() is where that
 * lives. Reporting it as stale would send an analyst looking for a number to
 * re-confirm that was never there.
 */
function estateAge(estate, now) {
  const e = estate || {};
  const at = e.reviewedAt || e.updatedAt || null;
  if (!at || !e.anyDeclared) return { at: null, days: null, stale: false };

  const then = at instanceof Date ? at : new Date(at);
  const ms = then.getTime();
  if (!Number.isFinite(ms)) return { at: null, days: null, stale: false };

  const nowMs = (now instanceof Date ? now : (now ? new Date(now) : new Date())).getTime();
  const days = Math.floor((nowMs - ms) / 86400000);
  return { at: then.toISOString(), days, stale: days >= STALE_AFTER_DAYS };
}

/**
 * Headcount and a training roster are allowed to disagree a little — someone
 * joined last week, someone left. Below this the difference is noise and
 * flagging it would train analysts to ignore the panel.
 *
 * Asset counts get no tolerance: one unmanaged server is worth naming.
 */
const HEADCOUNT_TOLERANCE = 0.05;

/**
 * Where the declaration and the telemetry disagree.
 *
 * Only fires on a field that was actually DECLARED and for which we also hold
 * a derived figure. Where the value came from telemetry in the first place the
 * two are equal by construction, and "the scan agrees with the scan" is not a
 * finding.
 *
 * @returns {Array<Object>} { field, label, declared, derived, delta, kind,
 *                            severity, meaning }
 */
function reconcile(estate) {
  const e = estate || {};
  const dec = e.declared || {};
  const der = e.derived  || {};
  const out = [];

  const add = (o) => out.push(o);
  const both = (f) => dec[f] !== null && dec[f] !== undefined &&
                      der[f] !== null && der[f] !== undefined;

  // ── External-facing assets, against what the scan reached ────────────────
  if (both('publicAssets')) {
    const delta = der.publicAssets - dec.publicAssets;
    if (delta > 0) {
      add({
        field: 'publicAssets', label: FIELD_LABELS.publicAssets,
        declared: dec.publicAssets, derived: der.publicAssets, delta,
        kind: 'undeclared-external', severity: 'high',
        meaning: 'The scan reached ' + delta + ' more external asset' +
          (delta === 1 ? '' : 's') + ' than the client has declared. These are ' +
          'internet-facing and absent from their own inventory.',
      });
    } else if (delta < 0) {
      add({
        field: 'publicAssets', label: FIELD_LABELS.publicAssets,
        declared: dec.publicAssets, derived: der.publicAssets, delta,
        kind: 'unscanned-external', severity: 'high',
        meaning: (-delta) + ' declared external asset' + (delta === -1 ? '' : 's') +
          ' the scan is not reaching. The vulnerability score is already capped ' +
          'at the coverage this implies; bringing them into scope lifts the cap.',
      });
    }
  }

  // ── Endpoints, against the EDR agent count ───────────────────────────────
  //
  // The declared-higher case is the one this whole rebuild was worth doing
  // for. It is not a data-quality nit: it is a count of machines with no agent
  // on them, and nothing in this codebase has ever surfaced it.
  if (both('endpoints')) {
    const delta = der.endpoints - dec.endpoints;
    if (delta < 0) {
      add({
        field: 'endpoints', label: FIELD_LABELS.endpoints,
        declared: dec.endpoints, derived: der.endpoints, delta,
        kind: 'unmanaged-endpoints', severity: 'high',
        meaning: (-delta) + ' of ' + dec.endpoints + ' declared endpoint' +
          (dec.endpoints === 1 ? '' : 's') + ' have no EDR agent reporting. ' +
          'They are unmonitored, and nothing in the score currently says so.',
      });
    } else if (delta > 0) {
      add({
        field: 'endpoints', label: FIELD_LABELS.endpoints,
        declared: dec.endpoints, derived: der.endpoints, delta,
        kind: 'undeclared-endpoints', severity: 'info',
        meaning: 'EDR is protecting ' + delta + ' more endpoint' +
          (delta === 1 ? '' : 's') + ' than the declared estate accounts for. ' +
          'The declared figure is probably out of date.',
      });
    }
  }

  // ── Headcount, against the training roster ───────────────────────────────
  //
  // trainedUsers is the size of the awareness roster, not a declared field, so
  // it is read off the estate directly rather than from derived{}.
  if (dec.users !== null && dec.users !== undefined && dec.users > 0 &&
      e.trainedUsers !== null && e.trainedUsers !== undefined) {
    const delta = e.trainedUsers - dec.users;
    if (Math.abs(delta) / dec.users > HEADCOUNT_TOLERANCE) {
      add({
        field: 'users', label: FIELD_LABELS.users,
        declared: dec.users, derived: e.trainedUsers, delta,
        kind: 'headcount-drift', severity: delta < 0 ? 'high' : 'info',
        meaning: delta < 0
          ? (-delta) + ' of ' + dec.users + ' staff are not on the awareness ' +
            'roster, so the awareness score describes only part of the ' +
            'organisation.'
          : 'The awareness roster carries ' + delta + ' more people than the ' +
            'declared headcount. One of the two figures is out of date.',
      });
    }
  }

  return out;
}

/**
 * What has not been recorded, and what that currently costs.
 *
 * Every entry is grounded in behaviour this engine actually has — the costs
 * are read off the same rules the scorer runs on, not invented as advice. The
 * first one in particular was previously buried in a hint paragraph while
 * being far and away the most expensive omission on the form.
 *
 * @param {Object} estate
 * @param {Object} [opts]  { hasScan, hasEdr, awarenessMeasured }
 */
function profileGaps(estate, opts) {
  const e = estate || {};
  const o = opts || {};
  const gaps = [];

  // Calls the real function rather than restating its conditions, so this
  // cannot drift away from what the scorer decides.
  if (vulnBasis(e, { hasScan: o.hasScan, hasEdr: o.hasEdr }) === 'unknown') {
    gaps.push({
      key: 'vuln-basis', severity: 'high',
      fields: ['servers', 'publicAssets', 'cloudTenancies'],
      title: 'Vulnerability management scores zero',
      cost: 'With no infrastructure recorded and no endpoint telemetry, there ' +
            'is no yardstick to measure against, so the component scores 0 — ' +
            'not "unknown", zero.',
      action: 'Record servers, public-facing assets and cloud tenancies. ' +
              'Entering 0 for all three is a valid answer and moves the client ' +
              'onto the endpoint measure instead.',
    });
  }

  if (e.users === null || e.users === undefined) {
    gaps.push({
      key: 'users', severity: 'medium', fields: ['users'],
      title: 'Weighting is not following headcount',
      cost: 'Awareness and incident response are splitting the remaining ' +
            'weight on the historical 35:25 fallback rather than on the size ' +
            'of the organisation.',
      action: 'Record the headcount.',
    });
  }

  if (e.servers && (e.serversPatched === null || e.serversPatched === undefined)) {
    gaps.push({
      key: 'serversPatched', severity: 'low', fields: ['serversPatched'],
      title: 'Managed patching is not being credited',
      cost: 'Patched servers carry up to half the exposure weight of unpatched ' +
            'ones. With nothing recorded the client is weighted as though none ' +
            'of their ' + e.servers + ' servers are patched.',
      action: 'Record how many servers are under managed patching.',
    });
  }

  if (!e.awarenessProgram && !o.awarenessMeasured) {
    gaps.push({
      key: 'awarenessProgram', severity: 'medium', fields: ['awarenessProgram'],
      title: 'Awareness scores zero at full weight',
      cost: 'No training records and no declared programme, so awareness is ' +
            'scored as though no training exists at all.',
      action: 'If the client runs their own programme, record it — the weight ' +
              'is halved pending evidence rather than the score being taken ' +
              'as a true zero.',
    });
  }

  return gaps;
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
  DECLARED_FIELDS, INFRA_FIELDS, SCANNED_FIELDS, SIZE_FIELDS, FIELD_LABELS,
  scannedAssets, unscannableAssets,
  EXPOSURE_POINTS, PATCH_RELIEF, HEADCOUNT_SHARE, PATCH_COVER,
  AWARENESS_PROGRAMS, AWARENESS_RELIEF, awarenessProgram, awarenessRelief,
  exposurePoints, patchCoverage, humanShare, trainingCoverage,
  resolveEstate, vulnBasis, scanDenominator, scanCoverage, describeEstate, count,
  STALE_AFTER_DAYS, HEADCOUNT_TOLERANCE, estateAge, reconcile, profileGaps,
};
