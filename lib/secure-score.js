'use strict';

/**
 * Secure Score calculation engine.
 * Combines vulnerability, awareness, and MDR metrics into a 0-100 composite.
 *
 * ── Missing data scores ZERO ──────────────────────────────────────────────
 *
 * The governing rule, and the one this engine used to get backwards: an
 * UNMEASURED control is an UNMANAGED control. If no vulnerability scan has
 * ever been uploaded, that is not evidence of no vulnerabilities — it is
 * evidence of no visibility, which is a worse security position than a scan
 * showing findings you at least know about.
 *
 * Previously `calculateVulnScore` returned 100 for absent data, commented
 * "No vulns = perfect score", and `calculateMdrScore` returned 100 for absent
 * data, commented "No data = no penalty". A client who had never uploaded
 * anything therefore scored 100 on both — a perfect vulnerability posture for
 * having never looked. Awareness meanwhile returned 0 for the same situation,
 * so the three components disagreed with each other about what absence meant.
 *
 * All three now score 0 when unmeasured, and report WHY, so a nought caused by
 * a missing upload is never mistaken for a nought earned by a bad result.
 *
 * ── Not measured vs measured-and-clean ────────────────────────────────────
 *
 * These are different security situations and must not collapse together:
 *   - no scan uploaded          -> unmeasured -> 0
 *   - scan uploaded, 0 findings -> measured   -> 100 (genuinely earned)
 *
 * ── Sized to the estate ───────────────────────────────────────────────────
 *
 * "Unmeasured scores zero" is right only where the control APPLIES. Applied
 * blindly it punished clients who have no infrastructure to scan, and the
 * absolute penalty it used saturated so fast that any real estate scored zero
 * anyway — one hundred LOW findings alone reached 0/100.
 *
 * The vulnerability component is therefore scored against what the client
 * actually has (see lib/estate.js), by one of two yardsticks:
 *
 *   infrastructure — servers, public-facing assets or cloud in scope. Scored on
 *                    finding DENSITY per asset, so a large estate is not doomed
 *                    by arithmetic, with an absolute cap for open criticals so
 *                    a dangerous finding cannot be diluted away.
 *
 *   endpoint       — endpoints only. Scored on patch currency and agent health
 *                    from the EDR feed, which is what endpoint hygiene means.
 *                    No infrastructure scan is expected or penalised.
 *
 * Only a client whose estate is unknown AND who has supplied nothing scores a
 * zero for absence — and it is reported as 'unknown', not as a failure.
 *
 * ── Weighted by service mix ───────────────────────────────────────────────
 *
 * The weights follow WHAT THE CLIENT BUYS — a fixed profile per service mix,
 * see resolveWeights(). They used to ride curves over the declared estate and
 * the declared headcount, which meant a number typed into the Client Profile
 * moved a board-reported composite by up to fourteen points, and merely
 * starting to fill the form moved it nine.
 *
 * A service mix is a contractual fact: it changes rarely, deliberately, on a
 * date somebody can point at. So the weights are stable between contract
 * changes and the score moves only when the EVIDENCE moves, which is the only
 * thing a client should ever have to explain to their board.
 *
 * The declared estate still selects the vulnerability YARDSTICK (see
 * lib/estate.js vulnBasis) and still caps the score by scan coverage. It sets
 * no weight.
 */

const estateLib = require('./estate');
const servicesLib = require('./services');

const WEIGHTS = { vulnerabilities: 0.40, awareness: 0.35, incidentResponse: 0.25 };

/* ── Two levers that were removed, and why ────────────────────────────────
 *
 * EXPOSURE_WEIGHT rode a saturating curve over the declared estate; INCIDENT_PULL
 * divided the remainder by ticket load. Both are gone, along with the headcount
 * curve in lib/estate.js. See resolveWeights() below for what replaced them.
 *
 * The exposure curve was the defect: it read numbers typed into the Client
 * Profile, so one edit moved a board-reported composite by up to fourteen
 * points.
 *
 * The incident pull was NOT typed — it came from ticket dates — and it is worth
 * recording why it went too:
 *
 *   It was discontinuous. incidentRateFrom() returns null below RATE_MIN_DATED
 *   dated tickets, so the fifth dated ticket flipped the pull from 1.0 and
 *   re-split the whole non-vulnerability remainder. Same cliff, different lever.
 *
 *   It measured upload behaviour, not risk. mdr_uploads has no period, so a
 *   dense three-day export read as one busy month and a two-year export read as
 *   a quiet one. A client's weighting followed how much CSV somebody exported.
 *
 *   It charged twice. Ticket volume already moves calculateMdrScore through the
 *   resolution rate and the speed penalty.
 *
 * The RATE ITSELF is still computed and still reported — incidentRateFrom below
 * is untouched. It is published as a fact about the client rather than used to
 * re-weight them.
 */

/**
 * incidentRateFrom — tickets per month, from the ticket dates themselves.
 *
 * Kept here rather than inline in the query so the arithmetic is testable
 * without a database, because two things about it are easy to get wrong:
 *
 *   - mdr_uploads HAS NO PERIOD. `total_tickets` is however much CSV someone
 *     uploaded — a month for most clients, two years for anyone who exported
 *     their whole history. Counting rows would say a client who uploaded more
 *     history is under heavier attack.
 *   - A SHORT SAMPLE MUST NOT BE EXTRAPOLATED. Three days scaled to a month
 *     turns a quiet week into a crisis, so the divisor is floored at one month:
 *     a dense short upload reads as one busy month, never as ten.
 *
 * @param {Object} span  { dated, firstAt, lastAt } straight off the query
 * @returns {number|null} tickets per month, or null when unknowable
 */
const RATE_MIN_DATED = 5;
const DAYS_PER_MONTH = 30.44;

function incidentRateFrom(span) {
  const s = span || {};
  const dated = Number(s.dated);
  // The parser leaves created_at null when the CSV carried no usable date, so a
  // feed can exist with no dates at all. That is unknown, not zero.
  if (!Number.isFinite(dated) || dated < RATE_MIN_DATED) return null;
  if (!s.firstAt || !s.lastAt) return null;

  const first = new Date(s.firstAt).getTime();
  const last  = new Date(s.lastAt).getTime();
  if (!Number.isFinite(first) || !Number.isFinite(last)) return null;

  const spanDays = (last - first) / 86400000;
  if (!Number.isFinite(spanDays) || spanDays < 0) return null;

  const months = Math.max(1, spanDays / DAYS_PER_MONTH);
  return Math.round((dated / months) * 10) / 10;
}

/* ── Weighting by service mix ──────────────────────────────────────────────
 *
 * THE PROBLEM THIS REPLACES.
 *
 * The weights used to ride two curves over the DECLARED estate: a saturating
 * exposure curve on public assets, servers and cloud tenancies, and a headcount
 * curve on the declared user count. Both read numbers a human types into the
 * Client Profile, and nothing else moved them — telemetry alone leaves
 * `anyDeclared` false, so a client with full EDR and a live scan still got the
 * flat fallback. The weighting was, in practice, one hundred per cent typed.
 *
 * Measured on one fixed set of findings, changing only what was typed:
 *
 *   nothing declared        composite 31
 *   publicAssets: 1         composite 40      <- +9 for typing one digit
 *   publicAssets: 50        composite 26
 *   users: 20 -> 2000       composite 29 -> 41
 *
 * So a single form field moved a board-reported number by up to fourteen
 * points, and merely STARTING to fill the form moved it nine — the old
 * basis:'default' -> basis:'exposure' cliff. A figure printed for a client's
 * board cannot move that far on data entry, and an analyst correcting a typo
 * should not be rewriting the client's security posture.
 *
 * WHAT DRIVES THEM NOW.
 *
 * The service mix: which of Managed Detection & Response, Vulnerability
 * Management and Security Awareness Training the client actually buys. That is
 * a contractual fact — it changes rarely, deliberately, on a date somebody can
 * point at — so the weights are stable between contract changes and the score
 * moves only when the evidence moves.
 *
 * WHY EVERY COMPONENT KEEPS A NON-ZERO WEIGHT.
 *
 * `coverage` is defined as the sum of the weights of the components the
 * client's services cover. If the weight collapsed onto only what they buy,
 * every client would cover 100% of their own weighting by construction and
 * coverage would stop measuring anything at all. Holding a floor under the
 * components they do NOT buy is what keeps it a real gap: one service reaches
 * about half their posture, two about four fifths, three all of it.
 *
 * The profiles are authored to sum to 1.0 and asserted to in the test suite.
 */
const SERVICE_WEIGHT_PROFILES = {
  '':                   { vulnerabilities: 0.40, awareness: 0.35, incidentResponse: 0.25 },
  'mdr':                { vulnerabilities: 0.25, awareness: 0.25, incidentResponse: 0.50 },
  'vuln':               { vulnerabilities: 0.50, awareness: 0.25, incidentResponse: 0.25 },
  'awareness':          { vulnerabilities: 0.25, awareness: 0.50, incidentResponse: 0.25 },
  'mdr+vuln':           { vulnerabilities: 0.35, awareness: 0.20, incidentResponse: 0.45 },
  'awareness+mdr':      { vulnerabilities: 0.20, awareness: 0.40, incidentResponse: 0.40 },
  'awareness+vuln':     { vulnerabilities: 0.40, awareness: 0.40, incidentResponse: 0.20 },
  'awareness+mdr+vuln': { vulnerabilities: 0.40, awareness: 0.35, incidentResponse: 0.25 },
};

/**
 * The three services that carry weight. Everything else in the catalogue —
 * EDR, NDR, Identity, email security, pentest, firewall, vISO — is either
 * delivered inside one of these or scored nowhere, so it cannot move a weight.
 *
 * Kept deliberately in step with SERVICE_COVERS in lib/services.js, which is
 * the one place that decides which service covers which component.
 */
const WEIGHTED_SERVICES = ['awareness', 'mdr', 'vuln'];

/**
 * The profile key for a service list: the weighted services they effectively
 * have, sorted, joined.
 *
 * effectiveServices() runs FIRST so MDR's implied EDR, NDR and Identity are
 * resolved before keying — a client on MDR is covered for incident response
 * without having ticked three more boxes. Unknown or unweighted keys are
 * dropped rather than rejected, so the catalogue can grow without this table
 * needing a row for every combination of things that do not weigh anything.
 *
 * WEIGHTED_SERVICES is already alphabetical, so filtering it preserves the sort
 * and the key is canonical however the caller ordered their array.
 */
function serviceWeightKey(services) {
  const eff = servicesLib.effectiveServices(services) || [];
  return WEIGHTED_SERVICES.filter(s => eff.indexOf(s) >= 0).join('+');
}

/**
 * resolveWeights — the three component weights for this client.
 * Always sums to exactly 1.
 *
 * @param {Array|null} services  the client's service mix, or null when nobody
 *                               has recorded it
 * @param {Object} [opts]        { awarenessMeasured } — reported back but no
 *                               longer able to move a weight. Kept so the
 *                               removal is documented here rather than
 *                               discovered by somebody wondering where it went.
 *
 * NOT RECORDED IS NOT NONE. A client with no service list on file and a client
 * recorded as buying nothing both get the balanced 40/35/25 profile — there is
 * no sensible third answer — but they report different `basis` values, because
 * everything else in this engine keeps the two apart and a reader is entitled
 * to know which one they are looking at.
 *
 * WHAT IS DELIBERATELY GONE:
 *
 *   exposure / users / serverPatchCoverage
 *       Read from the declared estate. The estate no longer touches any score.
 *
 *   incidentPull
 *       Telemetry rather than typing, but it still moved the weights with
 *       ticket volume — a busy month quietly re-weighted the client. The point
 *       of this change is weights that move when the CONTRACT moves.
 *
 *   awarenessRelief
 *       Moved, not deleted. An unevidenced client-run programme used to halve
 *       the awareness WEIGHT so the client was not scored as though they had no
 *       programme at all. That fairness still matters — awareness carries up to
 *       40 points — but a dropdown must not move a weight. It is now handled
 *       where it belongs, as a MEASUREMENT state: awareness is marked unmeasured
 *       with reason 'client-run programme, unverified', which lowers the stated
 *       ceiling (maxAchievable) instead. Same protection, stable weights.
 */
function resolveWeights(services, opts) {
  const o = opts || {};
  const recorded = Array.isArray(services);
  const key = recorded ? serviceWeightKey(services) : '';
  const profile = SERVICE_WEIGHT_PROFILES[key] || SERVICE_WEIGHT_PROFILES[''];

  /*
   * Round two and let the third absorb the remainder, so the three always sum
   * to exactly 1. The profiles above are authored to sum to 1 already; this is
   * kept because the invariant must hold by CONSTRUCTION rather than by the
   * table having been typed correctly. Rounding all three independently once
   * left totals like 1.0001, which quietly put the composite over 100.
   */
  const v = round4(profile.vulnerabilities);
  const a = round4(profile.awareness);

  return {
    vulnerabilities:  v,
    awareness:        a,
    incidentResponse: round4(1 - v - a),

    /*
     * How these weights were arrived at, so a client whose weighting differs
     * from another's can be told why in one line.
     *
     *   'services'      keyed off a recorded mix
     *   'none'          recorded as buying nothing
     *   'not-recorded'  nobody has said yet
     */
    basis: !recorded ? 'not-recorded' : (key === '' ? 'none' : 'services'),
    // The mix that produced them, already expanded through MDR's implications.
    weightedServices: recorded ? key.split('+').filter(Boolean) : null,
    profileKey: recorded ? key : null,
    // Reported so the change is visible rather than silent: the weights no
    // longer vary with whether awareness was measured.
    awarenessMeasured: o.awarenessMeasured === undefined ? null : !!o.awarenessMeasured,
  };
}

function round4(n) { return Math.round(n * 10000) / 10000; }

const SEVERITY_KEYS = ['critical', 'high', 'medium', 'low'];

/* ── Vulnerability density model ───────────────────────────────────────────
   Severity weights for one finding. Ratios kept from the old penalty model so
   the relative seriousness of a critical against a low is unchanged; only the
   denominator and the curve are new. */
const SEVERITY_WEIGHT = { critical: 10, high: 5, medium: 2, low: 0.5 };

/**
 * Density-to-score curve: 100 / (1 + density/K).
 *
 * Hyperbolic rather than linear, deliberately. A linear penalty hits zero and
 * stays there, at which point the metric stops carrying information — the old
 * model could not tell a bad estate from a catastrophic one. This decays
 * steeply where it matters and never quite reaches zero, so there is always a
 * measurable difference between bad and worse.
 *
 *   density 0 -> 100    density 1 -> 75    density 3 -> 50
 *   density 6 ->  33    density 12 -> 20   density 30 -> 9
 */
const DENSITY_K = 3;

/**
 * Open criticals cap the score no matter how large the estate.
 *
 * This is the floor under the density model. Without it, ten criticals spread
 * across two thousand assets score a density of 0.05 and a near-perfect 99 —
 * arithmetically defensible and operationally absurd. A board should never read
 * "excellent" while a critical sits open.
 */
const CRITICAL_CAPS = [
  { atLeast: 10, cap: 30 },
  { atLeast: 5,  cap: 40 },
  { atLeast: 3,  cap: 50 },
  { atLeast: 1,  cap: 65 },
];

/** Highs matter too, just less sharply. */
const HIGH_CAPS = [
  { atLeast: 25, cap: 55 },
  { atLeast: 10, cap: 70 },
];

/**
 * A vulnerability score cannot exceed the share of the estate that was actually
 * looked at.
 *
 * This is the same rule the whole engine runs on — an unmeasured control is an
 * unmanaged one — applied per asset instead of per component. Scanning 80% of
 * an estate caps the component at 80: the remaining fifth is not clean, it is
 * unexamined, and unexamined assets are the ones nothing is watching. They are
 * typically the same assets missing from managed patching and from the MDR
 * feed, so no other control is covering for the gap either.
 *
 * Deliberately a CAP rather than a multiplier. Findings already lower the
 * density score; multiplying by coverage would charge for the same gap twice.
 *
 * Unknown coverage applies no cap at all. A scan uploaded before scan scope was
 * recorded, or an Arctic Wolf register that cannot report it, must not be
 * treated as zero coverage — that would punish clients for a column that did
 * not exist when they uploaded.
 */
function coverageCap(coverage) {
  if (coverage === null || coverage === undefined) return 100;
  const c = Number(coverage);
  if (!Number.isFinite(c) || c < 0) return 100;
  return Math.max(0, Math.min(100, c * 100));
}

/* ── Measurement predicates ────────────────────────────────────────────────
   Kept separate from the scorers so "did we look?" and "what did we find?"
   are never conflated, and so callers can label a zero correctly. */

/**
 * A vulnerability posture is measured only when a scan exists AND its summary
 * actually carries severity counts. A `vuln_scans` row whose summary is the
 * column default `{}` means the upload parsed to nothing — that is a failed
 * measurement, not a clean bill of health.
 */
function isVulnMeasured(vulnData) {
  const summary = vulnData && vulnData.summary;
  if (!summary || typeof summary !== 'object') return false;
  return SEVERITY_KEYS.some(k => Number.isFinite(Number(summary[k])));
}

function isAwarenessMeasured(awarenessData) {
  const upload = awarenessData && awarenessData.upload;
  if (!upload) return false;
  return (parseInt(upload.total_users, 10) || 0) > 0;
}

function isMdrMeasured(mdrData) {
  return !!(mdrData && mdrData.upload);
}

/* ── Component scorers ─────────────────────────────────────────────────────
   Each returns a plain number so existing callers keep working. */

/** Severity counts off a scan summary, coerced to numbers. */
function severityCounts(vulnData) {
  const s = (vulnData && vulnData.summary) || {};
  const out = {};
  SEVERITY_KEYS.forEach((k) => { out[k] = Number(s[k]) || 0; });
  out.total = SEVERITY_KEYS.reduce((n, k) => n + out[k], 0);
  return out;
}

function applyCaps(score, caps, n) {
  let out = score;
  caps.forEach((c) => { if (n >= c.atLeast) out = Math.min(out, c.cap); });
  return out;
}

/**
 * Infrastructure path: finding density across the assets in scope.
 * @returns {Object} score plus the workings, so a client can be shown WHY.
 */
function scoreInfrastructure(vulnData, estate) {
  if (!isVulnMeasured(vulnData)) {
    return {
      score: 0, measured: false, basis: 'infrastructure',
      reason: 'no-scan',
    };
  }

  const c = severityCounts(vulnData);
  const assets = estateLib.scanDenominator(estate);
  const coverage = estateLib.scanCoverage(estate);
  const covCap = coverageCap(coverage);

  // A scan that ran and found nothing is a real, earned 100 — but only across
  // what it looked at. A clean scan of a fifth of the estate is not a clean
  // estate, and before the cap existed it scored the same as scanning all of it.
  if (c.total === 0) {
    return {
      score: Math.round(Math.min(100, covCap)),
      measured: true, basis: 'infrastructure',
      counts: c, assets, density: 0, coverage,
      coverageCapped: covCap < 100,
    };
  }

  const weighted = SEVERITY_KEYS.reduce((n, k) => n + c[k] * SEVERITY_WEIGHT[k], 0);
  const density = weighted / assets;

  let score = 100 / (1 + density / DENSITY_K);
  const uncapped = score;

  score = applyCaps(score, CRITICAL_CAPS, c.critical);
  score = applyCaps(score, HIGH_CAPS, c.high);
  const beforeCoverage = score;
  score = Math.min(score, covCap);

  return {
    score: Math.round(Math.max(0, Math.min(100, score))),
    measured: true,
    basis: 'infrastructure',
    counts: c,
    assets,
    density: Math.round(density * 100) / 100,
    capped: Math.round(score) < Math.round(uncapped),
    // Which cap bit matters for the advice: a coverage ceiling is a visibility
    // problem, and telling that client to "remediate criticals" is advice for a
    // different problem from the one holding their score down.
    coverageCapped: Math.round(score) < Math.round(beforeCoverage),
    coverage,
  };
}

/**
 * Endpoint path: patch currency and agent health from the EDR feed.
 *
 * This is the answer to "a client with only endpoints who does not run vuln
 * scans". They are not unmeasured — the EDR feed already knows how many of
 * their machines are patched, reporting and clean. That is their vulnerability
 * posture, and it is scored on its own terms.
 */
function scoreEndpoints(edrData) {
  const e = (edrData && edrData.agents) || null;
  const total = e ? (Number(e.total) || 0) : 0;

  if (!e || total <= 0) {
    return {
      score: 0, measured: false, basis: 'endpoint',
      reason: 'no-edr',
    };
  }

  const upToDate = Math.max(0, Math.min(total, Number(e.upToDate) || 0));
  const stale    = Math.max(0, Math.min(total, Number(e.stale) || 0));
  const threats  = Math.max(0, Number(e.activeThreats) || 0);

  const currency = (upToDate / total) * 100;

  // An agent that has not checked in is not "patched", it is unknown — the same
  // blind spot an unscanned server is, so it costs something on its own.
  const stalePenalty  = (stale / total) * 30;
  const threatPenalty = Math.min(25, threats * 5);

  const score = Math.round(Math.max(0, Math.min(100, currency - stalePenalty - threatPenalty)));

  return {
    score,
    measured: true,
    basis: 'endpoint',
    endpoints: total,
    upToDate,
    stale,
    activeThreats: threats,
    currencyPct: Math.round(currency),
  };
}

/**
 * Vulnerability posture (0-100), scored by whichever yardstick fits the estate.
 *
 * @param {Object} vulnData  latest scan summary
 * @param {Object} estate    resolved estate from lib/estate.js
 * @param {Object} edrData   { agents: { total, upToDate, stale, activeThreats } }
 * @returns {Object} detail — use calculateVulnScore() for the bare number.
 */
function assessVulnerabilities(vulnData, estate, edrData) {
  const hasScan = isVulnMeasured(vulnData);
  const hasEdr  = !!(edrData && edrData.agents && (Number(edrData.agents.total) || 0) > 0);
  const basis = estateLib.vulnBasis(estate, { hasScan, hasEdr });

  if (basis === 'infrastructure') return scoreInfrastructure(vulnData, estate);
  if (basis === 'endpoint')       return scoreEndpoints(edrData);

  return {
    score: 0, measured: false, basis: 'unknown', reason: 'no-estate',
  };
}

/**
 * Vulnerability score (0-100).
 *
 * Signature preserved for existing callers: with no estate supplied it behaves
 * as the infrastructure path, which is what every current caller means.
 */
function calculateVulnScore(vulnData, estate, edrData) {
  if (estate === undefined && edrData === undefined) {
    return scoreInfrastructure(vulnData, null).score;
  }
  return assessVulnerabilities(vulnData, estate, edrData).score;
}

/** Awareness score (0-100): share of assigned training completed. */
function calculateAwarenessScore(awarenessData) {
  if (!isAwarenessMeasured(awarenessData)) return 0;

  const { total_users, total_incomplete } = awarenessData.upload;
  const users = parseInt(total_users, 10) || 0;
  const completed = Math.max(0, users - (parseInt(total_incomplete, 10) || 0));

  return Math.round(Math.min(100, Math.max(0, (completed / users) * 100)));
}

/** MDR / Incident Response score (0-100): resolution rate, less a speed penalty. */
function calculateMdrScore(mdrData) {
  if (!isMdrMeasured(mdrData)) return 0;      // no MDR feed = unmonitored

  const { total_tickets = 0, resolved_count = 0, avg_resolution_hours = 0 } = mdrData.upload;
  const total = parseInt(total_tickets, 10) || 0;

  // An upload exists and reported no tickets: monitored, nothing to respond to.
  if (total === 0) return 100;

  const resolutionRate = ((parseInt(resolved_count, 10) || 0) / total) * 100;
  const speedPenalty = Math.min(20, Math.max(0, (Number(avg_resolution_hours) - 24) / 24) * 20);

  return Math.round(Math.max(0, Math.min(100, resolutionRate - speedPenalty)));
}

/**
 * Composite Secure Score (0-100).
 *
 * Returns the per-component scores plus a `measured` map and an `unmeasured`
 * list, so the UI and the board report can say "0 — no data uploaded" instead
 * of leaving a client to read a nought as a failed assessment.
 */
function calculateSecureScore(vulnData, awarenessData, mdrData, opts) {
  const o = opts || {};
  const vuln = assessVulnerabilities(vulnData, o.estate, o.edr);

  const vulnScore      = vuln.score;
  const awarenessScore = calculateAwarenessScore(awarenessData);
  const mdrScore       = calculateMdrScore(mdrData);

  const measured = {
    // Measured now means "assessed by the yardstick that applies", not "a
    // Nessus file exists" — an endpoint-only client with a live EDR feed is
    // measured, and must not be told to upload a scan they do not need.
    vulnerabilities:  vuln.measured,
    awareness:        isAwarenessMeasured(awarenessData),
    incidentResponse: isMdrMeasured(mdrData),
  };

  const LABELS = {
    vulnerabilities:  vuln.basis === 'endpoint'
      ? 'Endpoint patch currency'
      : 'Vulnerability management',
    awareness:        'Security awareness',
    incidentResponse: 'Incident response',
  };

  const svcList = Array.isArray(o.services) ? o.services : null;

  /*
   * WORDING ONLY. The awareness programme is a fact about the client, and two
   * screens phrase the awareness gap differently depending on it. It moves no
   * arithmetic whatsoever — it used to halve the awareness weight, and that
   * relief is gone. Read from the estate because that is where it is recorded,
   * not because the estate scores anything.
   */
  const awarenessProgram = (o.estate && o.estate.awarenessProgram) || null;

  /*
   * Weights follow the SERVICE MIX — see resolveWeights(). Everything
   * downstream must use THESE, or the score and the breakdown shown beside it
   * will not agree.
   *
   * They no longer read the estate, the headcount or the incident rate, so an
   * analyst correcting a typo on the Client Profile can no longer move a
   * client's board-reported score.
   */
  const weights = resolveWeights(svcList, { awarenessMeasured: measured.awareness });
  // Passed through for copy, never for arithmetic — see above.
  weights.awarenessProgram = awarenessProgram;

  const unmeasured = Object.keys(measured)
    .filter(k => !measured[k])
    .map(k => {
      // A component the client never bought is unmeasured for a completely
      // different reason from one they pay for and we have no data on. Telling
      // them to "upload a vulnerability scan" for a service they do not buy is
      // advice they cannot act on, attached to a gap that is not theirs.
      const outOfScope = svcList
        ? !servicesLib.coversComponent(svcList, k, vuln.basis) : false;

      return {
        key: k,
        label: LABELS[k],
        weight: weights[k],
        // How much of the 100 is unreachable while this stays unmeasured.
        pointsForfeited: Math.round(weights[k] * 100),
        outOfScope,
        // An internal programme we cannot see is a different kind of gap from no
        // programme at all, and the difference has to reach the report — the
        // halved forfeit would otherwise look like an arithmetic error.
        /*
         * Triggered by the PROGRAMME plus the absence of figures, not by a
         * weight relief factor — the relief no longer exists. An unevidenced
         * client-run programme used to halve the awareness weight; a dropdown
         * must not move a weight, so the fact is now carried here, where it
         * lowers the stated ceiling (maxAchievable) instead of the weighting.
         * The client is still not described as having no programme at all.
         */
        reason: outOfScope
          ? 'service not subscribed'
          : (k === 'awareness' && awarenessProgram === 'internal')
            ? 'client-run programme, unverified' : undefined,
      };
    });

  const composite = (vulnScore      * weights.vulnerabilities) +
                    (awarenessScore * weights.awareness) +
                    (mdrScore       * weights.incidentResponse);

  /* ── Coverage, and the two scores it produces ────────────────────────────
   *
   * THE PROBLEM. "Unmeasured scores zero" is the right rule for a control the
   * client pays us to run and we have no data for. It is the wrong rule for a
   * control they never bought. A client who buys only awareness training was
   * scored 0 for vulnerability management and 0 for incident response, so a
   * genuinely good awareness result of 88 arrived on their board as a
   * composite around 30 — a number that reads as failure and is really a
   * statement about our order book.
   *
   * THE SPLIT. Two questions, two numbers, and neither substitutes for the
   * other:
   *
   *   Service Secure Score  how well are the services they buy performing?
   *                         Scored over the in-scope components only, with
   *                         the weights renormalised across them.
   *
   *   Coverage              how much of their security posture those services
   *                         reach at all. This is the SUM OF THE WEIGHTS of
   *                         the covered components — so it is already sized to
   *                         this client's exposure. A client with heavy
   *                         public-facing estate who buys no vulnerability
   *                         management has worse coverage than one with no
   *                         infrastructure at all, because the vulnerability
   *                         weight is larger for the first. That falls out of
   *                         resolveWeights() rather than being asserted.
   *
   *   Overall Secure Score  the whole posture, from every piece of evidence
   *                         available. This is the existing composite,
   *                         unchanged.
   *
   * THE THREE ARE NOT RELATED BY A TIDY FORMULA, and an earlier version of
   * this comment claimed they were: overall = serviceScore × coverage. That
   * holds only when everything uncovered is also unmeasured, which is not the
   * common case. A client who runs their own awareness programme and uploads
   * the results is MEASURED on awareness while not being COVERED by it — the
   * engine already credits exactly that through awarenessRelief. Their overall
   * posture legitimately includes a control we do not sell them, so the
   * product understates it. Coverage is a statement about our service
   * footprint; overall is a statement about their security. Do not derive
   * either from the other.
   *
   * WHAT STAYS ZERO. A component the client DOES buy but we have no data for
   * is still 0 and still in scope — they are paying for it. Only what they
   * never bought leaves the scoped number.
   *
   * NOT RECORDED IS NOT NONE. With no service list on file, coverage and the
   * service score are null and every consumer falls back to the composite,
   * exactly as before this existed. Treating an unrecorded client as buying
   * nothing would drop every existing client's coverage to zero overnight.
   */
  const services = Array.isArray(o.services) ? o.services : null;
  const scopeKeys = ['vulnerabilities', 'awareness', 'incidentResponse'];

  const scoreOf = {
    vulnerabilities:  vulnScore,
    awareness:        awarenessScore,
    incidentResponse: mdrScore,
  };

  // Everything below is computed ONLY when a service mix is on file. An earlier
  // version evaluated coverage unconditionally with an "unrecorded means
  // everything" fallback, which read as load-bearing and was dead — nothing
  // consumed it, because every consumer was already guarded. Dead code that
  // looks like policy is worse than no code: it survives review as though it
  // were doing something.
  let coverage = null;
  let coverageNominal = null;
  let discountedPoints = 0;
  let discounts = [];
  let serviceScore = null;
  let coveredKeys = [];
  let uncovered = [];
  let blindSpotPoints = 0;

  /*
   * SERVICES THE CLIENT DOES NOT CONSUME — the whole catalogue, not just the
   * three that carry a score.
   *
   * `uncovered` above answers "which scored components are outside our
   * services". This answers a different question: what else do we do that they
   * are not buying. Penetration testing, firewall review, email security and
   * vISO cover none of the three components by design, so they can never
   * appear in `uncovered` — and a report that only ever recommends the three
   * scored services silently pretends the rest of the catalogue does not
   * exist.
   *
   * NULL, NOT AN EMPTY LIST, WHEN NOTHING IS RECORDED. An unconfigured client
   * has not been asked what they buy, and inferring "they consume nothing"
   * would put every service we sell into their board report as a
   * recommendation — the single most damaging way this could be wrong. Not
   * recorded is not none, here as everywhere else.
   *
   * Built from effectiveServices(), so an MDR client is never recommended the
   * Managed EDR, NDR and Identity that MDR already includes.
   */
  let unpurchased = null;
  if (services) {
    const eff = servicesLib.effectiveServices(services) || [];
    unpurchased = servicesLib.SERVICES
      .filter(s => eff.indexOf(s.key) < 0)
      .map(s => ({ key: s.key, label: s.label, hint: s.hint }));
  }

  if (services) {
    const covered = {};
    scopeKeys.forEach((k) => {
      covered[k] = !!servicesLib.coversComponent(services, k, vuln.basis);
    });

    const coveredWeight = scopeKeys.reduce(
      (sum, k) => sum + (covered[k] ? weights[k] : 0), 0);
    const coveredPoints = scopeKeys.reduce(
      (sum, k) => sum + (covered[k] ? scoreOf[k] * weights[k] : 0), 0);

    /*
     * ── SERVICE REACH ──────────────────────────────────────────────────────
     *
     * A CREDIT is how much of a covered component's weight the service
     * actually reaches. It is 1 for everything by default: buying the service
     * is normally the whole claim.
     *
     * MDR is the exception, because Arctic Wolf publishes a per-org Coverage
     * Score saying how much of the estate the service is genuinely onboarded
     * against. A client can buy MDR and have half their log sources
     * unconnected, and a coverage figure that reads 100% for them is a claim
     * the vendor's own number contradicts.
     *
     * WHAT THIS DOES NOT TOUCH, and why each one matters:
     *
     *   weights        never mutated. Every downstream reader — components[],
     *                  the uncovered table, maxAchievable — sees exactly what
     *                  it saw before, and the sum-to-1 invariant that makes
     *                  coverage a clean 0-100 still holds.
     *   serviceScore   stays on the UNDISCOUNTED weights. See below.
     *   maxAchievable  built from `unmeasured`. A half-onboarded MDR service is
     *                  still MEASURED — tickets exist and were scored — so
     *                  nothing enters `unmeasured` and the ceiling cannot move.
     *   composite      unchanged, and therefore `overall` too. Linking an
     *                  Arctic Wolf org moves coverage and nothing else.
     *   uncovered      a discounted MDR client must NEVER appear there. They
     *                  buy MDR; a row saying "covered by Managed Detection &
     *                  Response" would tell them to buy what they already pay
     *                  for, and blindSpotPoints would absorb points that are
     *                  not a blind spot. Discounts get their own array.
     *
     * WHY serviceScore IS NOT DISCOUNTED. The two figures answer different
     * questions, and that split is the documented spine of this block.
     * serviceScore is "how well are the services you buy performing" — and MDR
     * performance is already measured from ticket data by calculateMdrScore.
     * Coverage is "how much of your weighted posture do those services reach at
     * all". A half-onboarded service reaching less posture is literally what
     * that sentence means. Feeding reach into serviceScore would charge the
     * client twice for one fact and would leave serviceScore unable to
     * reconcile with the component scores printed beside it.
     */
    const credit = {};
    scopeKeys.forEach((k) => { credit[k] = 1; });

    const mdrCov = o.mdrCoverage || null;
    /*
     * Validated hard, because a bad credit silently rewrites a client's
     * coverage. Anything outside [0,1], non-finite, or a string is ignored and
     * coverage falls back to nominal — the safe direction.
     */
    const applyMdrDiscount = !!(
      mdrCov && mdrCov.available === true &&
      covered.incidentResponse &&                       // never discount a service they do not buy
      typeof mdrCov.credit === 'number' && Number.isFinite(mdrCov.credit) &&
      mdrCov.credit >= 0 && mdrCov.credit <= 1
    );
    if (applyMdrDiscount) credit.incidentResponse = mdrCov.credit;

    const creditedWeight = scopeKeys.reduce(
      (sum, k) => sum + (covered[k] ? weights[k] * credit[k] : 0), 0);

    coverageNominal = Math.round(coveredWeight * 100);
    coverage        = Math.round(creditedWeight * 100);

    /*
     * Derived from the two ROUNDED integers, never summed independently from
     * unrounded terms. The page prints "92% = 100% less 8 points" and those
     * three numbers have to add up on screen; a per-component sum of
     * round(w*100) - round(w*credit*100) is off by one in ordinary cases.
     */
    discountedPoints = coverageNominal - coverage;

    discounts = applyMdrDiscount ? [{
      key:    'incidentResponse',
      label:  'Incident response',
      // The undiscounted weight, so this row reconciles with the weights object.
      weight: weights.incidentResponse,
      credit: mdrCov.credit,
      pointsFull:       coverageNominal,
      pointsDiscounted: discountedPoints,
      source:  mdrCov.source,
      metric:  mdrCov.metric,
      orgName: mdrCov.matchedOrg,
      weekKey: mdrCov.weekKey,
      weekCommencing: mdrCov.weekCommencing,
      ageDays: mdrCov.ageDays,
      stale:   mdrCov.stale,
    }] : [];

    coveredKeys = scopeKeys.filter(k => covered[k]);

    // Guarded: a client who buys nothing that maps to a scored component has no
    // in-scope weight, and 0/0 is not a score. Null says "there is nothing to
    // score", which is a different statement from a nought.
    serviceScore = coveredWeight > 0
      ? Math.round(Math.min(100, Math.max(0, coveredPoints / coveredWeight)))
      : null;

    /*
     * Coverage rows are named for the SERVICE, never the yardstick.
     *
     * LABELS[] calls the vulnerability component "Endpoint patch currency"
     * when the engine scores an endpoint-only estate that way. That is the
     * right name for a measurement note and the wrong one for a coverage gap:
     * the gap is "you do not buy Vulnerability Management", and naming it
     * after an internal yardstick put a phrase in a client's board report for
     * a deliverable no contract mentions.
     */
    const COVERAGE_LABELS = {
      vulnerabilities:  'Vulnerability management',
      awareness:        'Security awareness',
      incidentResponse: 'Incident response',
    };

    uncovered = scopeKeys.filter(k => !covered[k]).map(k => ({
      key: k,
      label: COVERAGE_LABELS[k],
      weight: weights[k],
      // How much of the overall 100 sits outside our services.
      pointsForfeited: Math.round(weights[k] * 100),
      /*
       * Whether we have ANY measurement for it. A control that is measured but
       * uncovered is a commercial gap; one nobody is looking at is a security
       * one, and reporting them alike is how a real blind spot gets lost in a
       * sales argument.
       *
       * Deliberately 'measured', not 'client-supplied'. The evidence is not
       * always the client's: an MDR client's endpoint patch data comes from
       * OUR EDR feed, and calling that "client-run" would have been simply
       * untrue on the page.
       */
      evidence: measured[k] ? 'measured' : 'none',
      // What would close it, named so the report does not have to guess.
      closedBy: servicesLib.servicesCovering(k)
        .map(s => servicesLib.serviceLabel(s)),
    }));

    // Points sitting in controls that are neither covered by us nor evidenced
    // by anyone — the actual blind spot, and the only figure here that
    // describes a security risk rather than a commercial one.
    blindSpotPoints = uncovered
      .filter(u => u.evidence === 'none')
      .reduce((sum, u) => sum + u.pointsForfeited, 0);
  }

  return {
    composite: Math.round(Math.min(100, Math.max(0, composite))),
    // Same number as `composite`, under the name the report uses for it. Kept
    // as an alias rather than a second calculation so the two cannot diverge.
    overall: Math.round(Math.min(100, Math.max(0, composite))),
    serviceScore,
    coverage,
    // What coverage was BEFORE any vendor reach discount. Kept so the page can
    // show the arithmetic rather than a number that moved for invisible
    // reasons, and so anything that needs the pre-discount figure has it.
    coverageNominal,
    scope: {
      recorded: !!services,
      // What was sold, and what that entitles them to. MDR includes endpoint,
      // network and identity detection, so an MDR client is covered for those
      // without having ticked them. The browser gates read the effective set
      // rather than re-deriving it — the implication rule lives in
      // lib/services.js and nowhere else.
      services: services,
      effectiveServices: servicesLib.effectiveServices(services),
      covered:   coveredKeys,
      uncovered,
      // Everything in the catalogue they are not on. null when no mix is
      // recorded — see the construction above.
      unpurchased,
      blindSpotPoints,
      // Coverage before the reach discount, the points it removed, and what
      // removed them. Separate from `uncovered` on purpose: an uncovered
      // control is one the client does not buy, a discounted one is a service
      // they DO buy that does not reach their whole estate. Reporting them
      // alike would tell a client to purchase what they already pay for.
      coverageNominal,
      discountedPoints,
      discounts,
      // The vendor figure verbatim, including the reason when there is none —
      // so the page can say "not linked" rather than showing a silent gap.
      mdrCoverage: o.mdrCoverage || null,
    },
    vulnScore,
    awarenessScore,
    mdrScore,
    // How the vulnerability figure was arrived at: which yardstick, against how
    // many assets, and whether a cap bit. Without this a client sees a number
    // with no way to argue with it.
    vulnDetail: vuln,
    // The weighting actually applied, and why. A client whose vulnerability
    // weight has dropped to 15% is entitled to see that it did, and on what
    // grounds — otherwise their composite moves for no visible reason.
    weights,
    measured,
    unmeasured,
    // The best score reachable without uploading anything further — makes the
    // ceiling explicit rather than leaving it to be inferred.
    maxAchievable: Math.round(
      100 - unmeasured.reduce((sum, u) => sum + u.weight * 100, 0)
    ),
  };
}

/**
 * Which scored component each recommendation area belongs to.
 *
 * A single table rather than a `component:` on all twenty-odd push sites: one
 * place to read, one place to change. `null` means the advice stands whatever
 * the client buys.
 *
 * A NEW AREA MUST BE ADDED HERE. The test suite asserts that every `area:`
 * literal in this file appears in this map, because an unmapped area falls
 * through to "always show" — which is the safe default for a score but the
 * wrong one for a client who would then be advised to fix a service they do
 * not buy.
 */
const AREA_COMPONENT = {
  'Vulnerabilities':        'vulnerabilities',
  'Scan Coverage':          'vulnerabilities',
  'Asset Inventory':        'vulnerabilities',
  'Internal Infrastructure':'vulnerabilities',
  'Patch Management':       'vulnerabilities',
  'Endpoint Hygiene':       'vulnerabilities',
  'Training Coverage':      'awareness',
  'Security Awareness':     'awareness',
  'Incident Response':      'incidentResponse',
  'Overall':                null,
};

/**
 * Improvement recommendations.
 *
 * `measured` matters here as much as the score: without it a 0 caused by a
 * missing upload produced "Reduce critical and high-severity findings", which
 * is advice for a problem the client cannot act on and hides the real one.
 *
 * `opts.services` matters for the same reason one step further out. Advice to
 * "reduce critical and high-severity findings" for a client who does not buy
 * vulnerability management is worse than useless: it appears under Executive
 * Decisions in their board pack as a failing of theirs, when nobody was ever
 * engaged to scan. Out-of-scope areas are dropped entirely rather than
 * softened — the coverage section is where the gap is stated, once, honestly.
 */
function generateRecommendations(vulnScore, awarenessScore, mdrScore, measured, vulnDetail, estate, opts) {
  const m = measured || { vulnerabilities: true, awareness: true, incidentResponse: true };
  const v = vulnDetail || { basis: 'infrastructure' };
  const o = opts || {};
  const recommendations = [];

  // The advice has to match the yardstick. Telling a client with no servers to
  // upload an infrastructure scan is advice for someone else's problem, and it
  // buries the thing they can actually act on.
  if (!m.vulnerabilities && v.basis === 'endpoint') {
    recommendations.push({
      priority: 'high',
      area: 'Endpoint Hygiene',
      suggestion: 'This client has endpoints and no in-scope infrastructure, so patch ' +
                  'currency is the measure — but no EDR agent data is available. ' +
                  'Connect the EDR feed to recover up to 40 points.',
      impact: 'Major',
    });
  } else if (!m.vulnerabilities && v.basis === 'unknown') {
    recommendations.push({
      priority: 'high',
      area: 'Vulnerabilities',
      suggestion: 'No estate has been recorded for this client, so the vulnerability ' +
                  'measure cannot be chosen and scores zero. Record the server, ' +
                  'public-facing asset and endpoint counts on the Admin tab, then ' +
                  'upload a scan or connect EDR.',
      impact: 'Major',
    });
  } else if (!m.vulnerabilities) {
    recommendations.push({
      priority: 'high',
      area: 'Vulnerabilities',
      suggestion: 'No vulnerability scan has been uploaded, so this scores zero. ' +
                  'An unscanned estate is treated as an unknown estate, not a clean one. ' +
                  'Upload a scan to recover up to 40 points.',
      impact: 'Major',
    });
  } else if (v.basis === 'endpoint') {
    if (vulnScore < 70) {
      recommendations.push({
        priority: 'high',
        area: 'Endpoint Hygiene',
        suggestion: 'Endpoint patch currency is ' + (v.currencyPct != null ? v.currencyPct + '%' : 'low') +
                    (v.stale ? ', with ' + v.stale + ' agent(s) not reporting' : '') +
                    (v.activeThreats ? ' and ' + v.activeThreats + ' endpoint(s) carrying active threats' : '') +
                    '. Bring outstanding patches up to date and restore stale agents.',
        impact: 'Major',
      });
    } else if (vulnScore < 85) {
      recommendations.push({
        priority: 'medium',
        area: 'Endpoint Hygiene',
        suggestion: 'Endpoint patch currency is close to target. Clear the remaining ' +
                    'out-of-date agents to move above 85.',
        impact: 'Moderate',
      });
    }
  } else if (v.coverageCapped) {
    // Named FIRST, ahead of the density and critical advice: when coverage is
    // the ceiling, remediating findings cannot lift this component at all. The
    // problem is not what the scan found, it is what it never looked at.
    const pct = v.coverage != null ? Math.round(v.coverage * 100) : null;
    recommendations.push({
      priority: 'high',
      area: 'Scan Coverage',
      suggestion: (pct != null
        ? 'The last scan reached ' + pct + '% of the recorded external-facing ' +
          'assets, so this component is held at ' + pct + '/100 no matter what ' +
          'the findings say. '
        : 'The last scan reached only part of the external-facing estate. ') +
        'Unscanned assets are not clean assets — they are unexamined, and they ' +
        'are usually the same assets missing from managed patching and the MDR ' +
        'feed, so nothing else is covering the gap. Widen the scan scope before ' +
        'remediation work will move this score.',
      impact: 'Major',
    });
  } else if (v.capped && v.counts && v.counts.critical) {
    // A capped score is not a density problem and must not be described as one.
    recommendations.push({
      priority: 'high',
      area: 'Vulnerabilities',
      suggestion: v.counts.critical + ' critical finding(s) hold this score at a ceiling ' +
                  'regardless of estate size. Remediate the criticals first — no other ' +
                  'work will lift this component while they remain open.',
      impact: 'Major',
    });
  } else if (vulnScore < 70) {
    const workings = (v.density != null && v.assets)
      ? ' Finding density is ' + v.density + ' weighted findings per asset across ' +
        v.assets + ' asset' + (v.assets === 1 ? '' : 's') + ' in scope.'
      : '';
    recommendations.push({
      priority: 'high',
      area: 'Vulnerabilities',
      suggestion: 'Reduce critical and high-severity findings.' + workings +
                  ' Prioritise remediation of critical vulnerabilities.',
      impact: 'Major',
    });
  } else if (vulnScore < 85) {
    recommendations.push({
      priority: 'medium',
      area: 'Vulnerabilities',
      suggestion: 'Address remaining high-severity findings to improve score above 85.',
      impact: 'Moderate',
    });
  }

  // The scan reached more external hosts than the client's inventory records.
  // Not a scoring problem — coverage clamps at 100% — but an asset-management
  // one, and the kind that turns into an incident: something is internet-facing
  // that nobody has written down.
  if (estate && estate.undeclaredExternal > 0) {
    recommendations.push({
      priority: 'medium',
      area: 'Asset Inventory',
      suggestion: 'The last scan reached ' + estate.scannedHosts + ' external hosts, but ' +
                  'only ' + estate.publicAssets + ' public-facing assets are recorded — ' +
                  estate.undeclaredExternal + ' internet-facing host' +
                  (estate.undeclaredExternal === 1 ? ' is' : 's are') + ' not in the ' +
                  'inventory. Reconcile the asset register against the scan: an ' +
                  'unrecorded internet-facing host is one nobody owns.',
      impact: 'Moderate',
    });
  }

  // The external scan cannot reach servers or cloud tenancies at all, so an
  // internal estate outside managed patching has NO vulnerability measurement
  // behind it from any source. That gap must be named: it does not belong in
  // scan coverage (the scan was never in scope for it), and left unstated it
  // would look as though a clean external scan covered the whole estate.
  if (estate && estate.unscannableAssets > 0) {
    const cover = estateLib.patchCoverage(estate, 'serversPatched');
    const uncovered = cover == null
      ? estate.unscannableAssets
      : Math.round(estate.unscannableAssets - (estate.servers || 0) * cover);
    if (uncovered > 0) {
      recommendations.push({
        priority: cover == null ? 'high' : 'medium',
        area: 'Internal Infrastructure',
        suggestion: uncovered + ' internal asset' + (uncovered === 1 ? '' : 's') +
                    ' (servers and cloud tenancies) sit outside both the external ' +
                    'vulnerability scan, which cannot reach them, and managed ' +
                    'patching. Nothing is currently measuring their patch state, so ' +
                    'this score describes the estate\'s external face only. Managed ' +
                    'patching is the available control today; internal scanning will ' +
                    'cover them directly once it is in place.',
        impact: cover == null ? 'Major' : 'Moderate',
      });
    }
  }

  // Managed patching lowers how heavily vulnerabilities are weighted, so an
  // uncovered server estate is worth naming as an actionable gap rather than
  // leaving the client to discover the lever by accident.
  if (estate && estate.servers && estate.serversPatched != null) {
    const cover = estateLib.patchCoverage(estate, 'serversPatched');
    if (cover != null && cover < 0.9) {
      recommendations.push({
        priority: 'medium',
        area: 'Patch Management',
        suggestion: Math.round(cover * 100) + '% of ' + estate.servers + ' servers are ' +
                    'under managed patching. Bringing the remainder under management ' +
                    'reduces exposure and lowers how heavily vulnerability management ' +
                    'weighs on this score.',
        impact: 'Moderate',
      });
    }
  }

  // Partial coverage that is NOT yet the binding constraint — worth flagging
  // before it becomes one. Suppressed when the cap already fired above, or the
  // client gets the same advice twice at two different priorities.
  if (m.vulnerabilities && v.basis === 'infrastructure' && !v.coverageCapped &&
      v.coverage != null && v.coverage < 1) {
    recommendations.push({
      priority: 'medium',
      area: 'Scan Coverage',
      suggestion: 'The last scan reached ' + Math.round(v.coverage * 100) + '% of the ' +
                  'recorded external-facing assets, so this component cannot exceed ' +
                  Math.round(v.coverage * 100) + '/100. The score describes the assets ' +
                  'that were scanned; widen the scan scope for a complete picture.',
      impact: 'Moderate',
    });
  }

  // A completion percentage over a fraction of the workforce describes that
  // fraction, not the organisation. This is the awareness equivalent of scan
  // coverage and belongs beside it.
  if (m.awareness && estate) {
    const cover = estateLib.trainingCoverage(estate);
    if (cover != null && cover < 0.9) {
      recommendations.push({
        priority: cover < 0.5 ? 'high' : 'medium',
        area: 'Training Coverage',
        suggestion: 'Training reaches ' + Math.round(cover * 100) + '% of the ' +
                    estate.users + ' recorded staff (' + estate.trainedUsers +
                    ' enrolled). The awareness score describes the people who ' +
                    'were enrolled, not the whole organisation — enrol the ' +
                    'remainder for a representative figure.',
        impact: cover < 0.5 ? 'Major' : 'Moderate',
      });
    }
  }

  if (!m.awareness && estate && estate.awarenessProgram === 'internal') {
    // The client runs their own programme. Asking them to "upload training
    // records" as though they had none is both wrong and useless; what they
    // need is the figures their own programme already produces.
    recommendations.push({
      priority: 'medium',
      area: 'Security Awareness',
      suggestion: 'This client runs their own awareness programme, so awareness is ' +
                  'weighted at half pending evidence rather than scored as absent. ' +
                  'It still scores zero because no completion figures have been ' +
                  'recorded — enter the staff trained and completed on the Awareness ' +
                  'tab to have it scored on their own numbers at full weight.',
      impact: 'Moderate',
    });
  } else if (!m.awareness && estate && estate.awarenessProgram === 'none') {
    recommendations.push({
      priority: 'high',
      area: 'Security Awareness',
      suggestion: 'No security awareness programme is in place. Phishing remains the ' +
                  'most common initial access route, and this component scores zero ' +
                  'until a programme exists and its completion is recorded.',
      impact: 'Major',
    });
  } else if (!m.awareness) {
    recommendations.push({
      priority: 'high',
      area: 'Security Awareness',
      suggestion: 'No awareness training data has been uploaded, so this scores zero. ' +
                  'Upload training records — or, if the client runs their own ' +
                  'programme, record that on the Admin tab so they are not scored ' +
                  'as though they had none.',
      impact: 'Major',
    });
  } else if (awarenessScore < 70) {
    recommendations.push({
      priority: 'high',
      area: 'Security Awareness',
      suggestion: 'Increase training completion rates. Only ' + awarenessScore + '% of users have completed training.',
      impact: 'Major',
    });
  } else if (awarenessScore < 90) {
    recommendations.push({
      priority: 'medium',
      area: 'Security Awareness',
      suggestion: 'Continue promoting security awareness. Aim for 90%+ completion rate.',
      impact: 'Moderate',
    });
  }

  if (!m.incidentResponse) {
    recommendations.push({
      priority: 'high',
      area: 'Incident Response',
      suggestion: 'No MDR or incident data is available, so this scores zero. ' +
                  'Connect the MDR feed to recover up to 25 points.',
      impact: 'Major',
    });
  } else if (mdrScore < 70) {
    recommendations.push({
      priority: 'high',
      area: 'Incident Response',
      suggestion: 'Improve ticket resolution rates and speed. Current score reflects slow or incomplete resolutions.',
      impact: 'Major',
    });
  } else if (mdrScore < 85) {
    recommendations.push({
      priority: 'medium',
      area: 'Incident Response',
      suggestion: 'Accelerate incident response times to improve score above 85.',
      impact: 'Moderate',
    });
  }

  // Positive feedback only when everything was actually measured — a client
  // must never be congratulated on a posture nobody has looked at.
  const allMeasured = m.vulnerabilities && m.awareness && m.incidentResponse;
  if (allMeasured && vulnScore >= 85 && awarenessScore >= 85 && mdrScore >= 85) {
    recommendations.push({
      priority: 'info',
      area: 'Overall',
      suggestion: 'Excellent security posture. Maintain current practices and continue monitoring.',
      impact: 'Positive',
    });
  }

  /*
   * Drop advice about services the client does not buy.
   *
   * Applied once at the end rather than guarded at each push: the twenty-odd
   * branches above already carry enough conditions, and a filter that reads
   * "remove what is out of scope" is checkable at a glance in a way that
   * twenty scattered guards are not.
   *
   * An area missing from AREA_COMPONENT keeps its recommendation — failing
   * open here loses no advice, and the test suite is what stops an area going
   * unmapped in the first place.
   */
  const services = Array.isArray(o.services) ? o.services : null;
  if (!services) return recommendations;

  return recommendations.filter((r) => {
    const component = AREA_COMPONENT[r.area];
    if (component === undefined) return true;   // unmapped area — keep it
    if (component === null) return true;        // applies whatever they buy
    return servicesLib.coversComponent(services, component, v.basis) !== false;
  });
}

module.exports = {
  AREA_COMPONENT,
  WEIGHTS,
  incidentRateFrom,
  RATE_MIN_DATED,
  resolveWeights,
  SEVERITY_WEIGHT,
  DENSITY_K,
  CRITICAL_CAPS,
  HIGH_CAPS,
  calculateSecureScore,
  assessVulnerabilities,
  scoreInfrastructure,
  scoreEndpoints,
  severityCounts,
  calculateVulnScore,
  calculateAwarenessScore,
  calculateMdrScore,
  generateRecommendations,
  isVulnMeasured,
  isAwarenessMeasured,
  isMdrMeasured,
};
