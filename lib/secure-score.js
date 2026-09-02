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
 * ── Weighted by exposure ──────────────────────────────────────────────────
 *
 * The weights are not fixed either. 40/35/25 is the fallback for a client
 * whose estate has not been recorded; where it has, the vulnerability weight
 * follows how much surface an attacker can actually reach, and the remainder
 * goes to awareness and incident response. See resolveWeights().
 */

const estateLib = require('./estate');
const servicesLib = require('./services');

const WEIGHTS = { vulnerabilities: 0.40, awareness: 0.35, incidentResponse: 0.25 };

/* ── Weighting by exposure ─────────────────────────────────────────────────
 *
 * How WELL a client manages vulnerabilities is one question; how MUCH that
 * ought to count toward their posture is another, and a fixed 40% answered it
 * the same way for everyone.
 *
 * It should not. A client whose whole external surface is a single website,
 * with endpoints patched by an RMM, does not have two fifths of their security
 * riding on infrastructure scanning — the dominant risks are their people and
 * their ability to respond. A client running a dozen internet-facing
 * applications on fifty servers is the opposite case entirely.
 *
 * So the vulnerability weight rides a saturating curve on exposure points
 * (lib/estate.js), and whatever it gives up is redistributed to awareness and
 * incident response in their existing 35:25 proportion.
 *
 *   exposure   0  (endpoints only)        -> 10%
 *              3  (one website)           -> 18%
 *              9  (website + 2 apps)      -> 27%
 *             13  (website + 5 servers)   -> 31%
 *             39  (10 srv, 5 apps, cloud) -> 41%
 *            260  (large estate)          -> 48%
 *
 * An UNKNOWN estate keeps the flat 40%. Nothing about a client we have not
 * profiled should move, and a low weight must be earned by declaring a small
 * surface, never granted by leaving the form blank.
 */
const EXPOSURE_WEIGHT = { min: 0.10, max: 0.50, k: 12 };

/* ── Weighting by incident load ────────────────────────────────────────────
 *
 * Incident response used to be the RESIDUAL. Vulnerability weight was chosen
 * from exposure, awareness's share of what remained was chosen from headcount,
 * and incident response got the arithmetic leftover — the only component with
 * no driver of its own. The 25% it fell back to was a bare literal from the
 * first version of this file; extracting it into a named constant never made
 * it a decision.
 *
 * Worse, both existing levers pushed the same way. More assets raised the
 * vulnerability weight; more staff raised awareness's share of the remainder.
 * Incident response was squeezed from both sides at once, so the largest and
 * most complex clients weighted their ability to respond LOWEST — 16% at ten
 * thousand staff and a hundred-odd assets. That is backwards: a large estate is
 * exactly where detection and response carry the load, because nobody patches
 * or trains their way out of that much surface.
 *
 * So the remainder is now divided by relative PULL. Headcount pulls toward
 * awareness; incident load pulls toward incident response. Both are legitimate
 * claims on the same pool, and neither is a leftover.
 *
 *   rate    0 /mo  ->  x1.00   (neutral — see below)
 *          10 /mo  ->  x1.30
 *          30 /mo  ->  x1.60
 *         100 /mo  ->  x1.92
 *         500 /mo  ->  x2.13
 *
 * A QUIET MONTH IS NEUTRAL, NEVER PENALISED. The curve starts at 1.0 and only
 * rises, so a client with no incidents keeps exactly the weighting they had.
 * Letting volume cut the weight would repeat the mistake this engine was built
 * to fix — treating an absence of findings as evidence of an absent risk. A
 * client with nothing to respond to this month still needs to be able to
 * respond next month.
 *
 * An unknown rate returns 1.0, so every client whose ticket dates we cannot
 * establish keeps the weighting they had before this existed.
 */
const INCIDENT_PULL = { max: 2.2, k: 30 };

/**
 * How hard incident load pulls weight toward incident response.
 * @param {number|null} rate  incidents per month, or null when unknown
 * @returns {number} a multiplier >= 1
 */
function incidentPull(rate) {
  if (rate === null || rate === undefined) return 1;
  const n = Number(rate);
  if (!Number.isFinite(n) || n <= 0) return 1;
  const { max, k } = INCIDENT_PULL;
  return 1 + (max - 1) * (n / (n + k));
}

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

/**
 * resolveWeights — the three component weights for this client.
 * Always sums to 1. Falls back to the flat defaults when exposure is unknown.
 *
 * @param {Object} estate
 * @param {Object} opts  { awarenessMeasured, incidentRate }
 *   awarenessMeasured — whether awareness is scored from real figures. Only
 *                       matters for a client who has declared an internal
 *                       programme; see awarenessRelief().
 *   incidentRate      — MDR tickets per month, or null when unknown. Pulls
 *                       weight toward incident response; see incidentPull().
 */
function resolveWeights(estate, opts) {
  const e = estate || null;
  const o = opts || {};
  // Absent, this must behave exactly as before: no relief for anyone.
  const measured = o.awarenessMeasured === undefined ? true : !!o.awarenessMeasured;
  const relief = estateLib.awarenessRelief(e, { measured });

  const DEFAULT_SHARE = WEIGHTS.awareness / (WEIGHTS.awareness + WEIGHTS.incidentResponse);

  let vuln, awarenessShare, exposure = null, basis = 'exposure';

  if (!e || !e.anyDeclared) {
    // No estate on record: keep the historical flat vulnerability weight. The
    // awareness relief and the incident pull still apply — both are claims about
    // controls and events, not about assets, so neither needs an asset profile.
    vuln = WEIGHTS.vulnerabilities;
    awarenessShare = DEFAULT_SHARE;
    basis = 'default';
  } else {
    exposure = estateLib.exposurePoints(e);
    const { min, max, k } = EXPOSURE_WEIGHT;
    vuln = min + (max - min) * (exposure / (exposure + k));

    // Headcount decides awareness's claim where it is known: ten people and ten
    // thousand people are not the same phishing target, and awareness is scored
    // as a percentage, so scale cannot show up anywhere but the weight. Unknown
    // headcount keeps the ratio the two already stand in.
    const share = estateLib.humanShare(e);
    awarenessShare = share === null ? DEFAULT_SHARE : share;
  }

  // The remainder, divided by relative pull rather than handed to awareness
  // with incident response taking what fell off the end. With an unknown
  // incident rate the pull is 1.0 and this reduces exactly to the old
  // `aware = rest * awarenessShare`, which is what keeps every existing client
  // where they were until real ticket dates say otherwise.
  const rest  = 1 - vuln;
  const pull  = incidentPull(o.incidentRate);
  const aPull = awarenessShare;
  const iPull = (1 - awarenessShare) * pull;
  const total = aPull + iPull;

  let aware = total > 0 ? rest * (aPull / total) : rest * awarenessShare;
  let ir    = rest - aware;

  // An unevidenced internal programme gives back half the awareness weight to
  // the two components we CAN see, in the proportion they already stand in.
  // The client is not scored on the programme — they simply stop being scored
  // as though they had none.
  if (relief < 1) {
    const freed = aware * (1 - relief);
    aware -= freed;
    const rest = vuln + ir;
    if (rest > 0) { vuln += freed * (vuln / rest); ir += freed * (ir / rest); }
    else { aware += freed; }        // degenerate; never reachable with real weights
  }

  // Round two and let the third absorb the remainder, so the three always sum
  // to exactly 1. Rounding all three independently left totals like 1.0001,
  // which would quietly put the composite over 100 on a perfect score.
  const v = round4(vuln);
  const a = round4(aware);

  const out = {
    vulnerabilities:  v,
    awareness:        a,
    incidentResponse: round4(1 - v - a),
    exposure,
    basis,
    awarenessProgram: e ? e.awarenessProgram : null,
    awarenessRelief:  relief,
    // A weight that moved is a weight a client is entitled to have explained.
    incidentRate: o.incidentRate === undefined ? null : o.incidentRate,
    incidentPull: pull,
  };
  if (basis === 'exposure') {
    out.users = e.users;
    // No endpoint equivalent: endpoint patch state comes from the EDR feed
    // (scoreEndpoints), not from a declared count. The `endpointsPatched`
    // field that used to be read here never reached any scoring path — see
    // the note in lib/estate.js.
    out.serverPatchCoverage = estateLib.patchCoverage(e, 'serversPatched');
  }
  return out;
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

  // Weights follow the client's exposure, not a fixed table — see
  // resolveWeights(). Everything downstream must use THESE, or the score and
  // the breakdown shown beside it will not agree.
  const weights = resolveWeights(o.estate, {
    awarenessMeasured: measured.awareness,
    // Only a measured MDR feed can carry a rate. An unmeasured one leaves it
    // null, so a client with no feed is not quietly given a quiet month.
    incidentRate: measured.incidentResponse ? o.incidentRate : null,
  });

  const svcList = Array.isArray(o.services) ? o.services : null;

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
        reason: outOfScope
          ? 'service not subscribed'
          : (k === 'awareness' && weights.awarenessRelief < 1)
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
  let serviceScore = null;
  let coveredKeys = [];
  let uncovered = [];
  let blindSpotPoints = 0;

  if (services) {
    const covered = {};
    scopeKeys.forEach((k) => {
      covered[k] = !!servicesLib.coversComponent(services, k, vuln.basis);
    });

    const coveredWeight = scopeKeys.reduce(
      (sum, k) => sum + (covered[k] ? weights[k] : 0), 0);
    const coveredPoints = scopeKeys.reduce(
      (sum, k) => sum + (covered[k] ? scoreOf[k] * weights[k] : 0), 0);

    coverage = Math.round(coveredWeight * 100);
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
      blindSpotPoints,
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
  EXPOSURE_WEIGHT,
  INCIDENT_PULL,
  incidentPull,
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
