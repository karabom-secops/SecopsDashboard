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

/**
 * resolveWeights — the three component weights for this client.
 * Always sums to 1. Falls back to the flat defaults when exposure is unknown.
 */
function resolveWeights(estate) {
  const e = estate || null;

  // No estate on record: keep the historical flat weighting.
  if (!e || !e.anyDeclared) {
    return Object.assign({}, WEIGHTS, { exposure: null, basis: 'default' });
  }

  const exposure = estateLib.exposurePoints(e);
  const { min, max, k } = EXPOSURE_WEIGHT;
  const vuln = min + (max - min) * (exposure / (exposure + k));

  // How the remainder splits. Headcount decides it where it is known: ten people
  // and ten thousand people are not the same phishing target, and awareness is
  // scored as a percentage, so scale cannot show up anywhere but the weight.
  // Unknown headcount keeps the ratio the two already stand in (35:25).
  const rest = 1 - vuln;
  const share = estateLib.humanShare(e);
  const awarenessShare = share === null
    ? WEIGHTS.awareness / (WEIGHTS.awareness + WEIGHTS.incidentResponse)
    : share;

  // Round two and let the third absorb the remainder, so the three always sum
  // to exactly 1. Rounding all three independently left totals like 1.0001,
  // which would quietly put the composite over 100 on a perfect score.
  const v = round4(vuln);
  const a = round4(rest * awarenessShare);

  return {
    vulnerabilities:  v,
    awareness:        a,
    incidentResponse: round4(1 - v - a),
    exposure,
    users: e.users,
    serverPatchCoverage: estateLib.patchCoverage(e, 'serversPatched'),
    endpointPatchCoverage: estateLib.patchCoverage(e, 'endpointsPatched'),
    basis: 'exposure',
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

  // A scan that ran and found nothing is a real, earned 100.
  if (c.total === 0) {
    return {
      score: 100, measured: true, basis: 'infrastructure',
      counts: c, assets, density: 0, coverage: estateLib.scanCoverage(estate),
    };
  }

  const weighted = SEVERITY_KEYS.reduce((n, k) => n + c[k] * SEVERITY_WEIGHT[k], 0);
  const density = weighted / assets;

  let score = 100 / (1 + density / DENSITY_K);
  const uncapped = score;

  score = applyCaps(score, CRITICAL_CAPS, c.critical);
  score = applyCaps(score, HIGH_CAPS, c.high);

  return {
    score: Math.round(Math.max(0, Math.min(100, score))),
    measured: true,
    basis: 'infrastructure',
    counts: c,
    assets,
    density: Math.round(density * 100) / 100,
    capped: Math.round(score) < Math.round(uncapped),
    coverage: estateLib.scanCoverage(estate),
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
  const weights = resolveWeights(o.estate);

  const unmeasured = Object.keys(measured)
    .filter(k => !measured[k])
    .map(k => ({
      key: k,
      label: LABELS[k],
      weight: weights[k],
      // How much of the 100 is unreachable while this stays unmeasured.
      pointsForfeited: Math.round(weights[k] * 100),
    }));

  const composite = (vulnScore      * weights.vulnerabilities) +
                    (awarenessScore * weights.awareness) +
                    (mdrScore       * weights.incidentResponse);

  return {
    composite: Math.round(Math.min(100, Math.max(0, composite))),
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
 * Improvement recommendations.
 *
 * `measured` matters here as much as the score: without it a 0 caused by a
 * missing upload produced "Reduce critical and high-severity findings", which
 * is advice for a problem the client cannot act on and hides the real one.
 */
function generateRecommendations(vulnScore, awarenessScore, mdrScore, measured, vulnDetail, estate) {
  const m = measured || { vulnerabilities: true, awareness: true, incidentResponse: true };
  const v = vulnDetail || { basis: 'infrastructure' };
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

  // Scanning a fraction of a declared estate is its own gap: the score reflects
  // what was looked at, not what exists.
  if (m.vulnerabilities && v.basis === 'infrastructure' &&
      v.coverage != null && v.coverage < 0.8) {
    recommendations.push({
      priority: 'medium',
      area: 'Scan Coverage',
      suggestion: 'The last scan reached ' + Math.round(v.coverage * 100) + '% of the ' +
                  'recorded infrastructure. The score describes the assets that were ' +
                  'scanned; widen the scan scope for a complete picture.',
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

  if (!m.awareness) {
    recommendations.push({
      priority: 'high',
      area: 'Security Awareness',
      suggestion: 'No awareness training data has been uploaded, so this scores zero. ' +
                  'Upload training records to recover up to 35 points.',
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

  return recommendations;
}

module.exports = {
  WEIGHTS,
  EXPOSURE_WEIGHT,
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
