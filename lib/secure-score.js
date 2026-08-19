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
 * Weighting: vulnerabilities 40%, awareness 35%, MDR/IR 25%.
 */

const WEIGHTS = { vulnerabilities: 0.40, awareness: 0.35, incidentResponse: 0.25 };

const SEVERITY_KEYS = ['critical', 'high', 'medium', 'low'];

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

/**
 * Vulnerability score (0-100). Lower counts score higher; critical and high
 * findings are penalised most heavily.
 */
function calculateVulnScore(vulnData) {
  if (!isVulnMeasured(vulnData)) return 0;   // no scan = no visibility = no score

  const s = vulnData.summary;
  const critical = Number(s.critical) || 0;
  const high     = Number(s.high)     || 0;
  const medium   = Number(s.medium)   || 0;
  const low      = Number(s.low)      || 0;

  // A scan that ran and found nothing is a real, earned 100.
  if (critical + high + medium + low === 0) return 100;

  const penalty = (critical * 20) + (high * 10) + (medium * 5) + (low * 1);
  return Math.round(Math.max(0, 100 - penalty));
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
function calculateSecureScore(vulnData, awarenessData, mdrData) {
  const vulnScore      = calculateVulnScore(vulnData);
  const awarenessScore = calculateAwarenessScore(awarenessData);
  const mdrScore       = calculateMdrScore(mdrData);

  const measured = {
    vulnerabilities:  isVulnMeasured(vulnData),
    awareness:        isAwarenessMeasured(awarenessData),
    incidentResponse: isMdrMeasured(mdrData),
  };

  const LABELS = {
    vulnerabilities:  'Vulnerability management',
    awareness:        'Security awareness',
    incidentResponse: 'Incident response',
  };

  const unmeasured = Object.keys(measured)
    .filter(k => !measured[k])
    .map(k => ({
      key: k,
      label: LABELS[k],
      weight: WEIGHTS[k],
      // How much of the 100 is unreachable while this stays unmeasured.
      pointsForfeited: Math.round(WEIGHTS[k] * 100),
    }));

  const composite = (vulnScore      * WEIGHTS.vulnerabilities) +
                    (awarenessScore * WEIGHTS.awareness) +
                    (mdrScore       * WEIGHTS.incidentResponse);

  return {
    composite: Math.round(Math.min(100, Math.max(0, composite))),
    vulnScore,
    awarenessScore,
    mdrScore,
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
function generateRecommendations(vulnScore, awarenessScore, mdrScore, measured) {
  const m = measured || { vulnerabilities: true, awareness: true, incidentResponse: true };
  const recommendations = [];

  if (!m.vulnerabilities) {
    recommendations.push({
      priority: 'high',
      area: 'Vulnerabilities',
      suggestion: 'No vulnerability scan has been uploaded, so this scores zero. ' +
                  'An unscanned estate is treated as an unknown estate, not a clean one. ' +
                  'Upload a scan to recover up to 40 points.',
      impact: 'Major',
    });
  } else if (vulnScore < 70) {
    recommendations.push({
      priority: 'high',
      area: 'Vulnerabilities',
      suggestion: 'Reduce critical and high-severity findings. Prioritize remediation of critical vulnerabilities.',
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
  calculateSecureScore,
  calculateVulnScore,
  calculateAwarenessScore,
  calculateMdrScore,
  generateRecommendations,
  isVulnMeasured,
  isAwarenessMeasured,
  isMdrMeasured,
};
