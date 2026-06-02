'use strict';

/**
 * Secure Score calculation engine.
 * Combines vulnerability, awareness, and MDR metrics into a 0-100 composite score.
 * 
 * Weighting:
 * - Vulnerabilities: 40%
 * - Security Awareness: 35%
 * - MDR/Incident Response: 25%
 */

/**
 * Calculate vulnerability score (0-100).
 * Lower vulnerability counts = higher score.
 * Penalizes critical and high findings more heavily.
 */
function calculateVulnScore(vulnData) {
  if (!vulnData || !vulnData.summary) {
    return 100; // No vulns = perfect score
  }

  const { critical = 0, high = 0, medium = 0, low = 0 } = vulnData.summary;
  const total = critical + high + medium + low;

  if (total === 0) return 100;

  // Penalty calculation: critical=20pts, high=10pts, medium=5pts, low=1pt each
  // Capped at 100 points (minimum score 0)
  const penalty = (critical * 20) + (high * 10) + (medium * 5) + (low * 1);
  const score = Math.max(0, 100 - penalty);

  return Math.round(score);
}

/**
 * Calculate security awareness score (0-100).
 * Based on percentage of users who have completed training.
 */
function calculateAwarenessScore(awarenessData) {
  if (!awarenessData || !awarenessData.upload) {
    return 0; // No data = no score
  }

  const { total_users, total_incomplete } = awarenessData.upload;

  if (total_users === 0) return 0;

  const completed = total_users - total_incomplete;
  const percentage = (completed / total_users) * 100;

  return Math.round(percentage);
}

/**
 * Calculate MDR/Incident Response score (0-100).
 * Based on: ticket resolution rate + resolution speed.
 */
function calculateMdrScore(mdrData) {
  if (!mdrData || !mdrData.upload) {
    return 100; // No data = no penalty
  }

  const { total_tickets = 0, resolved_count = 0, avg_resolution_hours = 0 } = mdrData.upload;

  if (total_tickets === 0) return 100;

  // Resolution rate score (0-100): % of resolved/closed tickets
  const resolutionRate = (resolved_count / total_tickets) * 100;

  // Speed penalty: deduct points if avg resolution > 24 hours
  // Max 20 point penalty for very slow resolution
  const speedPenalty = Math.min(20, Math.max(0, (avg_resolution_hours - 24) / 24) * 20);

  const score = resolutionRate - speedPenalty;

  return Math.round(Math.max(0, Math.min(100, score)));
}

/**
 * Calculate composite Secure Score (0-100).
 * Weights: vulns=40%, awareness=35%, mdr=25%
 */
function calculateSecureScore(vulnData, awarenessData, mdrData) {
  const vulnScore = calculateVulnScore(vulnData);
  const awarenessScore = calculateAwarenessScore(awarenessData);
  const mdrScore = calculateMdrScore(mdrData);

  const composite = (vulnScore * 0.40) + (awarenessScore * 0.35) + (mdrScore * 0.25);

  return {
    composite: Math.round(composite),
    vulnScore,
    awarenessScore,
    mdrScore,
  };
}

/**
 * Generate improvement recommendations based on score components.
 */
function generateRecommendations(vulnScore, awarenessScore, mdrScore) {
  const recommendations = [];

  if (vulnScore < 70) {
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

  if (awarenessScore < 70) {
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

  if (mdrScore < 70) {
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

  // If all scores are good, provide positive feedback
  if (vulnScore >= 85 && awarenessScore >= 85 && mdrScore >= 85) {
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
  calculateSecureScore,
  calculateVulnScore,
  calculateAwarenessScore,
  calculateMdrScore,
  generateRecommendations,
};
