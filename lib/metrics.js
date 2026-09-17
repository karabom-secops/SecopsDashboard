'use strict';

/**
 * computeAllMetrics(weeksData)
 * Takes the full weeks.json object and returns a metricsData object keyed by weekKey.
 * Each entry: { weekKey, weekCommencing, orgs, agents, deltas }
 */
function computeAllMetrics(weeksData) {
  const metricsData = {};

  const sortedKeys = Object.keys(weeksData).sort();

  sortedKeys.forEach((weekKey, idx) => {
    const week = weeksData[weekKey];
    const prevKey = idx > 0 ? sortedKeys[idx - 1] : null;
    const prevMetrics = prevKey ? metricsData[prevKey] : null;

    const orgs = computeOrgMetrics(week.orgs || []);
    const agents = computeAgentMetrics(week.sysmon, week.containment);
    const deltas = prevMetrics
      ? computeDeltas({ orgs, agents }, prevMetrics)
      : null;

    metricsData[weekKey] = {
      weekKey,
      weekCommencing: week.weekCommencing || weekKey,
      orgs,
      agents,
      deltas,
    };
  });

  return metricsData;
}

// ── Per-week computations ─────────────────────────────────────────────────────

function computeOrgMetrics(orgs) {
  const total = orgs.length;
  const totalAlerts = orgs.reduce((s, o) => s + (o.alerts || 0), 0);
  const totalEscalated = orgs.reduce((s, o) => s + (o.escalated || 0), 0);
  const escalationRate = totalAlerts > 0 ? round2((totalEscalated / totalAlerts) * 100) : 0;

  const coverageScores = orgs.map(o => o.coverageScore).filter(v => v !== null && v !== undefined);
  const avgCoverageScore = coverageScores.length > 0
    ? round2(coverageScores.reduce((s, v) => s + v, 0) / coverageScores.length)
    : null;

  const orgsBelowCoverage = orgs.filter(
    o => o.coverageScore !== null && o.coverageScore !== undefined && o.coverageScore < 75
  ).length;

  const orgsNoIRPlan = orgs.filter(o => !o.irPlan).length;

  return { total, totalAlerts, totalEscalated, escalationRate, avgCoverageScore, orgsBelowCoverage, orgsNoIRPlan };
}

function computeAgentMetrics(sysmon, containment) {
  const sysmonDeploymentRate = (sysmon && sysmon.total > 0)
    ? round2((sysmon.deployed / sysmon.total) * 100)
    : null;
  const containmentDriverRate = (containment && containment.total > 0)
    ? round2((containment.deployed / containment.total) * 100)
    : null;

  return {
    sysmon: sysmon || null,
    containment: containment || null,
    sysmonDeploymentRate,
    containmentDriverRate,
  };
}

/**
 * Compute week-over-week deltas.
 * Positive delta means the raw value increased. UI interprets sign direction per metric.
 */
function computeDeltas(current, prevMetrics) {
  const delta = (curr, prev) => {
    if (curr === null || curr === undefined || prev === null || prev === undefined) return null;
    return round2(curr - prev);
  };

  return {
    totalAlerts: delta(current.orgs.totalAlerts, prevMetrics.orgs.totalAlerts),
    totalEscalated: delta(current.orgs.totalEscalated, prevMetrics.orgs.totalEscalated),
    escalationRate: delta(current.orgs.escalationRate, prevMetrics.orgs.escalationRate),
    avgCoverageScore: delta(current.orgs.avgCoverageScore, prevMetrics.orgs.avgCoverageScore),
    sysmonDeploymentRate: delta(current.agents.sysmonDeploymentRate, prevMetrics.agents.sysmonDeploymentRate),
    containmentDriverRate: delta(current.agents.containmentDriverRate, prevMetrics.agents.containmentDriverRate),
    orgsBelowCoverage: delta(current.orgs.orgsBelowCoverage, prevMetrics.orgs.orgsBelowCoverage),
    orgsNoIRPlan: delta(current.orgs.orgsNoIRPlan, prevMetrics.orgs.orgsNoIRPlan),
  };
}

// ── Summary helpers ───────────────────────────────────────────────────────────

/**
 * Returns the last N weeks of metrics as a sorted array.
 */
function getSummary(metricsData, n) {
  const sortedKeys = Object.keys(metricsData).sort();
  const recent = sortedKeys.slice(-n);
  return recent.map(k => metricsData[k]);
}

/**
 * Builds per-org alert/escalated/coverage history across all weeks.
 * Returns { orgName: [{ weekKey, alerts, escalated, coverageScore }] }
 */
function getOrgHistory(weeksData) {
  const history = {};
  const sortedKeys = Object.keys(weeksData).sort();

  sortedKeys.forEach(weekKey => {
    const orgs = weeksData[weekKey].orgs || [];
    orgs.forEach(org => {
      if (!history[org.orgName]) history[org.orgName] = [];
      history[org.orgName].push({
        weekKey,
        alerts: org.alerts || 0,
        escalated: org.escalated || 0,
        coverageScore: org.coverageScore !== undefined ? org.coverageScore : null,
      });
    });
  });

  return history;
}

// ── Utility ───────────────────────────────────────────────────────────────────

function round2(n) {
  return Math.round(n * 100) / 100;
}

module.exports = { computeAllMetrics, getSummary, getOrgHistory };
