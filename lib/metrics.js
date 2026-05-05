'use strict';

/**
 * computeAllMetrics(weeksData)
 * Takes the full weeks.json object and returns a metricsData object keyed by weekKey.
 * Each entry: { weekKey, weekCommencing, priorities, orgs, agents, deltas }
 */
function computeAllMetrics(weeksData) {
  const metricsData = {};

  const sortedKeys = Object.keys(weeksData).sort();

  sortedKeys.forEach((weekKey, idx) => {
    const week = weeksData[weekKey];
    const prevKey = idx > 0 ? sortedKeys[idx - 1] : null;
    const prevMetrics = prevKey ? metricsData[prevKey] : null;

    const priorities = computePriorityMetrics(week.priorities || []);
    const orgs = computeOrgMetrics(week.orgs || []);
    const agents = computeAgentMetrics(week.sysmon, week.containment);
    const deltas = prevMetrics
      ? computeDeltas({ priorities, orgs, agents }, prevMetrics)
      : null;

    metricsData[weekKey] = {
      weekKey,
      weekCommencing: week.weekCommencing || weekKey,
      priorities,
      orgs,
      agents,
      deltas,
    };
  });

  return metricsData;
}

// ── Per-week computations ─────────────────────────────────────────────────────

function computePriorityMetrics(priorities) {
  const total = priorities.length;
  const open = priorities.filter(p => p.status === 'open').length;
  const wip = priorities.filter(p => p.status === 'wip').length;
  const done = priorities.filter(p => p.status === 'done').length;
  const resolutionRate = total > 0 ? round2((done / total) * 100) : 0;
  const p1Count = priorities.filter(p => p.priority === 1).length;
  const p2Count = priorities.filter(p => p.priority === 2).length;
  const criticalOpen = priorities.filter(
    p => (p.priority === 1 || p.priority === 2) && p.status !== 'done'
  ).length;

  return { total, open, wip, done, resolutionRate, p1Count, p2Count, criticalOpen };
}

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
    resolutionRate: delta(current.priorities.resolutionRate, prevMetrics.priorities.resolutionRate),
    criticalOpen: delta(current.priorities.criticalOpen, prevMetrics.priorities.criticalOpen),
    avgCoverageScore: delta(current.orgs.avgCoverageScore, prevMetrics.orgs.avgCoverageScore),
    sysmonDeploymentRate: delta(current.agents.sysmonDeploymentRate, prevMetrics.agents.sysmonDeploymentRate),
    containmentDriverRate: delta(current.agents.containmentDriverRate, prevMetrics.agents.containmentDriverRate),
    orgsBelowCoverage: delta(current.orgs.orgsBelowCoverage, prevMetrics.orgs.orgsBelowCoverage),
    orgsNoIRPlan: delta(current.orgs.orgsNoIRPlan, prevMetrics.orgs.orgsNoIRPlan),
    p1Count: delta(current.priorities.p1Count, prevMetrics.priorities.p1Count),
    p2Count: delta(current.priorities.p2Count, prevMetrics.priorities.p2Count),
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
