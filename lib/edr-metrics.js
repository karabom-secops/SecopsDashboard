'use strict';

/**
 * lib/edr-metrics.js
 * Reporting metrics for the Managed EDR (SentinelOne) tab.
 *
 * Everything is derived from the edr_threats / edr_activities / edr_agents
 * tables the integration sync populates, scoped to one tenant and a rolling
 * window (default 30 days) so the numbers line up with a monthly report.
 */

/** Round to 1dp, or null when there was nothing to average. */
function avg1(v) {
  if (v === null || v === undefined) return null;
  const n = parseFloat(v);
  return isNaN(n) ? null : parseFloat(n.toFixed(1));
}

function toInt(v) {
  return parseInt(v, 10) || 0;
}

/** Map a { name, count } row set into a plain array of tallies. */
function tallies(rows, labelKey = 'label') {
  return rows.map(r => ({ label: r[labelKey] || 'Unknown', count: toInt(r.count) }));
}

async function computeEdrSummary(pool, tenantId, days = 30) {
  const window = Math.max(1, Math.min(365, parseInt(days, 10) || 30));

  const [
    headline, byStatus, byConfidence, byClassification, byVerdict,
    daily, topEndpoints, topThreats, fleet, osBreakdown, activityTypes, lastSync,
  ] = await Promise.all([
    // ── Headline counters + mean time to mitigate/resolve ──
    pool.query(
      `SELECT
         COUNT(*)::int                                                            AS total,
         COUNT(*) FILTER (WHERE mitigation_status = 'mitigated')::int             AS mitigated,
         COUNT(*) FILTER (WHERE incident_status = 'resolved')::int                AS resolved,
         COUNT(*) FILTER (WHERE incident_status <> 'resolved'
                             OR incident_status IS NULL)::int                     AS unresolved,
         COUNT(*) FILTER (WHERE confidence_level = 'malicious')::int              AS malicious,
         COUNT(*) FILTER (WHERE confidence_level = 'suspicious')::int             AS suspicious,
         COUNT(*) FILTER (WHERE analyst_verdict = 'false_positive')::int          AS false_positives,
         COUNT(DISTINCT endpoint_id) FILTER (WHERE endpoint_id IS NOT NULL)::int  AS affected_endpoints,
         AVG(EXTRACT(EPOCH FROM (mitigated_at - detected_at)) / 3600.0)
           FILTER (WHERE mitigated_at IS NOT NULL AND detected_at IS NOT NULL
                     AND mitigated_at >= detected_at)                             AS mttm_hours,
         AVG(EXTRACT(EPOCH FROM (resolved_at - detected_at)) / 3600.0)
           FILTER (WHERE resolved_at IS NOT NULL AND detected_at IS NOT NULL
                     AND resolved_at >= detected_at)                              AS mttr_hours
       FROM edr_threats
       WHERE tenant_id = $1 AND detected_at >= NOW() - ($2::int * INTERVAL '1 day')`,
      [tenantId, window]
    ),

    pool.query(
      `SELECT COALESCE(incident_status, 'unknown') AS label, COUNT(*)::int AS count
       FROM edr_threats
       WHERE tenant_id = $1 AND detected_at >= NOW() - ($2::int * INTERVAL '1 day')
       GROUP BY 1 ORDER BY count DESC`,
      [tenantId, window]
    ),

    pool.query(
      `SELECT COALESCE(confidence_level, 'n/a') AS label, COUNT(*)::int AS count
       FROM edr_threats
       WHERE tenant_id = $1 AND detected_at >= NOW() - ($2::int * INTERVAL '1 day')
       GROUP BY 1 ORDER BY count DESC`,
      [tenantId, window]
    ),

    pool.query(
      `SELECT COALESCE(NULLIF(classification, ''), 'Unclassified') AS label, COUNT(*)::int AS count
       FROM edr_threats
       WHERE tenant_id = $1 AND detected_at >= NOW() - ($2::int * INTERVAL '1 day')
       GROUP BY 1 ORDER BY count DESC LIMIT 10`,
      [tenantId, window]
    ),

    pool.query(
      `SELECT COALESCE(analyst_verdict, 'undefined') AS label, COUNT(*)::int AS count
       FROM edr_threats
       WHERE tenant_id = $1 AND detected_at >= NOW() - ($2::int * INTERVAL '1 day')
       GROUP BY 1 ORDER BY count DESC`,
      [tenantId, window]
    ),

    // ── Detections per day, zero-filled so the trend line has no gaps ──
    pool.query(
      `SELECT to_char(d.day::date, 'YYYY-MM-DD') AS label,
              COALESCE(t.count, 0)::int    AS count,
              COALESCE(t.mitigated, 0)::int AS mitigated
       FROM generate_series(
              (NOW() - ($2::int * INTERVAL '1 day'))::date, NOW()::date, '1 day'
            ) AS d(day)
       LEFT JOIN (
         SELECT detected_at::date AS day,
                COUNT(*)          AS count,
                COUNT(*) FILTER (WHERE mitigation_status = 'mitigated') AS mitigated
         FROM edr_threats
         WHERE tenant_id = $1 AND detected_at >= NOW() - ($2::int * INTERVAL '1 day')
         GROUP BY 1
       ) t ON t.day = d.day::date
       ORDER BY d.day`,
      [tenantId, window]
    ),

    pool.query(
      `SELECT COALESCE(endpoint_name, 'Unknown') AS label,
              COUNT(*)::int                      AS count,
              COUNT(*) FILTER (WHERE incident_status <> 'resolved' OR incident_status IS NULL)::int AS unresolved
       FROM edr_threats
       WHERE tenant_id = $1 AND detected_at >= NOW() - ($2::int * INTERVAL '1 day')
       GROUP BY 1 ORDER BY count DESC, label LIMIT 10`,
      [tenantId, window]
    ),

    pool.query(
      `SELECT threat_name AS label, COUNT(*)::int AS count,
              COALESCE(MAX(classification), '') AS classification
       FROM edr_threats
       WHERE tenant_id = $1 AND detected_at >= NOW() - ($2::int * INTERVAL '1 day')
       GROUP BY 1 ORDER BY count DESC, label LIMIT 10`,
      [tenantId, window]
    ),

    // ── Fleet health is a point-in-time snapshot, not windowed ──
    pool.query(
      `SELECT COUNT(*)::int                                         AS total,
              COUNT(*) FILTER (WHERE is_active)::int                AS online,
              COUNT(*) FILTER (WHERE is_infected)::int              AS infected,
              COUNT(*) FILTER (WHERE is_up_to_date)::int            AS up_to_date,
              COUNT(*) FILTER (WHERE NOT is_up_to_date)::int        AS out_of_date,
              COALESCE(SUM(active_threats), 0)::int                 AS active_threats,
              COUNT(*) FILTER (WHERE last_active_at < NOW() - INTERVAL '7 days')::int AS stale
       FROM edr_agents WHERE tenant_id = $1`,
      [tenantId]
    ),

    pool.query(
      `SELECT COALESCE(os_type, 'unknown') AS label, COUNT(*)::int AS count
       FROM edr_agents WHERE tenant_id = $1
       GROUP BY 1 ORDER BY count DESC`,
      [tenantId]
    ),

    pool.query(
      `SELECT COALESCE(NULLIF(activity_type_name, ''), 'Type ' || activity_type::text) AS label,
              COUNT(*)::int AS count
       FROM edr_activities
       WHERE tenant_id = $1 AND created_at >= NOW() - ($2::int * INTERVAL '1 day')
       GROUP BY 1 ORDER BY count DESC LIMIT 10`,
      [tenantId, window]
    ),

    pool.query(
      `SELECT last_synced_at, last_sync_status, last_sync_message
       FROM integrations WHERE tenant_id = $1 AND provider = 'sentinelone'`,
      [tenantId]
    ),
  ]);

  const h = headline.rows[0] || {};
  const f = fleet.rows[0] || {};

  const total     = toInt(h.total);
  const mitigated = toInt(h.mitigated);

  return {
    windowDays: window,
    threats: {
      total,
      mitigated,
      resolved:          toInt(h.resolved),
      unresolved:        toInt(h.unresolved),
      malicious:         toInt(h.malicious),
      suspicious:        toInt(h.suspicious),
      falsePositives:    toInt(h.false_positives),
      affectedEndpoints: toInt(h.affected_endpoints),
      mitigationRate:    total > 0 ? parseFloat(((mitigated / total) * 100).toFixed(1)) : null,
      mttmHours:         avg1(h.mttm_hours),
      mttrHours:         avg1(h.mttr_hours),
    },
    fleet: {
      total:         toInt(f.total),
      online:        toInt(f.online),
      infected:      toInt(f.infected),
      upToDate:      toInt(f.up_to_date),
      outOfDate:     toInt(f.out_of_date),
      activeThreats: toInt(f.active_threats),
      stale:         toInt(f.stale),
      coverage:      toInt(f.total) > 0
        ? parseFloat(((toInt(f.up_to_date) / toInt(f.total)) * 100).toFixed(1))
        : null,
    },
    byStatus:         tallies(byStatus.rows),
    byConfidence:     tallies(byConfidence.rows),
    byClassification: tallies(byClassification.rows),
    byVerdict:        tallies(byVerdict.rows),
    byOsType:         tallies(osBreakdown.rows),
    activityTypes:    tallies(activityTypes.rows),
    daily: daily.rows.map(r => ({
      date: r.label, count: toInt(r.count), mitigated: toInt(r.mitigated),
    })),
    topEndpoints: topEndpoints.rows.map(r => ({
      label: r.label, count: toInt(r.count), unresolved: toInt(r.unresolved),
    })),
    topThreats: topThreats.rows.map(r => ({
      label: r.label, count: toInt(r.count), classification: r.classification || null,
    })),
    sync: lastSync.rows[0] || null,
  };
}

module.exports = { computeEdrSummary };
