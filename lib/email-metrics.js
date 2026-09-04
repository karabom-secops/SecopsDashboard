'use strict';

/**
 * lib/email-metrics.js
 * Reporting metrics for the Managed Email Security (Acronis) tab.
 *
 * Derived from the email_alerts table the integration sync populates, scoped to
 * one tenant and a rolling window (default 30 days) so the numbers line up with
 * a monthly report — the same contract as lib/edr-metrics.js.
 *
 * ══ THE DENOMINATOR PROBLEM, STATED UP FRONT ══
 *
 * "Catch rate" normally means threats stopped ÷ messages processed. The Acronis
 * Alert Manager API returns ALERTS — things that went wrong — and not a count of
 * mail scanned. There is no honest way to derive total message volume from it.
 *
 * So this module does NOT report a catch rate against mail volume, and does not
 * invent a denominator to make one. It reports:
 *
 *   threats        — how many email threats were detected
 *   containment    — of the threats whose OUTCOME the alert stated, how many
 *                    were blocked, quarantined or remediated rather than
 *                    delivered. The denominator is alerts with a KNOWN
 *                    disposition, and the count that had none is reported
 *                    beside it, because a rate computed over 40% of the data is
 *                    a different claim from one computed over all of it.
 *
 * If message volume is needed for a board slide it has to come from somewhere
 * that actually counts messages — the Acronis console's own reporting, or the
 * mail platform. Presenting alert counts as though they were volume would be a
 * fabrication that nobody downstream could detect.
 */

function toInt(v) {
  return parseInt(v, 10) || 0;
}

function pct1(numerator, denominator) {
  if (!denominator) return null;   // NOT zero: no denominator means no rate
  return parseFloat(((numerator / denominator) * 100).toFixed(1));
}

/** Map { label, count } rows into plain tallies. */
function tallies(rows) {
  return rows.map(r => ({ label: r.label, count: toInt(r.count) }));
}

/*
 * Dispositions that mean the message did not reach the user in a usable state.
 * 'remediated' counts as contained — it was delivered and then pulled back,
 * which is a worse outcome than blocking but still a stopped attack. It is
 * reported separately as well, because the difference matters operationally.
 */
const CONTAINED = ['blocked', 'quarantined', 'remediated'];

async function computeEmailSummary(pool, tenantId, days = 30) {
  const window = Math.max(1, Math.min(365, parseInt(days, 10) || 30));

  const [
    headline, byClass, bySeverity, byDisposition, daily,
    topRecipients, topSenderDomains, unrecognisedTypes, lastSync,
  ] = await Promise.all([
    /*
     * Headline counters.
     *
     * `classified` and `known_disposition` are counted explicitly so the tab can
     * say what share of the window each rate was computed over, rather than
     * presenting a percentage of an unstated subset.
     */
    pool.query(
      `SELECT
         COUNT(*)::int                                                       AS total,
         COUNT(*) FILTER (WHERE threat_class IS NOT NULL)::int               AS classified,
         COUNT(*) FILTER (WHERE disposition IS NOT NULL)::int                AS known_disposition,
         COUNT(*) FILTER (WHERE disposition = ANY($3::text[]))::int          AS contained,
         COUNT(*) FILTER (WHERE disposition = 'delivered')::int              AS delivered,
         COUNT(*) FILTER (WHERE disposition = 'remediated')::int             AS remediated,
         COUNT(DISTINCT recipient) FILTER (WHERE recipient IS NOT NULL)::int AS targeted_users,
         COUNT(DISTINCT sender_domain) FILTER (WHERE sender_domain IS NOT NULL)::int AS sender_domains
       FROM email_alerts
       WHERE tenant_id = $1 AND created_at >= NOW() - ($2::int * INTERVAL '1 day')`,
      [tenantId, window, CONTAINED]
    ),

    // COALESCE to a sentinel the UI renders as "Unclassified", not to a real
    // class — an unrecognised threat kind must never be filed under 'other'.
    pool.query(
      `SELECT COALESCE(threat_class, 'unclassified') AS label, COUNT(*)::int AS count
       FROM email_alerts
       WHERE tenant_id = $1 AND created_at >= NOW() - ($2::int * INTERVAL '1 day')
       GROUP BY 1 ORDER BY count DESC`,
      [tenantId, window]
    ),

    pool.query(
      `SELECT COALESCE(severity, 'unknown') AS label, COUNT(*)::int AS count
       FROM email_alerts
       WHERE tenant_id = $1 AND created_at >= NOW() - ($2::int * INTERVAL '1 day')
       GROUP BY 1 ORDER BY count DESC`,
      [tenantId, window]
    ),

    pool.query(
      `SELECT COALESCE(disposition, 'unknown') AS label, COUNT(*)::int AS count
       FROM email_alerts
       WHERE tenant_id = $1 AND created_at >= NOW() - ($2::int * INTERVAL '1 day')
       GROUP BY 1 ORDER BY count DESC`,
      [tenantId, window]
    ),

    // Zero-filled so a quiet day is a zero on the line and not a gap in it.
    pool.query(
      `SELECT to_char(d.day::date, 'YYYY-MM-DD') AS label,
              COALESCE(a.count, 0)::int     AS count,
              COALESCE(a.contained, 0)::int AS contained
       FROM generate_series(
              (NOW() - ($2::int * INTERVAL '1 day'))::date, NOW()::date, '1 day'
            ) AS d(day)
       LEFT JOIN (
         SELECT created_at::date AS day,
                COUNT(*)         AS count,
                COUNT(*) FILTER (WHERE disposition = ANY($3::text[])) AS contained
         FROM email_alerts
         WHERE tenant_id = $1 AND created_at >= NOW() - ($2::int * INTERVAL '1 day')
         GROUP BY 1
       ) a ON a.day = d.day::date
       ORDER BY d.day`,
      [tenantId, window, CONTAINED]
    ),

    /*
     * Who is being attacked. This is the operationally useful view and the
     * reason recipient addresses are stored at all — a name here is a name to
     * put on the next awareness campaign.
     */
    pool.query(
      `SELECT recipient AS label, COUNT(*)::int AS count,
              COUNT(*) FILTER (WHERE disposition = 'delivered')::int AS delivered
       FROM email_alerts
       WHERE tenant_id = $1 AND created_at >= NOW() - ($2::int * INTERVAL '1 day')
         AND recipient IS NOT NULL
       GROUP BY 1 ORDER BY count DESC, label LIMIT 10`,
      [tenantId, window]
    ),

    pool.query(
      `SELECT sender_domain AS label, COUNT(*)::int AS count
       FROM email_alerts
       WHERE tenant_id = $1 AND created_at >= NOW() - ($2::int * INTERVAL '1 day')
         AND sender_domain IS NOT NULL
       GROUP BY 1 ORDER BY count DESC, label LIMIT 10`,
      [tenantId, window]
    ),

    /*
     * Alert types the classifier did NOT read as email security.
     *
     * Mostly this is correct and uninteresting — Acronis raises backup and
     * patching alerts through the same API. It is surfaced anyway because the
     * failure mode it guards against is invisible: if Acronis ships a new
     * Advanced Email Security type tomorrow, the only symptom is a chart that
     * quietly stops rising. Not windowed — a type seen once last quarter is
     * still a gap in the classifier today.
     */
    pool.query(
      `SELECT alert_type AS label, category, seen_count::int AS count, last_seen_at
       FROM email_alert_types_seen
       WHERE tenant_id = $1 AND is_email = FALSE
       ORDER BY seen_count DESC, alert_type LIMIT 25`,
      [tenantId]
    ),

    pool.query(
      `SELECT last_synced_at, last_sync_status, last_sync_message
       FROM integrations WHERE tenant_id = $1 AND provider = 'acronis'`,
      [tenantId]
    ),
  ]);

  const h = headline.rows[0] || {};

  const total            = toInt(h.total);
  const knownDisposition = toInt(h.known_disposition);
  const contained        = toInt(h.contained);
  const classified       = toInt(h.classified);

  return {
    windowDays: window,

    threats: {
      total,
      classified,
      // How many email alerts we could not put a kind to. Reported as a count,
      // not folded into a bucket, so it is a visible gap rather than a category.
      unclassified: total - classified,
      targetedUsers: toInt(h.targeted_users),
      senderDomains: toInt(h.sender_domains),
    },

    /*
     * Containment, with its own denominator attached.
     *
     * `rate` is null — not 0 — when no alert in the window stated an outcome.
     * A rate of 0% says every threat got through; null says we do not know, and
     * those must not render the same way.
     */
    containment: {
      contained,
      delivered:        toInt(h.delivered),
      remediated:       toInt(h.remediated),
      knownDisposition,
      unknownDisposition: total - knownDisposition,
      rate:     pct1(contained, knownDisposition),
      // What share of the window the rate above was actually computed over.
      coverage: pct1(knownDisposition, total),
    },

    byClass:       tallies(byClass.rows),
    bySeverity:    tallies(bySeverity.rows),
    byDisposition: tallies(byDisposition.rows),

    daily: daily.rows.map(r => ({
      date: r.label, count: toInt(r.count), contained: toInt(r.contained),
    })),

    topRecipients: topRecipients.rows.map(r => ({
      label: r.label, count: toInt(r.count), delivered: toInt(r.delivered),
    })),
    topSenderDomains: tallies(topSenderDomains.rows),

    unrecognisedTypes: unrecognisedTypes.rows.map(r => ({
      label: r.label, category: r.category || null,
      count: toInt(r.count), lastSeenAt: r.last_seen_at || null,
    })),

    sync: lastSync.rows[0] || null,
  };
}

module.exports = { computeEmailSummary, CONTAINED };
