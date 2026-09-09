/* mdr-metrics.js — the reporting-period cohort for MDR / incident-response metrics.
   Loaded both in the browser (<script>) and in Node (server.js via require()),
   the same way ir-playbooks-data.js is, and for the same reason: the browser
   builds the KPI table and the server computes the score, and they must be
   describing the same tickets. */
(function (root) {
  'use strict';

  /**
   * ══ THE COHORT RULE ══
   *
   * A month's MDR figures describe the tickets RAISED in that month, followed
   * through to whenever they were resolved. One population, one denominator.
   *
   * WHAT THIS REPLACES, AND WHY IT WAS WRONG
   *
   * Three parts of the product measured "MDR performance this month" over three
   * different populations, and on one real feed they produced 78, 62 and 95 for
   * the same August:
   *
   *   the Secure Score      read mdr_uploads.total_tickets — the whole uploaded
   *                         CSV. A month for most clients, two years for anyone
   *                         who exported their full history. No period at all.
   *   the report KPI table  counted tickets RAISED in the month against tickets
   *                         RESOLVED in the month — two different cohorts, since
   *                         a ticket resolved in August may have been raised in
   *                         June. That is what made the old "resolution rate"
   *                         produce 125%.
   *   the trend chart       counted every ticket raised up to that month END,
   *                         cumulatively, so a good month could not move it.
   *
   * They sat on the same page as each other. The maturity table's Managed
   * Detection and Response score and the incident-resolution KPIs printed
   * directly beneath it were computed over different sets of tickets, with
   * nothing on the slide saying so.
   *
   * ══ THE CUT-OFF, AND THE HONEST THING TO SAY ABOUT IT ══
   *
   * A ticket raised on 30 August and resolved on 2 September IS counted as
   * resolved for August. The alternative — freezing the cohort at month end —
   * judges a ticket raised on the 30th on one day of life and reads as a miss
   * for work that was done.
   *
   * The consequence is that August's figure can improve if the report is re-run
   * in October, so every consumer of these numbers MUST print the as-at date.
   * That is what makes the figure reproducible: not that it never changes, but
   * that it says what it was true of.
   *
   * ══ MONTHS ARE UTC ══
   *
   * monthKeyOf() slices a UTC ISO string, matching monthOf() in
   * report-sections.js and every other period filter in the product. In SAST
   * (UTC+2, no DST) that puts a ticket raised at 00:30 on the 1st into the
   * previous month. Consistency across the report is worth more than those two
   * hours; changing it is a deliberate decision to take everywhere at once, not
   * here alone.
   */

  /** A Date, or null. Accepts a Date, an ISO string, or anything pg hands back. */
  function toDate(v) {
    if (v === null || v === undefined || v === '') return null;
    var d = (v instanceof Date) ? v : new Date(String(v));
    return isNaN(d.getTime()) ? null : d;
  }

  /** 'YYYY-MM' in UTC, or null when there is no usable date. */
  function monthKeyOf(v) {
    var d = toDate(v);
    return d ? d.toISOString().slice(0, 7) : null;
  }

  /*
   * Field aliases. /api/mdr aliases its columns to camelCase for the browser
   * while a direct pg query in server.js returns snake_case, and this module is
   * fed by both. Reading only one shape would have made every server-side
   * cohort silently empty — the worst possible failure here, because an empty
   * cohort scores 100 rather than erroring.
   */
  function createdOf(t) {
    return t && (t.createdAt !== undefined ? t.createdAt : t.created_at);
  }
  function resolvedOf(t) {
    return t && (t.resolvedAt !== undefined ? t.resolvedAt : t.resolved_at);
  }

  /**
   * The last COMPLETE calendar month, as at `now`.
   *
   * The Secure Score tab has no period selector, so it needs a window chosen
   * for it. The current month to date was rejected: on the 1st it would score a
   * handful of tickets or none, which is exactly the volatility the weighting
   * change was made to remove. This matches the month a board report covers, so
   * the tab and the deck describe the same tickets.
   */
  function lastCompleteMonth(now) {
    var d = toDate(now) || new Date();
    return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() - 1, 1))
      .toISOString().slice(0, 7);
  }

  /**
   * Elapsed hours between two timestamps — nights, weekends and public
   * holidays included, because a 24/7 service runs through them.
   *
   * THE ONE IMPLEMENTATION. report-sections.js exported an
   * elapsedHoursBetween() of its own; when the cohort arithmetic moved in here
   * there were briefly two, which is how a business-hours model crept back in
   * once already. That function now delegates to this one.
   *
   * null, not 0 and not a negative, when the pair cannot be measured: a
   * resolution stamped before creation is a feed error, and averaging it in
   * would drag a real mean below zero.
   */
  function elapsedHours(startTs, endTs) {
    var a = toDate(startTs);
    var b = toDate(endTs);
    if (!a || !b) return null;
    if (b.getTime() < a.getTime()) return null;
    return (b.getTime() - a.getTime()) / 3600000;
  }

  /** The tickets raised in a month. The cohort every figure below is drawn from. */
  function raisedIn(tickets, monthKey) {
    if (!monthKey) return [];
    return (Array.isArray(tickets) ? tickets : []).filter(function (t) {
      return t && typeof t === 'object' && monthKeyOf(createdOf(t)) === monthKey;
    });
  }

  /**
   * Every MDR figure for one month, from one cohort.
   *
   * @param {Array}  tickets   raised in any month; filtered here
   * @param {string} monthKey  'YYYY-MM'
   * @returns {Object} raised, resolved, stillOpen, resolutionRate, meanHours,
   *                   medianHours, measuredHours
   */
  function cohortStats(tickets, monthKey) {
    var cohort = raisedIn(tickets, monthKey);
    var hours = [];
    var resolved = 0;

    cohort.forEach(function (t) {
      if (!toDate(resolvedOf(t))) return;   // still open — counted in stillOpen
      resolved++;
      // null when the pair cannot be measured — see elapsedHours(). Such a
      // ticket is still resolved; it just contributes no duration.
      var h = elapsedHours(createdOf(t), resolvedOf(t));
      if (h !== null) hours.push(h);
    });

    hours.sort(function (a, b) { return a - b; });

    return {
      monthKey:    monthKey,
      raised:      cohort.length,
      resolved:    resolved,
      stillOpen:   cohort.length - resolved,
      /*
       * A REAL RATE, because the numerator is a subset of the denominator.
       * The old one divided across cohorts and could exceed 100%; this cannot,
       * by construction. null rather than 0 when nothing was raised — a month
       * with no tickets has no rate, and printing 0% would read as total
       * failure on a month where nothing needed doing.
       */
      resolutionRate: cohort.length
        ? Math.round((resolved / cohort.length) * 100) : null,
      meanHours:   hours.length
        ? hours.reduce(function (s, h) { return s + h; }, 0) / hours.length : null,
      // Upper median on an even count, matching the figure this replaced so the
      // change of population is the only thing that moves.
      medianHours: hours.length ? hours[Math.floor(hours.length / 2)] : null,
      // How many resolutions could actually be timed. Not the same as
      // `resolved` when a feed omits a creation stamp.
      measuredHours: hours.length,
    };
  }

  /**
   * Cohort stats shaped for calculateMdrScore(), which takes an upload-style
   * object. Keeping the adapter here means the score and the KPI table cannot
   * end up counting differently.
   */
  function scoreInput(stats) {
    var s = stats || {};
    return {
      total_tickets:        s.raised || 0,
      resolved_count:       s.resolved || 0,
      // calculateMdrScore treats the speed penalty as 0 when there is nothing
      // to time, which is right: an untimed month is not a slow one.
      avg_resolution_hours: s.meanHours == null ? 0 : s.meanHours,
    };
  }

  var api = {
    monthKeyOf, lastCompleteMonth, raisedIn, cohortStats, scoreInput,
    elapsedHours,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  } else {
    root.MdrMetrics = api;
  }
})(typeof window !== 'undefined' ? window : globalThis);
