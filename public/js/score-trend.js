/* score-trend.js — what moved the Secure Score, month to month, in words.
   Loaded both in the browser (<script>, for the Secure Score tab) and in Node
   (lib/portal-routes.js via require()), the same way mdr-metrics.js is: the
   staff tab and the client portal must explain the same month the same way. */
(function (root) {
  'use strict';

  /**
   * ══ WHY THIS EXISTS ══
   *
   * The trend chart showed a line. A score that falls six points with nothing
   * beside it reads to a board as "security got worse", when the cause may be a
   * scan that finally reached the servers, or one month with three slow
   * incidents. The explanation has to be ON the trend, in terms of what
   * happened, or the number invites the wrong conversation.
   *
   * ══ TWO AUDIENCES, ONE FUNCTION ══
   *
   *   staff   also gets each component's contribution in POINTS on the
   *           composite — delta × that component's weight. That is how an
   *           analyst reconciles the headline with the components.
   *   client  never does. Weights are the weighting model, which the portal
   *           withholds everywhere else (see lib/portal-routes.js); a points
   *           breakdown is the weighting model by another name. The client is
   *           told which component moved and the evidence for it, which is the
   *           part they can act on.
   *
   * The client branch is enforced HERE, not by the caller forgetting to pass
   * weights: with audience 'client', weights are ignored even if supplied.
   */

  var COMPONENTS = [
    { key: 'vulnerabilities',  field: 'vulnScore',      label: 'Vulnerability management' },
    { key: 'awareness',        field: 'awarenessScore', label: 'Security awareness' },
    { key: 'incidentResponse', field: 'mdrScore',       label: 'Managed Detection and Response' },
  ];

  /** A finite number, or null. Null is never zero. */
  function num(v) {
    if (v === null || v === undefined || v === '') return null;
    var x = Number(v);
    return isFinite(x) ? x : null;
  }

  function signed(x, oneDp) {
    var r = oneDp ? Math.round(x * 10) / 10 : Math.round(x);
    return (r > 0 ? '+' : r < 0 ? '−' : '±') + Math.abs(r);
  }

  function plural(count, one, many) {
    return count + ' ' + (count === 1 ? one : (many || one + 's'));
  }

  function hours(h) {
    if (h === null || h === undefined) return null;
    if (h < 48) return Math.max(1, Math.round(h)) + 'h';
    return (Math.round((h / 24) * 10) / 10) + ' days';
  }

  function sentence(s) {
    return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
  }

  // ── Evidence, per component ─────────────────────────────────────────────

  function vulnEvidence(a, b) {
    if (!b) return null;
    if (a && a.scanMonth && a.scanMonth === b.scanMonth) {
      return 'No new scan; findings carried forward from the ' + b.scanMonth + ' scan.';
    }
    if (!a) {
      return 'The ' + b.scanMonth + ' scan found ' + plural(b.critical, 'critical finding') +
        ' and ' + b.high + ' high.';
    }
    return 'Critical findings ' + a.critical + ' → ' + b.critical +
      ', high ' + a.high + ' → ' + b.high +
      (b.carried ? ' (carried forward from the ' + b.scanMonth + ' scan).'
                 : ' (' + b.scanMonth + ' scan).');
  }

  function awarenessEvidence(a, b) {
    if (!b) return null;
    var now = 'training completion ' + b.pct + '% (' + b.completed + ' of ' +
      plural(b.assigned, 'assignment') + ')';
    if (!a) return sentence(now) + '.';
    if (a.pct === b.pct && a.assigned === b.assigned) return sentence(now) + ', unchanged.';
    return 'Training completion ' + a.pct + '% → ' + b.pct + '% (' + b.completed +
      ' of ' + plural(b.assigned, 'assignment') + ')' +
      (b.assigned > a.assigned ? ', with ' + (b.assigned - a.assigned) + ' newly assigned.' : '.');
  }

  function incidentEvidence(a, b) {
    if (!b) return null;
    var noun = b.typeFiltered === false ? 'ticket' : 'incident';
    if (!b.raised) {
      return 'No ' + noun + 's were raised this month' +
        (a && a.raised ? ' (' + a.raised + ' the month before).' : '.');
    }
    var out = plural(b.raised, noun) + ' raised, ' + b.resolved + ' resolved (' +
      b.resolutionRate + '%)';
    if (a && a.raised) {
      out += ', against ' + a.resolved + ' of ' + a.raised + ' (' + a.resolutionRate + '%) the month before';
    }
    var ma = a && hours(a.meanHours);
    var mb = hours(b.meanHours);
    if (mb) out += '; mean time to resolve ' + (ma ? ma + ' → ' : '') + mb;
    return out + '.';
  }

  var EVIDENCE = {
    vulnerabilities: vulnEvidence,
    awareness: awarenessEvidence,
    incidentResponse: incidentEvidence,
  };

  // ── One month against the one before ────────────────────────────────────

  function driverFor(c, prev, cur, weights, client) {
    var a = num(prev[c.field]);
    var b = num(cur[c.field]);
    if (a === null && b === null) return null;

    var evA = prev.evidence && prev.evidence[c.key];
    var evB = cur.evidence && cur.evidence[c.key];
    var evidence = EVIDENCE[c.key](evA || null, evB || null);

    var d = {
      key: c.key,
      label: c.label,
      from: a,
      to: b,
      delta: (a !== null && b !== null) ? b - a : null,
      points: null,
      status: a === null ? 'new' : b === null ? 'no-data' : (b === a ? 'unchanged' : 'moved'),
      evidence: evidence,
    };

    if (!client && d.delta !== null && weights && isFinite(Number(weights[c.key]))) {
      d.points = Math.round(d.delta * Number(weights[c.key]) * 10) / 10;
    }

    var head;
    if (d.status === 'new') {
      head = c.label + ': first measured this month, at ' + b + '/100.';
    } else if (d.status === 'no-data') {
      // Not "fell to zero". The composite is combined over the components that
      // have data, so a missing month is left out rather than scored as a zero.
      head = c.label + ': no data this month (was ' + a + '/100), so it is left out of this month rather than counted as zero.';
    } else if (d.status === 'unchanged') {
      head = c.label + ': unchanged at ' + b + '/100.';
    } else {
      head = c.label + ' ' + a + ' → ' + b + ' (' + signed(d.delta) + ')' +
        (d.points !== null ? ', ' + signed(d.points, true) + ' pts on the score' : '') + '.';
    }
    d.text = head + (evidence ? ' ' + evidence : '');
    return d;
  }

  function magnitude(d, client) {
    if (!client && d.points !== null) return Math.abs(d.points);
    return d.delta === null ? (d.status === 'moved' ? 0 : 0.5) : Math.abs(d.delta);
  }

  function summaryFor(delta, drivers) {
    if (delta === null) return 'Not comparable: one of these months has no score.';
    var movers = drivers.filter(function (d) { return d.delta; });
    var changed = drivers.filter(function (d) { return d.status === 'new' || d.status === 'no-data'; });

    if (delta === 0) {
      if (!movers.length && !changed.length) return 'Unchanged.';
      return 'Unchanged overall' + (movers.length
        ? ': ' + movers.map(function (d) { return d.label.toLowerCase() + ' ' + signed(d.delta); }).join(', ') + ' cancelled out.'
        : '.');
    }

    var up = delta > 0;
    var withIt = movers.filter(function (d) { return (d.delta > 0) === up; });
    var against = movers.filter(function (d) { return (d.delta > 0) !== up; });

    var s = (up ? 'Up ' : 'Down ') + plural(Math.abs(Math.round(delta)), 'point');
    if (withIt.length) {
      s += ', driven by ' + withIt[0].label.toLowerCase() + ' (' + signed(withIt[0].delta) + ')';
      if (withIt[1]) s += ' and ' + withIt[1].label.toLowerCase() + ' (' + signed(withIt[1].delta) + ')';
    } else if (changed.length) {
      s += ', because ' + changed[0].label.toLowerCase() +
        (changed[0].status === 'new' ? ' was measured for the first time' : ' has no data this month');
    }
    if (against.length) {
      s += ', partly offset by ' + against[0].label.toLowerCase() + ' (' + signed(against[0].delta) + ')';
    }
    return s + '.';
  }

  /**
   * Explain every month against the one before it.
   *
   * @param {Array}  history  rows shaped like /api/secure-score/history —
   *                          { monthKey, score, vulnScore, awarenessScore,
   *                            mdrScore, source?, evidence? }, any order
   * @param {Object} [opts]   { audience: 'staff'|'client', weights }
   * @returns {Array} newest first, matching the history route:
   *   { monthKey, prevMonthKey, from, to, delta, summary, drivers, note }
   */
  function explainTrend(history, opts) {
    var o = opts || {};
    var client = o.audience === 'client';
    var weights = client ? null : (o.weights || null);

    var rows = (Array.isArray(history) ? history : [])
      .filter(function (r) { return r && /^\d{4}-\d{2}$/.test(String(r.monthKey || '')); })
      .slice()
      .sort(function (x, y) { return x.monthKey < y.monthKey ? -1 : x.monthKey > y.monthKey ? 1 : 0; });

    var out = [];
    for (var i = 1; i < rows.length; i++) {
      var prev = rows[i - 1];
      var cur = rows[i];
      var from = num(prev.score);
      var to = num(cur.score);
      var delta = (from !== null && to !== null) ? to - from : null;

      var drivers = COMPONENTS
        .map(function (c) { return driverFor(c, prev, cur, weights, client); })
        .filter(Boolean)
        .sort(function (x, y) { return magnitude(y, client) - magnitude(x, client); });

      /*
       * THE RECONCILIATION NOTE (staff only). The component points should add
       * up to the headline change. When they do not, say why rather than let an
       * analyst hunt for a bug: a month missing a component is combined over
       * fewer components, and a stored snapshot was computed on the weights in
       * force that day while a reconstructed month uses today's.
       */
      var note = null;
      if (!client && delta !== null) {
        var withPoints = drivers.filter(function (d) { return d.points !== null; });
        if (withPoints.length) {
          var sum = withPoints.reduce(function (s, d) { return s + d.points; }, 0);
          var gap = Math.round((delta - sum) * 10) / 10;
          if (Math.abs(gap) >= 1.5) {
            var missing = drivers.some(function (d) { return d.status === 'new' || d.status === 'no-data'; });
            note = signed(gap, true) + ' pts of this change are not accounted for by component movement: ' +
              (missing
                ? 'a component has data in only one of the two months, so they were combined over different components.'
                : (prev.source !== cur.source
                  ? 'one month is a stored snapshot and the other is reconstructed, so they were computed at different times.'
                  : 'rounding, and the score being combined over the components with data.'));
          }
        }
      }

      out.push({
        monthKey: cur.monthKey,
        prevMonthKey: prev.monthKey,
        from: from,
        to: to,
        delta: delta,
        summary: summaryFor(delta, drivers),
        drivers: drivers,
        note: note,
      });
    }
    return out.reverse();
  }

  var api = { explainTrend: explainTrend, COMPONENTS: COMPONENTS };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  } else {
    root.ScoreTrend = api;
  }
})(typeof window !== 'undefined' ? window : globalThis);
