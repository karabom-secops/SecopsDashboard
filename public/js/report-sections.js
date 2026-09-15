'use strict';

/**
 * Section registry for the client report deck.
 *
 * Each entry declares the data it needs (`requires`, resolved to URLs by the
 * DATA_SOURCES map in tab-reports.js) and returns a slide body as an HTML
 * string, or an array of bodies to span several pages. Returning null
 * self-disables the section — the generator then skips it without consuming a
 * page number.
 *
 * The cover slide is not in this registry; ReportDeck.coverSlide() always emits
 * it as page 1.
 */
window.ReportSections = (function () {

  var S = window.ReportShell;
  var D = window.ReportDeck;
  // Shared with server.js, which require()s the same file. The MDR score and
  // the incident-resolution KPIs have to count one population of tickets, so
  // there is one implementation of what that population is.
  var MM = window.MdrMetrics;
  var P = S.PALETTE;

  // Slides are fixed-height with overflow:hidden, so an over-long list is
  // cropped silently. Cap explicitly rather than trusting the layout.
  // Budget: ~235mm of body height per A4 portrait slide. A ticket row wraps to
  // at most 3 lines at MAX_DESC_CHARS in the narrower 39%-wide column (~70mm
  // rather than the old ~118mm), giving a ~16mm row, so these fit with headroom.
  // The vuln count is lower because a .sev-row sits above that table.
  var MAX_AWARENESS_ROWS = 6;
  var MAX_TICKET_ROWS    = 12;
  var MAX_VULN_ROWS      = 11;
  var MAX_DESC_CHARS     = 80;
  // Section 9 shares a body with a 4-tile strip, so both tables stay short.
  var MAX_VENDOR_ROWS       = 6;
  var MAX_LINKED_RISK_ROWS  = 5;

  function esc(s) { return S.esc(s); }

  function truncate(str, n) {
    var s = String(str == null ? '' : str);
    return s.length > n ? s.slice(0, n).replace(/\s+\S*$/, '') + '…' : s;
  }

  function fmtDateTime(iso) {
    if (!iso) return '—';
    var d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    return d.toISOString().slice(0, 19).replace('T', ' ') + 'Z';
  }

  function fmtLongDate(ymd) {
    if (!ymd) return '—';
    var d = new Date(ymd + 'T00:00:00Z');
    if (isNaN(d.getTime())) return String(ymd);
    return d.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric', timeZone: 'UTC' });
  }

  /** '15 Aug 2026' — accepts a DATE ('2026-08-15') or a full ISO timestamp. */
  function fmtShortDate(value) {
    if (!value) return '—';
    var s = String(value);
    var d = new Date(/^\d{4}-\d{2}-\d{2}$/.test(s) ? s + 'T00:00:00Z' : s);
    if (isNaN(d.getTime())) return s;
    return d.toLocaleDateString('en-GB', {
      day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC',
    });
  }

  /** Compact large counts the way the reference deck does: 223000000 -> '223 M'. */
  function compactNumber(v) {
    var n = Number(v);
    if (!isFinite(n)) return String(v);
    if (n >= 1e9) return (Math.round(n / 1e8) / 10) + ' B';
    if (n >= 1e6) return Math.round(n / 1e6) + ' M';
    if (n >= 1e4) return Math.round(n / 1e3) + ' K';
    return String(n);
  }

  /** Effective tile value: a manual override always beats the derived figure. */
  function tileValue(tiles, id) {
    var t = (tiles || {})[id];
    if (!t) return null;
    if (t.override != null && t.override !== '') return String(t.override);
    if (t.derived == null || t.derived === '') return null;
    return String(t.derived);
  }

  /**
   * /api/vulns/latest-summary returns an ARRAY — normally a single row now that
   * the route honours ?tenantId=, but still one row per tenant when it is
   * called without one. Pick the row for the client being reported on and hand
   * back its flat summary object.
   *
   * Matching on tenantId comes FIRST. This used to shortcut to rows[0] whenever
   * the array had exactly one entry, which meant a deck could quietly print
   * another client's scan — if the response held one row for a different
   * tenant, the id was never checked. Falling back to rows[0] is only safe when
   * the caller has no tenant context at all (a single-tenant login), so that is
   * the only case where it happens.
   */
  function vulnSummaryFor(ctx) {
    var rows = ctx.data.vulnSummary;
    if (!Array.isArray(rows) || !rows.length) return null;

    var row;
    if (ctx.tenantId != null && ctx.tenantId !== '') {
      row = rows.filter(function (r) {
        return String(r.tenantId) === String(ctx.tenantId);
      })[0];
    } else if (rows.length === 1) {
      row = rows[0];
    }
    return row && row.summary ? row.summary : null;
  }

  // Mirrors getScoreRating/getScoreColor in tab-secure-score.js:31-42 — the deck
  // must not invent its own bands for a score the dashboard already rates.
  var SCORE_BANDS = [
    { min: 80, label: 'Excellent', color: '#27ae60' },
    { min: 70, label: 'Good',      color: '#f39c12' },
    { min: 50, label: 'Fair',      color: '#e67e22' },
    { min: -1, label: 'Poor',      color: '#e74c3c' },
  ];

  function scoreBand(score) {
    for (var i = 0; i < SCORE_BANDS.length; i++) {
      if (score >= SCORE_BANDS[i].min) return SCORE_BANDS[i];
    }
    return SCORE_BANDS[SCORE_BANDS.length - 1];
  }

  // ── Slide 2: Managed Cybersecurity Overview ───────────────────────────────

  var ICONS = {
    secureScore: '<svg class="ov-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M12 2 4 5v6c0 5 3.4 9.3 8 11 4.6-1.7 8-6 8-11V5l-8-3z"/><path d="M9 12l2 2 4-4"/></svg>',
    tickets:     '<svg class="ov-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    incidents:   '<svg class="ov-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="3" y="4" width="18" height="16" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="12" y1="13" x2="12" y2="16"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>',
  };

  function overviewCard(icon, title, desc, valueHtml) {
    return '<div class="ov-card">' +
        icon +
        '<div class="ov-t">' + esc(title) + '</div>' +
        '<div class="ov-d">' + esc(desc) + '</div>' +
        valueHtml +
      '</div>';
  }

  /** Coloured value pill. `tone` may be a band class or an explicit hex. */
  function pill(value, tone) {
    if (value == null) return '<div class="ov-nodata">no data</div>';
    var isHex = /^#/.test(tone);
    return '<div class="ov-pill' + (isHex ? '' : ' ' + tone) + '"' +
           (isHex ? ' style="background:' + tone + '"' : '') + '>' + esc(value) + '</div>';
  }

  function bigNumber(value, compact) {
    if (value == null) return '<div class="ov-nodata">no data</div>';
    var shown = compact && /^\d+$/.test(value) ? compactNumber(value) : value;
    return '<div class="ov-num">' + esc(shown) + '</div>';
  }

  // The three weighted inputs to the Secure Score, as shown on the Secure Score
  // tab. Weights and scores both come from /api/secure-score — nothing is
  // recomputed here.
  var COMPONENTS = [
    { key: 'vulnerabilities',  label: 'Vulnerabilities',   desc: 'Based on critical, high, medium, and low findings' },
    { key: 'awareness',        label: 'Security Awareness', desc: 'Training completion rate' },
    // Named for the SERVICE, not the internal component key. "Incident
    // Response" is what we call the field; "Managed Detection and Response" is
    // what the client buys, what their invoice says, and what the score is
    // actually computed from — the MDR ticket feed. The key stays
    // `incidentResponse` because that is the payload's name for it.
    { key: 'incidentResponse', label: 'Managed Detection and Response', desc: 'Ticket resolution & speed' },
  ];

  /**
   * The vulnerability component is scored by whichever yardstick fits the
   * client's estate, so its label and description have to follow. A client with
   * no servers is measured on endpoint patch currency, and captioning that card
   * "Based on critical, high, medium and low findings" would describe an
   * assessment that never happened.
   */
  function componentCaption(c, comp, score) {
    // Awareness run by the client, with no figures recorded, is NAMED rather
    // than treated as absent. "Training completion rate" beside a zero would
    // describe a measurement nobody took, and would read to a board as a
    // programme that failed rather than one we have not been shown.
    //
    // It used to say "weighted down", because an unevidenced internal
    // programme halved the awareness weight. That relief is gone — weights now
    // follow the service mix and a dropdown must not move one — so the copy
    // says what is true: the figures are missing, and the zero is a gap in
    // evidence rather than a verdict.
    if (c.key === 'awareness') {
      var w = (score && score.weights) || {};
      if (comp.measured === false && w.awarenessProgram === 'internal') {
        return {
          label: c.label,
          desc: 'Client-run programme — no completion figures recorded',
        };
      }
      if (comp.measured === false && w.awarenessProgram === 'none') {
        return { label: c.label, desc: 'No awareness programme in place' };
      }
      return { label: c.label, desc: c.desc };
    }

    if (c.key !== 'vulnerabilities') return { label: c.label, desc: c.desc };

    var d = comp.detail || {};
    var basis = comp.basis || 'infrastructure';

    if (basis === 'endpoint') {
      return {
        label: 'Endpoint Hygiene',
        desc: d.endpoints
          ? (d.currencyPct != null ? d.currencyPct + '% of ' : '') + d.endpoints +
            ' endpoints patched and reporting'
          : 'Endpoint patch currency and agent health',
      };
    }
    if (basis === 'unknown') {
      return { label: c.label, desc: 'Estate not recorded — measure cannot be selected' };
    }
    if (d.density != null && d.assets) {
      return {
        label: c.label,
        desc: d.density + ' weighted findings per asset across ' + d.assets +
              ' asset' + (d.assets === 1 ? '' : 's') +
              (d.capped ? ', capped by open criticals' : ''),
      };
    }
    return { label: c.label, desc: c.desc };
  }

  function componentCard(c, comp, scoreData) {
    var score  = Math.round(Number(comp.score) || 0);
    var weight = comp.weight != null ? Math.round(comp.weight * 100) + '%' : '';
    var band   = scoreBand(score);
    var cap    = componentCaption(c, comp, scoreData);

    return '<div class="cmp-card">' +
        '<div class="cmp-head">' +
          '<span class="cmp-t">' + esc(cap.label) + '</span>' +
          (weight ? '<span class="cmp-w">(' + esc(weight) + ')</span>' : '') +
        '</div>' +
        '<div class="cmp-bar">' +
          '<div class="cmp-fill" style="width:' + score + '%;background:' + band.color + '"></div>' +
        '</div>' +
        '<div class="cmp-score">' + score + '/100</div>' +
        '<div class="cmp-d">' + esc(cap.desc) + '</div>' +
      '</div>';
  }

  /** The weighted breakdown row, or '' when no score data is available. */
  function componentRow(ctx) {
    var sc = ctx.data.secureScore || {};
    var comps = sc.components;
    if (!comps) return '';

    /*
     * Only components the client buys. Without this an MDR client got a
     * "Endpoint Hygiene — 82% of 240 endpoints patched and reporting" card,
     * which is a genuine measurement of something no contracted service
     * covers, sitting in a board pack as though it were a deliverable.
     */
    var cards = COMPONENTS
      .filter(function (c) { return comps[c.key] && comps[c.key].score != null; })
      .filter(function (c) { return componentInScope(ctx, c.key); })
      .map(function (c) { return componentCard(c, comps[c.key], sc); });

    if (!cards.length) return '';
    return '<div class="cmp-row">' + cards.join('') + '</div>';
  }

  function renderOverview(ctx) {
    var tiles = (ctx.data.metrics || {}).tiles;
    if (!tiles) return null;

    // Secure Score is a 0-100 rating, so the pill is coloured by its band
    // rather than being permanently green.
    var raw   = tileValue(tiles, 'secureScore');
    var score = raw != null && /^\d+(\.\d+)?$/.test(raw) ? Math.round(Number(raw)) : null;
    var band  = score != null ? scoreBand(score) : null;
    // A Secure Score is out of 100, not a percentage — no '%' suffix.
    var scoreLabel = score != null ? String(score) : raw;

    return '<div class="ov-stack">' +
        '<div class="ov-row three">' +
          overviewCard(ICONS.secureScore, 'Secure Score',
            'Your overall security posture score across vulnerabilities, awareness and incident response.',
            pill(scoreLabel, band ? band.color : 'green') +
            (band ? '<div class="ov-sub">' + esc(band.label) + '</div>' : '')) +
          overviewCard(ICONS.tickets, 'Open Tickets',
            'The number of open tickets that still require action.',
            pill(tileValue(tiles, 'openTickets'), 'amber')) +
          overviewCard(ICONS.incidents, 'Ticketed Incidents',
            'Security incidents brought to your attention.',
            bigNumber(tileValue(tiles, 'ticketedIncidents'), false)) +
        '</div>' +
        componentRow(ctx) +
      '</div>';
  }

  // ── Slide 3: Managed Security Awareness ───────────────────────────────────

  /**
   * Group raw session rows from /api/awareness — the same payload the Awareness
   * tab renders — into the deck's "Last 3 <type>" table.
   *
   * Deliberately client-side off the shared endpoint rather than a bespoke SQL
   * aggregate, so the deck can never disagree with what the Awareness tab shows.
   *
   * `status` is only ever 'Complete' | 'Not Started' | 'N/A' — there is no
   * 'In Progress', so a started-but-unfinished session is inferred from having
   * time on the clock.
   */
  // Two decimals, because the table renders toFixed(2). Rounding to one first
  // would turn 7/549 (1.2750%) into "1.30 %" instead of "1.28 %".
  function completionPct(done, total) {
    return total > 0 ? Math.round((done / total) * 10000) / 100 : 0;
  }

  function groupSessions(sessions, sessionType) {
    var buckets = {};
    var order   = [];

    (sessions || []).forEach(function (s) {
      if (s.session_type !== sessionType) return;
      if (s.status === 'N/A') return;
      if (!s.sent_date) return;

      var day = String(s.sent_date).slice(0, 10);
      var key = day + '||' + (s.title || '');
      if (!buckets[key]) {
        buckets[key] = {
          sentDate: day,
          title: s.title || '(untitled)',
          assigned: 0, completed: 0, inProgress: 0, notStarted: 0,
        };
        order.push(key);
      }
      var b = buckets[key];
      b.assigned++;
      if (s.status === 'Complete') b.completed++;
      else if ((s.elapsed_seconds || 0) > 0) b.inProgress++;
      else b.notStarted++;
    });

    return order
      .map(function (k) { return buckets[k]; })
      .sort(function (a, b) {
        if (a.sentDate !== b.sentDate) return a.sentDate < b.sentDate ? 1 : -1;
        return a.title < b.title ? -1 : 1;
      })
      .slice(0, MAX_AWARENESS_ROWS)
      .map(function (r) {
        r.completionPct = completionPct(r.completed, r.assigned);
        return r;
      });
  }

  /**
   * Totals across the client's entire session history for one type, not just the
   * three sessions shown. /api/awareness returns the full history (the Arctic
   * Wolf sync pulls ALL_TIME), so no period filtering is involved either way —
   * this simply widens the denominator from 3 sessions to the whole programme.
   */
  function allTimeTotals(sessions, sessionType) {
    var t = { assigned: 0, completed: 0, inProgress: 0, notStarted: 0, campaigns: 0 };
    var seen = {};

    (sessions || []).forEach(function (s) {
      if (s.session_type !== sessionType) return;
      if (s.status === 'N/A') return;
      // Same exclusions as groupSessions — both rows in a table must count the
      // same population, or the Total and All time rows quietly disagree.
      if (!s.sent_date) return;

      var key = String(s.sent_date).slice(0, 10) + '||' + (s.title || '');
      if (!seen[key]) { seen[key] = true; t.campaigns++; }

      t.assigned++;
      if (s.status === 'Complete') t.completed++;
      else if ((s.elapsed_seconds || 0) > 0) t.inProgress++;
      else t.notStarted++;
    });

    t.completionPct = completionPct(t.completed, t.assigned);
    return t;
  }

  function totalsFor(rows) {
    var t = rows.reduce(function (a, r) {
      return {
        assigned:   a.assigned   + r.assigned,
        notStarted: a.notStarted + r.notStarted,
        inProgress: a.inProgress + r.inProgress,
        completed:  a.completed  + r.completed,
      };
    }, { assigned: 0, notStarted: 0, inProgress: 0, completed: 0 });
    t.completionPct = completionPct(t.completed, t.assigned);
    return t;
  }

  function awarenessTable(caption, rows, shownTotals, allTime) {
    var cols = [
      { label: 'Date',         key: 'sentDate',      width: '19%', raw: function (r) { return esc(fmtLongDate(r.sentDate)); } },
      { label: 'Title',        key: 'title',         width: '33%' },
      { label: 'Assigned',     key: 'assigned',      width: '10%', cls: 'num' },
      { label: 'Not started',  key: 'notStarted',    width: '10%', cls: 'num' },
      { label: 'In progress',  key: 'inProgress',    width: '10%', cls: 'num' },
      { label: 'Completed',    key: 'completed',     width: '10%', cls: 'num' },
      { label: 'Completion %', key: 'completionPct', width: '12%', cls: 'num',
        raw: function (r) { return esc(Number(r.completionPct).toFixed(2)) + ' %'; } },
    ];
    // Two summary rows: the visible three (so the arithmetic on the slide adds
    // up) and the whole programme to date. Only show the second when it actually
    // covers more than what is listed above.
    var totalRows = [];
    if (rows.length) {
      totalRows.push(Object.assign({ _label: 'Total' }, shownTotals));
      if (allTime && allTime.campaigns > rows.length) {
        totalRows.push(Object.assign(
          { _label: 'All time (' + allTime.campaigns + ')' },
          allTime
        ));
      }
    }

    return D.dataTable({
      caption:   caption,
      cols:      cols,
      rows:      rows.slice(0, MAX_AWARENESS_ROWS),
      totalRows: totalRows,
    });
  }

  function awarenessBlock(ctx) {
    // Not shown at all for a client without the training service.
    if (!componentInScope(ctx, 'awareness')) return null;
    var a = ctx.data.awareness;
    if (!a) return null;

    // Summary-format uploads carry no session rows, so the tables genuinely
    // cannot be built — the section self-disables.
    var sessionRows = a.sessions || [];
    if (!sessionRows.length) return null;

    var sessions = groupSessions(sessionRows, 'Awareness Session');
    var quizzes  = groupSessions(sessionRows, 'Quiz');
    if (!sessions.length && !quizzes.length) return null;

    var totals = { sessions: totalsFor(sessions), quizzes: totalsFor(quizzes) };
    var allTime = {
      sessions: allTimeTotals(sessionRows, 'Awareness Session'),
      quizzes:  allTimeTotals(sessionRows, 'Quiz'),
    };

    // The Secure Score is not repeated here — it has its own tile and weighted
    // breakdown on the Overview slide.
    var html =
      '<div style="margin-bottom:7mm">' +
        // Caption follows the row count rather than hard-coding one: the cap is
        // MAX_AWARENESS_ROWS, and a client with fewer campaigns must not be
        // shown a heading promising more than the table lists.
        awarenessTable('Last ' + sessions.length + ' Session' + (sessions.length === 1 ? '' : 's'),
                       sessions, totals.sessions, allTime.sessions) +
      '</div>' +
      '<div>' +
        awarenessTable('Last ' + quizzes.length + ' Quiz' + (quizzes.length === 1 ? '' : 'zes'),
                       quizzes, totals.quizzes, allTime.quizzes) +
      '</div>';

    return html;
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Executive risk policy
  //
  // These thresholds are what turn raw scores into board-facing statements
  // ("outside appetite", "overdue", "SLA compliance"). They are deliberately in
  // one block so the policy can be changed in a single place and so nobody has
  // to guess where a RAG rating came from.
  // ══════════════════════════════════════════════════════════════════════════

  /**
   * Days from first_seen_at within which a finding of each severity must be
   * fixed — NOT a local policy, and deliberately not a literal.
   *
   * This block owns the report's board-facing thresholds, and the remediation
   * SLA used to be one of them: a private 7/30/90/180 that had drifted from
   * lib/vuln-parser.js's 7/14/30/60. The parser is the module that computes
   * the due_date stored on each finding, so the deck was contradicting the
   * dashboard AND the database about the same row — a High at 20 days was
   * flagged overdue on the Vulnerabilities tab and reported to the board as
   * comfortably within SLA. The prose two hundred lines below already said
   * "High 2 weeks", so the file also contradicted itself.
   *
   * Read through the accessor, at use time. window.VULN_SLA_DAYS is filled
   * from GET /api/auth/me; capturing it into a var here would freeze whatever
   * happened to be set when this file parsed, which is the fallback.
   */
  function vulnSlaDays(severity) {
    if (typeof window !== 'undefined' && typeof window.vulnSlaDays === 'function') {
      return window.vulnSlaDays(severity);
    }
    // Standalone (a headless test harness, a saved deck): mirror the parser.
    var fallback = { critical: 7, high: 14, medium: 30, low: 60 };
    var v = fallback[String(severity == null ? '' : severity).trim().toLowerCase()];
    return v === undefined ? null : v;
  }

  /** The severities that carry an SLA at all, in order. */
  var VULN_SLA_SEVERITIES = ['Critical', 'High', 'Medium', 'Low'];

  /** Target score per domain. A domain below target is outside appetite. */
  var MATURITY_TARGETS = {
    vulnerabilities:  80,
    awareness:        90,
    incidentResponse: 90,
    overall:          75,
  };

  /** An open risk at or above this score puts its area outside appetite. */
  var RISK_APPETITE_SCORE = 15;

  /**
   * RAG rating measured against the area's own target, not an absolute band.
   *
   * Both the rating and the within-appetite column must come from the same
   * comparison, otherwise the table can say "Low risk" and "outside appetite"
   * on the same row — which is exactly the sort of thing that costs a report
   * its credibility with an executive audience. Low is true if and only if the
   * area is at or above target.
   */
  function ragFor(score, target) {
    if (score == null) return { label: 'Unknown', tone: '#8C8C8C' };
    var gap = score - (target == null ? 75 : target);
    if (gap >= 0)  return { label: 'Low',    tone: '#2E9E5B' };
    if (gap >= -10) return { label: 'Medium', tone: '#f39c12' };
    return { label: 'High', tone: '#e74c3c' };
  }

  /** Compare two scores into a trend word. */
  function trendFor(current, previous) {
    if (current == null || previous == null) return { label: 'No prior data', mark: '' };
    var delta = current - previous;
    if (delta > 3)  return { label: 'Improving',  mark: '▲', tone: '#2E9E5B' };
    if (delta < -3) return { label: 'Increasing', mark: '▼', tone: '#e74c3c' };
    return { label: 'Stable', mark: '→', tone: '#8C8C8C' };
  }

  /** Whole days between a timestamp and now. */
  function ageDays(ts) {
    if (!ts) return null;
    var d = new Date(ts);
    if (isNaN(d.getTime())) return null;
    return Math.floor((Date.now() - d.getTime()) / 86400000);
  }

  /** Normalise a vuln severity label to one that carries an SLA, or null. */
  function sevKey(risk) {
    var t = titleCase(risk);
    return VULN_SLA_SEVERITIES.indexOf(t) >= 0 ? t : null;
  }

  // ── Remediation Tracker ───────────────────────────────────────────────────
  // Left column: what was closed out during the reporting period.
  // Right column: what is due in the month after it.
  //
  // Sources are the same combined payload the Remediation Tracker tab uses
  // (/api/remediation-tracker): vuln findings, pentest findings and risks.
  //
  // All three carry a target date: pentest findings and risks have one entered by
  // hand, vuln findings get one from the severity SLA measured off first
  // detection. The numbers live in lib/vuln-parser.js and reach the browser via
  // GET /api/auth/me — they are deliberately not restated here, because the
  // version of this comment that did restate them went stale and disagreed.

  // Both columns now stack vertically (see .rem-cols), so the two tables share
  // the body height rather than sitting side by side.
  var MAX_REMEDIATION_ROWS = 6;

  // The Scheduled list is never truncated — everything due in the period is
  // shown, spilling onto continuation slides. Row budgets are set against the
  // ~235mm portrait body: page 1 shares its height with the Remediated table,
  // continuation pages carry one table each and so fit far more.
  var SCHEDULED_ROWS_FIRST = MAX_REMEDIATION_ROWS;
  var SCHEDULED_ROWS_CONT  = 18;

  /** 'YYYY-MM' of a timestamp, or null. */
  function monthOf(ts) {
    if (!ts) return null;
    var s = String(ts);
    return /^\d{4}-\d{2}/.test(s) ? s.slice(0, 7) : null;
  }

  /** Shift a 'YYYY-MM' period by n months. */
  function shiftPeriod(period, n) {
    var m = /^(\d{4})-(\d{2})$/.exec(period || '');
    if (!m) return null;
    var d = new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1 + n, 1));
    return d.toISOString().slice(0, 7);
  }

  /** 'July 2026' from 'YYYY-MM'. */
  function periodName(period) {
    var m = /^(\d{4})-(\d{2})$/.exec(period || '');
    if (!m) return period || '';
    return new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, 1))
      .toLocaleDateString('en-GB', { month: 'long', year: 'numeric', timeZone: 'UTC' });
  }

  var CLOSED_PENTEST = { fixed: 1, accepted: 1, 'risk-accepted': 1 };
  var CLOSED_VULN    = { fixed: 1, accepted: 1 };

  /** Vuln findings store 'Critical'; pentest findings store 'critical'. */
  function titleCase(s) {
    var str = String(s == null ? '' : s).trim();
    return str ? str.charAt(0).toUpperCase() + str.slice(1).toLowerCase() : '';
  }

  function collectRemediated(data, period) {
    var out = [];

    (data.vulns || []).forEach(function (v) {
      if (v.status !== 'fixed') return;
      if (monthOf(v.statusUpdatedAt) !== period) return;
      out.push({ source: 'Vuln', item: v.name, detail: v.host || v.cve || '',
                 severity: v.risk || '', when: v.statusUpdatedAt });
    });

    (data.pentestFindings || []).forEach(function (f) {
      if (f.status !== 'fixed') return;
      if (monthOf(f.status_updated_at) !== period) return;
      out.push({ source: 'Pentest', item: f.title, detail: f.owner || '',
                 severity: f.severity || '', when: f.status_updated_at });
    });

    (data.risks || []).forEach(function (r) {
      if (r.stage !== 'closed') return;
      if (monthOf(r.closed_at) !== period) return;
      out.push({ source: 'Risk', item: r.title, detail: r.owner || '',
                 severity: r.risk_score != null ? 'Score ' + r.risk_score : '',
                 when: r.closed_at });
    });

    return out.sort(function (a, b) { return String(a.when) < String(b.when) ? 1 : -1; });
  }

  function collectScheduled(data, period) {
    var out = [];

    (data.vulns || []).forEach(function (v) {
      if (CLOSED_VULN[v.status]) return;
      if (monthOf(v.dueDate) !== period) return;
      out.push({ source: 'Vuln', item: v.name, detail: v.host || v.cve || '',
                 severity: v.risk || '', when: v.dueDate });
    });

    (data.pentestFindings || []).forEach(function (f) {
      if (CLOSED_PENTEST[f.status]) return;
      if (monthOf(f.due_date) !== period) return;
      out.push({ source: 'Pentest', item: f.title, detail: f.owner || '',
                 severity: f.severity || '', when: f.due_date });
    });

    (data.risks || []).forEach(function (r) {
      if (r.stage === 'closed') return;
      if (monthOf(r.due_date) !== period) return;
      out.push({ source: 'Risk', item: r.title, detail: r.owner || '',
                 severity: r.risk_score != null ? 'Score ' + r.risk_score : '',
                 when: r.due_date });
    });

    return out.sort(function (a, b) { return String(a.when) < String(b.when) ? -1 : 1; });
  }

  function remediationTable(rows, dateLabel, limit) {
    if (!rows.length) return null;
    var max = limit === undefined ? MAX_REMEDIATION_ROWS : limit;
    return D.dataTable({
      cols: [
        { label: 'Item', key: 'item', width: '46%',
          raw: function (r) {
            return '<span class="rem-src">' + esc(r.source) + '</span> ' +
                   esc(truncate(r.item || '(untitled)', 68));
          } },
        { label: 'Severity', key: 'severity', width: '18%',
          raw: function (r) { return esc(truncate(titleCase(r.severity) || '—', 16)); } },
        { label: 'Owner / Host', key: 'detail', width: '20%',
          raw: function (r) { return esc(truncate(r.detail || '—', 26)); } },
        { label: dateLabel, key: 'when', width: '16%', cls: 'num',
          raw: function (r) { return esc(fmtShortDate(r.when)); } },
      ],
      rows: rows.slice(0, max),
    });
  }

  function remediationColumn(heading, sub, rows, dateLabel, emptyMsg, caveat, limit) {
    var max   = limit === undefined ? MAX_REMEDIATION_ROWS : limit;
    var table = remediationTable(rows, dateLabel, max);
    return '<div class="rem-col">' +
        '<div class="rem-h">' + esc(heading) + '</div>' +
        '<div class="rem-sub">' + esc(sub) + '</div>' +
        (table || '<div class="rem-empty">' + esc(emptyMsg) + '</div>') +
        (rows.length > max
          ? '<div class="rem-more">+ ' + (rows.length - max) +
            ' more not shown</div>'
          : '') +
        (caveat ? '<div class="rem-more">' + esc(caveat) + '</div>' : '') +
      '</div>';
  }

  function remediationPages(ctx) {
    var data = ctx.data.vulnFindings;
    if (!data) return null;

    var period = ctx.period;
    var next   = shiftPeriod(period, 1);
    if (!next) return null;

    var done     = collectRemediated(data, period);
    var upcoming = collectScheduled(data, next);
    if (!done.length && !upcoming.length) return null;

    // Built from the live table rather than written out, so the sentence can
    // never end up describing a policy the report is no longer applying —
    // which is exactly what had happened: this said "High 2 weeks" while the
    // code above it was allowing thirty days.
    var slaNote = 'Scan findings are dated by remediation SLA: ' +
      VULN_SLA_SEVERITIES.map(function (s) {
        return s + ' ' + vulnSlaDays(s) + ' days';
      }).join(', ') + ' from first detection.';

    // Page 1 shares its height with the Remediated table, so it carries the
    // first slice of Scheduled; the remainder spills onto continuation pages.
    var firstSlice = upcoming.slice(0, SCHEDULED_ROWS_FIRST);
    var overflow   = upcoming.slice(SCHEDULED_ROWS_FIRST);
    var totalPages = 1 + Math.ceil(overflow.length / SCHEDULED_ROWS_CONT);

    function scheduledSub(pageNo) {
      var sub = 'Due during ' + periodName(next);
      if (totalPages > 1) sub += ' — page ' + pageNo + ' of ' + totalPages;
      return sub;
    }

    var pages = ['<div class="rem-cols">' +
        remediationColumn(
          'Remediated', 'Closed out during ' + periodName(period),
          done, 'Closed',
          'Nothing was closed out during ' + periodName(period) + '.') +
        remediationColumn(
          'Scheduled', scheduledSub(1),
          firstSlice, 'Due',
          'Nothing is currently scheduled for ' + periodName(next) + '.',
          overflow.length ? null : slaNote,
          SCHEDULED_ROWS_FIRST) +
      '</div>'];

    for (var i = 0; i < overflow.length; i += SCHEDULED_ROWS_CONT) {
      var chunk = overflow.slice(i, i + SCHEDULED_ROWS_CONT);
      var last  = i + SCHEDULED_ROWS_CONT >= overflow.length;
      pages.push('<div class="rem-cols">' +
          remediationColumn(
            'Scheduled (continued)', scheduledSub(pages.length + 1),
            chunk, 'Due', '',
            last ? slaNote : null,
            SCHEDULED_ROWS_CONT) +
        '</div>');
    }

    return pages;
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Executive risk assurance sections
  // ══════════════════════════════════════════════════════════════════════════

  /**
   * Optional analyst commentary beneath a section, typed on the Reports tab.
   *
   * Rendered verbatim (escaped, with line breaks preserved) and omitted entirely
   * when empty, so an unused box never leaves a blank panel on the page.
   */
  function sectionComment(ctx, id) {
    var text = ((ctx.comments || {})[id] || '').trim();
    if (!text) return '';
    return '<div class="sec-comment">' +
        '<div class="sec-comment-label">Commentary</div>' +
        '<div class="sec-comment-body">' +
          esc(text).replace(/\r?\n/g, '<br>') +
        '</div>' +
      '</div>';
  }

  /** Effective tile value as a number, or null when neither set nor derived. */
  function tileNum(ctx, id) {
    var raw = tileValue(((ctx.data.metrics || {}).tiles) || {}, id);
    if (raw == null || raw === '') return null;
    var n = parseFloat(String(raw).replace(/[^0-9.\-]/g, ''));
    return isNaN(n) ? null : n;
  }

  /**
   * Incidents in the reporting period. ONE definition, used by both the
   * Executive Summary tile and the prose drafted above it.
   *
   * Two feeds with no shared key: incidents logged on the Incident Response tab,
   * and the MDR tickets the Operations tab raises. An event escalated from a
   * ticket into a logged incident appears in both, so `total` is a sum and not a
   * deduplicated count — the section footnote says so rather than implying a
   * precision the data does not have.
   *
   * WHY IT IS A FUNCTION. The tile counted both feeds; the drafted paragraph
   * counted only the logged ones. A client with a month of MDR activity and no
   * separately-logged incident read "2 Security incidents this period" in the
   * tile and "No security incidents were recorded" in the sentence beneath it.
   * Two answers to one question on one slide, and the analyst's only recourse is
   * to retype the prose — which is how a hand-written number reaches a board.
   */
  function incidentCount(ctx) {
    var ir = (((ctx.data || {}).vulnFindings || {}).incidents || []).filter(function (i) {
      return monthOf(i.opened_at) === ctx.period;
    }).length;
    /*
     * MDR tickets count only for a client who buys MDR — the same gate the tile
     * applies. Incidents logged on the Incident Response tab always count:
     * those are recorded against the client directly and belong to them
     * whatever they buy from us.
     *
     * Only tickets typed 'incident'. The tile is captioned "Security incidents
     * this period", and it was counting the whole feed — support requests and
     * administrative tickets included — which overstated the number on the
     * front page of the board pack. Through the shared cohort module, so this
     * tile and the incident-resolution KPIs count the same things.
     */
    var mdr = serviceInScope(ctx, 'mdr')
      ? MM.cohortStats(((ctx.data || {}).mdr || {}).tickets || [], ctx.period).raised
      : 0;
    return { ir: ir, mdr: mdr, total: ir + mdr };
  }

  /** Component scores from /api/secure-score, rounded. */
  function componentScores(ctx) {
    var c = (ctx.data.secureScore || {}).components || {};
    function s(k) {
      return c[k] && c[k].score != null ? Math.round(Number(c[k].score)) : null;
    }
    // A component with no data behind it scores 0 rather than being excluded —
    // an unmeasured control is an unmanaged one. The deck has to be able to
    // tell that zero apart from a zero that was earned, because on a
    // client-facing page "Vulnerability Management: 0" reads as a catastrophic
    // scan result when it may only mean no scan was uploaded.
    // Payloads predating the flag are treated as measured.
    function m(k) { return !(c[k] && c[k].measured === false); }
    return {
      vulnerabilities:  s('vulnerabilities'),
      awareness:        s('awareness'),
      incidentResponse: s('incidentResponse'),
      overall: (ctx.data.secureScore || {}).score != null
        ? Math.round(Number(ctx.data.secureScore.score)) : null,
      measured: {
        vulnerabilities:  m('vulnerabilities'),
        awareness:        m('awareness'),
        incidentResponse: m('incidentResponse'),
        overall:          true,
      },
    };
  }

  /**
   * The reporting period's preceding month, from /api/secure-score/history.
   *
   * Selected by month key rather than by array position: the history covers
   * whichever months have data, so index 1 is not reliably the month before the
   * period being reported on. If that exact month is absent, fall back to the
   * most recent month that precedes it.
   *
   * Component scores are null on 'derived' rows — awareness and incident-response
   * inputs are overwritten by each upload, so past months genuinely have none
   * until stored snapshots accumulate.
   */
  function previousScores(ctx) {
    var h = ctx.data.secureScoreHistory;
    var rows = Array.isArray(h) ? h : (h && h.history) || [];
    var want = shiftPeriod(ctx.period, -1);
    if (!rows.length || !want) return {};

    var prev = null;
    rows.forEach(function (r) {
      var k = r.monthKey || r.month_key;
      if (!k || k > want) return;
      if (!prev || k > (prev.monthKey || prev.month_key)) prev = r;
    });
    if (!prev) return {};

    var n = function (v) { return v == null ? null : Math.round(v); };
    return {
      monthKey:         prev.monthKey || prev.month_key,
      source:           prev.source || 'derived',
      vulnerabilities:  n(prev.vulnScore),
      awareness:        n(prev.awarenessScore),
      incidentResponse: n(prev.mdrScore),
      overall:          n(prev.score),
    };
  }

  // ── Executive Risk Assessment ─────────────────────────────────────────────

  /** Name the signals the Identity score actually used, so the basis is honest. */
  function identityBasis(ctx) {
    var id = identityMetrics(ctx);
    if (!id || !id.termsUsed || !id.termsUsed.length) return 'Managed Identity telemetry';
    var names = {
      modernAuth:    'modern auth',
      riskHandled:   'risk handling',
      signInSuccess: 'sign-in success',
    };
    return id.termsUsed.map(function (k) { return names[k]; }).join(', ') + ' (Managed Identity)';
  }

  function riskAreas(ctx) {
    var now  = componentScores(ctx);
    var prev = previousScores(ctx);

    return [
      { label: 'Vulnerability Exposure',      score: now.vulnerabilities,  prev: prev.vulnerabilities,
        target: MATURITY_TARGETS.vulnerabilities,  basis: 'Secure Score component' },
      { label: 'User Behaviour',              score: now.awareness,        prev: prev.awareness,
        target: MATURITY_TARGETS.awareness,        basis: 'Awareness completion' },
      { label: 'Incident Response Capability', score: now.incidentResponse, prev: prev.incidentResponse,
        target: MATURITY_TARGETS.incidentResponse, basis: 'Resolution rate & speed' },
      { label: 'Identity Security',           score: (identityMetrics(ctx) || {}).score, prev: null,
        target: 90, basis: identityBasis(ctx) },
      { label: 'Endpoint Protection',         score: (endpointMetrics(ctx) || {}).agentCurrency, prev: null,
        target: 98, basis: 'EDR agent currency' },
    ];
  }

  function riskAreaTable(ctx, areas) {

    var openRisks    = ((ctx.data.vulnFindings || {}).risks) || [];
    var aboveAppetite = openRisks.filter(function (r) {
      return r.stage !== 'closed' && Number(r.risk_score) >= RISK_APPETITE_SCORE;
    }).length;

    var rows = areas.map(function (a) {
      var rag   = ragFor(a.score, a.target);
      var trend = trendFor(a.score, a.prev);
      var within = a.score == null ? null : a.score >= a.target;
      return {
        area: a.label,
        basis: a.basis,
        risk: rag,
        score: a.score,
        target: a.target,
        trend: trend,
        within: within,
      };
    });

    return '<table class="dt rag">' +
        '<thead><tr>' +
          '<th style="width:30%">Risk Area</th>' +
          '<th style="width:16%">Current Risk</th>' +
          '<th class="num" style="width:14%">Score / Target</th>' +
          '<th style="width:20%">Trend</th>' +
          '<th style="width:20%">Within Appetite</th>' +
        '</tr></thead><tbody>' +
        rows.map(function (r) {
          return '<tr>' +
              '<td><div class="rag-area">' + esc(r.area) + '</div>' +
                  '<div class="rag-basis">' + esc(r.basis) + '</div></td>' +
              '<td><span class="rag-pill" style="background:' + r.risk.tone + '">' +
                  esc(r.risk.label) + '</span></td>' +
              '<td class="num">' + (r.score == null ? '—' : r.score + ' / ' + r.target) + '</td>' +
              '<td><span style="color:' + (r.trend.tone || '#8C8C8C') + '">' +
                  esc(r.trend.mark) + '</span> ' + esc(r.trend.label) + '</td>' +
              '<td>' + (r.within == null
                ? '<span class="rag-unknown">Not measured</span>'
                : (r.within ? '<span class="rag-yes">Yes</span>'
                            : '<span class="rag-no">No</span>')) + '</td>' +
            '</tr>';
        }).join('') +
      '</tbody></table>' +
      '<div class="rag-note">' +
        'Within appetite means the area is at or above its target score. ' +
        (aboveAppetite
          ? esc(String(aboveAppetite)) + ' open risk' + (aboveAppetite === 1 ? '' : 's') +
            ' currently score ' + RISK_APPETITE_SCORE + ' or above on the risk register.'
          : 'No open risk currently scores ' + RISK_APPETITE_SCORE + ' or above.') +
      '</div>' +
      sectionComment(ctx, 'execRisk');
  }

  // ── Business Impact Summary ───────────────────────────────────────────────

  function renderBusinessImpact(ctx) {
    var incidents = ((ctx.data.vulnFindings || {}).incidents) || [];
    var period    = ctx.period;

    function inPeriod(i) { return monthOf(i.opened_at) === period; }
    function countType(t) {
      return incidents.filter(function (i) { return inPeriod(i) && i.incident_type === t; }).length;
    }

    var securityIncidents = incidents.filter(inPeriod).length;
    var mdrTickets = ((ctx.data.mdr || {}).tickets || []).filter(function (t) {
      return monthOf(t.createdAt) === period;
    }).length;

    // Everything here comes from the Incident Response tab's records. A
    // "confirmed breach" is a data-breach incident that was worked to closure;
    // "material" is critical or high severity — both are properties the IR tab
    // already captures, so nothing is attested separately.
    var closed = { resolved: 1, closed: 1 };
    var confirmedBreaches = incidents.filter(function (i) {
      return inPeriod(i) && i.incident_type === 'data_breach' && closed[i.status];
    }).length;
    var material = incidents.filter(function (i) {
      var s = String(i.severity || '').toLowerCase();
      return inPeriod(i) && (s === 'critical' || s === 'high');
    }).length;

    var rows = [
      { label: 'Confirmed Breaches',            value: confirmedBreaches },
      { label: 'Security Incidents',            value: Math.max(securityIncidents, mdrTickets) },
      { label: 'Material Incidents',            value: material },
      { label: 'Data Loss Events',              value: countType('data_breach') },
      { label: 'Privileged Account Compromise', value: countType('unauthorized_access') },
      { label: 'Ransomware Events',             value: countType('malware_ransomware') },
    ];

    if (!incidents.length && !mdrTickets) return null;

    return '<div class="bi-grid">' +
        rows.map(function (r) {
          var shown = r.value == null ? 'Not measured' : String(r.value);
          var zero  = r.value === 0;
          return '<div class="bi-cell' + (zero ? ' ok' : '') + '">' +
              '<div class="bi-v' + (r.value == null ? ' nd' : '') + '">' + esc(shown) + '</div>' +
              '<div class="bi-l">' + esc(r.label) + '</div>' +
            '</div>';
        }).join('') +
      '</div>' +
      '<div class="rag-note">Counted from Incident Response records for ' +
        esc(ctx.periodLabel || 'the period') + '. A confirmed breach is a data-breach ' +
        'incident worked to closure; material means critical or high severity.</div>' +
      sectionComment(ctx, 'businessImpact');
  }

  // ── Top Cyber Risks (risk register) ───────────────────────────────────────

  var MAX_TOP_RISKS = 6;

  function renderTopRisks(ctx) {
    var risks = ((ctx.data.vulnFindings || {}).risks) || [];
    var open  = risks.filter(function (r) { return r.stage !== 'closed'; });
    if (!open.length) return null;

    open.sort(function (a, b) { return (Number(b.risk_score) || 0) - (Number(a.risk_score) || 0); });

    return D.dataTable({
      cols: [
        { label: 'Risk', key: 'title', width: '36%',
          raw: function (r) { return esc(truncate(r.title || '(untitled)', 62)); } },
        { label: 'Rating', key: 'risk_score', width: '13%',
          raw: function (r) {
            var s = Number(r.risk_score) || 0;
            var band = s >= 20 ? { l: 'Critical', t: '#c0392b' }
                     : s >= 15 ? { l: 'High',     t: '#e74c3c' }
                     : s >= 8  ? { l: 'Medium',   t: '#f39c12' }
                               : { l: 'Low',      t: '#2E9E5B' };
            return '<span class="rag-pill" style="background:' + band.t + '">' +
                   esc(band.l) + ' ' + s + '</span>';
          } },
        { label: 'Owner', key: 'owner', width: '22%',
          raw: function (r) { return esc(truncate(r.owner || 'Unassigned', 30)); } },
        { label: 'Stage', key: 'stage', width: '15%',
          raw: function (r) { return esc(titleCase(r.stage || '')); } },
        { label: 'Target Closure', key: 'due_date', width: '14%', cls: 'num',
          raw: function (r) { return esc(fmtShortDate(r.due_date)); } },
      ],
      rows: open.slice(0, MAX_TOP_RISKS),
    }) + (open.length > MAX_TOP_RISKS
      ? '<div class="rem-more">+ ' + (open.length - MAX_TOP_RISKS) + ' further open risks on the register</div>'
      : '');
  }

  // ── Vulnerability Exposure Dashboard ──────────────────────────────────────

  var VULN_OPEN_STATUSES = { open: 1, 'in-progress': 1 };

  function vulnExposureBlock(ctx) {
    // Scan findings, so this follows the Vulnerability Management SERVICE — not
    // the vulnerabilities score component, which an MDR client satisfies
    // through endpoint patch currency without buying a scan.
    if (!serviceInScope(ctx, 'vuln')) return null;
    var findings = ((ctx.data.vulnFindings || {}).vulns) || [];
    if (!findings.length) return null;

    var order = ['Critical', 'High', 'Medium', 'Low'];
    var buckets = {};
    order.forEach(function (s) {
      buckets[s] = { severity: s, open: 0, overdue: 0, accepted: 0, ageSum: 0, ageN: 0 };
    });

    var oldest = null;
    var withinSla = 0, slaTotal = 0;

    findings.forEach(function (f) {
      var k = sevKey(f.risk);
      if (!k) return;
      var b = buckets[k];

      if (f.status === 'accepted') { b.accepted++; return; }
      if (!VULN_OPEN_STATUSES[f.status]) return;

      b.open++;
      var age = ageDays(f.firstSeenAt);
      if (age != null) {
        b.ageSum += age; b.ageN++;
        slaTotal++;
        if (age > vulnSlaDays(k)) b.overdue++; else withinSla++;
        if (!oldest || age > oldest.age) oldest = { age: age, name: f.name, severity: k };
      }
    });

    var rows = order.map(function (s) {
      var b = buckets[s];
      b.avgAge = b.ageN ? Math.round(b.ageSum / b.ageN) : null;
      return b;
    });

    var totals = rows.reduce(function (a, b) {
      return { open: a.open + b.open, overdue: a.overdue + b.overdue, accepted: a.accepted + b.accepted };
    }, { open: 0, overdue: 0, accepted: 0 });

    if (!totals.open && !totals.accepted) return null;

    var slaPct = slaTotal ? Math.round((withinSla / slaTotal) * 1000) / 10 : null;

    var table = D.dataTable({
      cols: [
        { label: 'Severity', key: 'severity', width: '22%',
          raw: function (r) {
            return '<span class="sev-dot" style="background:' + severityTone(r.severity) + '"></span> ' +
                   esc(r.severity) +
                   '<span class="sev-sla">' + vulnSlaDays(r.severity) + 'd SLA</span>';
          } },
        { label: 'Open',          key: 'open',     width: '15%', cls: 'num' },
        { label: 'Overdue',       key: 'overdue',  width: '15%', cls: 'num',
          raw: function (r) {
            return r.overdue
              ? '<span class="ov-bad">' + r.overdue + '</span>'
              : '0';
          } },
        { label: 'Risk Accepted', key: 'accepted', width: '18%', cls: 'num' },
        { label: 'Avg Age (days)', key: 'avgAge',  width: '18%', cls: 'num',
          raw: function (r) { return r.avgAge == null ? '—' : String(r.avgAge); } },
      ],
      rows: rows,
      totalRows: [{ _label: 'Total', open: totals.open, overdue: totals.overdue, accepted: totals.accepted }],
    });

    var facts = [
      { l: 'SLA compliance', v: slaPct == null ? '—' : slaPct + ' %' },
      { l: 'Oldest outstanding', v: oldest ? oldest.age + ' days' : '—' },
      { l: 'Risk accepted', v: String(totals.accepted) },
    ];

    return table +
      '<div class="ve-facts">' +
        facts.map(function (f) {
          return '<div class="ve-fact"><div class="ve-fv">' + esc(f.v) + '</div>' +
                 '<div class="ve-fl">' + esc(f.l) + '</div></div>';
        }).join('') +
      '</div>' +
      (oldest
        ? '<div class="rag-note">Oldest outstanding: ' + esc(truncate(oldest.name, 80)) +
          ' (' + esc(oldest.severity) + ', ' + oldest.age + ' days). ' +
          'SLA measured from first detection.</div>'
        : '');
  }

  function severityTone(s) {
    return { Critical: '#c0392b', High: '#e74c3c', Medium: '#f39c12', Low: '#2E9E5B' }[s] || '#8C8C8C';
  }

  // ── Cyber Defence Coverage ────────────────────────────────────────────────

  /** Unwrap the { available, data } envelope the Wazuh-backed screens return. */
  function envData(node) {
    return node && node.available && node.data ? node.data : null;
  }

  function pct(part, whole) {
    if (!whole) return null;
    return Math.round((part / whole) * 1000) / 10;
  }

  /**
   * Share of a tally matching `match`, as a percentage of the rows that carry
   * the field at all.
   *
   * Returns null — "not measured" — when the tally is empty, because an empty
   * terms aggregation means the field is missing from the index mapping. Using
   * total sign-ins as the denominator instead would silently score an
   * unmapped field as 0%, which on an identity slide reads as a catastrophic
   * finding rather than as missing data.
   */
  function tallyShare(rows, match) {
    if (!Array.isArray(rows) || !rows.length) return null;
    var denom = 0, hit = 0;
    rows.forEach(function (r) {
      var n = Number(r.count) || 0;
      denom += n;
      if (match(String(r.label || '').toLowerCase())) hit += n;
    });
    if (!denom) return null;
    return Math.round((hit / denom) * 1000) / 10;
  }

  /**
   * Weights for the Identity Security composite.
   *
   * Only ratios the current integration actually produces are here. MFA
   * enrolment, Conditional Access coverage and device compliance are not: they
   * are directory configuration, and neither the Office 365 audit log nor the
   * MS Graph feed carries them. Rather than report them as permanently
   * unmeasured, they are left out until a Graph configuration integration
   * exists.
   *
   * Any term without data drops out and the rest re-normalise, so a partial
   * signal still scores rather than dragging the result down.
   */
  var IDENTITY_WEIGHTS = {
    modernAuth:    0.45,   // ms-graph: sign-ins not on legacy protocols
    riskHandled:   0.35,   // ms-graph: flagged users actually dealt with
    signInSuccess: 0.20,   // office365 audit: credential-attack pressure
  };

  var RISK_HANDLED_STATES = { remediated: 1, dismissed: 1, confirmedsafe: 1 };

  /**
   * Identity posture from the Managed Identity tab (/api/o365/summary).
   *
   * MFA and Conditional Access *registration* coverage are tenant configuration
   * and are not in this telemetry — it records sign-in events. What is
   * measurable from events: how many sign-ins actually satisfied MFA, how many
   * had a Conditional Access policy evaluated at all, how many avoided legacy
   * protocols, and whether flagged users were subsequently dealt with.
   */
  function identityMetrics(ctx) {
    var o = ctx.data.o365 || {};
    var g = envData(o.graph);
    var d = envData(o.o365);
    if (!g && !d) return null;

    /*
     * A part the direct Microsoft APIs could not read (not licensed, not
     * permitted) is carried as zeros in the data with its key in `unavailable`.
     * Those zeros must not reach a board slide as measurements.
     */
    var missing = function (env, key) {
      var dd = envData(env);
      return !!(dd && Array.isArray(dd.unavailable) && dd.unavailable.some(function (u) {
        return (u && (u.key || u)) === key;
      }));
    };

    var signins = (g && !missing(o.graph, 'signins') && g.signins) || {};
    var risky   = (g && !missing(o.graph, 'riskyUsers') && g.riskyUsers) || {};
    var auditSignins = !!(d && d.signins && !missing(o.o365, 'signins'));
    var legacy  = (signins.legacyAuth && signins.legacyAuth.total) || 0;
    var total   = signins.total || 0;

    // Risk state travels per user on riskyUsers.users[], through both the live
    // and the rollup path — no extra aggregation needed.
    var users   = Array.isArray(risky.users) ? risky.users : [];
    var handled = users.filter(function (u) {
      return RISK_HANDLED_STATES[String(u.state || '').toLowerCase()];
    }).length;

    var ok   = auditSignins ? (d.signins.success || 0) : null;
    var bad  = auditSignins ? (d.signins.failed  || 0) : null;
    var attempts = ok != null && bad != null ? ok + bad : 0;

    var m = {
      modernAuth:  total ? pct(total - legacy, total) : null,
      riskHandled: users.length ? pct(handled, users.length) : null,
      // Share of sign-in attempts that succeeded. A falling rate means
      // credential pressure — spraying, stuffing or a broken auth path.
      signInSuccess: attempts ? pct(ok, attempts) : null,

      legacyAuth:   total ? legacy : null,
      caFailures:   signins.caFailures != null ? signins.caFailures : null,
      riskyUsers:   risky.distinct != null ? risky.distinct : null,
      riskOpen:     users.length ? users.length - handled : null,
      failedLogins: bad,
      // Sources whose failures look like spraying rather than a stuck client.
      sprayIps: auditSignins && d.failedLogins && Array.isArray(d.failedLogins.byIp)
        ? d.failedLogins.byIp.filter(function (r) { return r.spray; }).length
        : null,
      adminOps:     d && d.admin && !missing(o.o365, 'admin')               ? d.admin.total        : null,
      mailboxRules: d && d.mailboxRules && !missing(o.o365, 'mailboxRules') ? d.mailboxRules.total : null,
      dlpEvents:    d && d.dlp && !missing(o.o365, 'dlp')                   ? d.dlp.total          : null,
    };

    // Weighted composite over whichever terms are actually measured.
    var num = 0, den = 0;
    Object.keys(IDENTITY_WEIGHTS).forEach(function (k) {
      if (m[k] == null) return;
      num += m[k] * IDENTITY_WEIGHTS[k];
      den += IDENTITY_WEIGHTS[k];
    });
    m.score     = den ? Math.round((num / den) * 10) / 10 : null;
    m.termsUsed = Object.keys(IDENTITY_WEIGHTS).filter(function (k) { return m[k] != null; });
    m.hasGraph  = !!g && total > 0;
    m.hasAudit  = attempts > 0;

    return m;
  }

  /** Endpoint posture from the Managed EDR tab (/api/edr/summary). */
  function endpointMetrics(ctx) {
    var s = ctx.data.edr;
    if (!s || !s.fleet) return null;
    var f = s.fleet;
    if (!f.total) return null;

    return {
      protected:  f.total,
      agentCurrency: f.coverage != null ? f.coverage : pct(f.upToDate, f.total),
      online:     pct(f.online, f.total),
      stale:      f.stale != null ? f.stale : null,
      infected:   f.infected != null ? f.infected : null,
      windowDays: s.windowDays || null,
    };
  }

  /**
   * Everything the Reports tab renders an input for. Grouped so the form reads
   * as a short attestation checklist rather than a wall of boxes.
   */
  /** One coverage cell. `target` greens the value; `lowerIsBetter` greens zero. */
  function ccItem(label, value, opts) {
    var o = opts || {};
    var tone = '#8C8C8C';
    if (value != null && o.target != null) {
      tone = value >= o.target ? '#2E9E5B' : (value >= o.target - 10 ? '#f39c12' : '#e74c3c');
    } else if (value != null && o.lowerIsBetter) {
      tone = value === 0 ? '#2E9E5B' : (value <= (o.warnAbove || 0) ? '#f39c12' : '#e74c3c');
    } else if (value != null) {
      tone = P.DECK_INK;
    }

    return '<div class="cc-item">' +
        '<div class="cc-v" style="color:' + (value == null ? '#A6A6A6' : tone) + '">' +
          (value == null ? 'No data' : esc(String(value) + (o.unit || ''))) +
        '</div>' +
        '<div class="cc-l">' + esc(label) +
          (o.target != null ? '<span class="cc-t">target ' + o.target + (o.unit || '') + '</span>' : '') +
        '</div>' +
      '</div>';
  }

  /**
   * The identity half of the old Cyber Defence Coverage section, as a standalone
   * `.cc-group`. Returns '' when no identity telemetry is configured.
   *
   * Only what the integration actually emits: every item is omitted rather than
   * shown empty when its source is missing for the tenant.
   */
  function identityCoverageGroup(ctx) {
    var id = identityMetrics(ctx);
    if (!id) return '';

    var items = [];

    {
      if (id.hasGraph) {
        items.push(ccItem('Modern auth coverage', id.modernAuth, { unit: '%', target: 99 }));
        items.push(ccItem('Legacy auth sign-ins', id.legacyAuth, { lowerIsBetter: true }));
      }
      if (id.riskyUsers != null) {
        items.push(ccItem('Users flagged at risk', id.riskyUsers, { lowerIsBetter: true }));
      }
      if (id.riskHandled != null) {
        items.push(ccItem('Risky users handled', id.riskHandled, { unit: '%', target: 90 }));
        items.push(ccItem('Risks still open', id.riskOpen, { lowerIsBetter: true }));
      }
      if (id.hasAudit) {
        items.push(ccItem('Sign-in success rate', id.signInSuccess, { unit: '%', target: 95 }));
        // Not a defect count: some failures are expected in any population.
        items.push(ccItem('Failed sign-ins', id.failedLogins, {}));
      }
      if (id.sprayIps != null) {
        items.push(ccItem('Password-spray sources', id.sprayIps, { lowerIsBetter: true }));
      }
      if (id.caFailures != null) {
        // A policy block is the control working, so this is informational.
        items.push(ccItem('Conditional Access blocks', id.caFailures, {}));
      }
      if (id.adminOps != null)     items.push(ccItem('Admin operations', id.adminOps, {}));
      if (id.mailboxRules != null) items.push(ccItem('Mailbox rule changes', id.mailboxRules, { lowerIsBetter: true, warnAbove: 5 }));
      if (id.dlpEvents != null)    items.push(ccItem('DLP events', id.dlpEvents, { lowerIsBetter: true }));

    }

    if (!items.length) return '';
    return '<div class="cc-group">' +
        '<div class="cc-gh">Managed Identity</div>' +
        '<div class="cc-items">' + items.join('') + '</div>' +
      '</div>';
  }

  /** The endpoint half, as a standalone `.cc-group`. '' when EDR is absent. */
  function endpointCoverageGroup(ctx) {
    // Endpoint coverage is a Managed EDR deliverable.
    if (!serviceInScope(ctx, 'edr')) return '';
    var ep = endpointMetrics(ctx);
    if (!ep) return '';
    return '<div class="cc-group">' +
        '<div class="cc-gh">Endpoints &mdash; Managed EDR</div>' +
        '<div class="cc-items">' +
          ccItem('Endpoints protected', ep.protected, {}) +
          ccItem('Agent currency', ep.agentCurrency, { unit: '%', target: 98 }) +
          ccItem('Agents online', ep.online, { unit: '%', target: 95 }) +
          ccItem('Not reporting', ep.stale, { lowerIsBetter: true }) +
          ccItem('Endpoints with active threats', ep.infected, { lowerIsBetter: true }) +
        '</div>' +
      '</div>';
  }

  /**
   * The honesty footnote for either coverage group: these are observed sign-in
   * and agent outcomes, not directory configuration.
   */
  function coverageNote(ctx) {
    var ep = endpointMetrics(ctx);
    var window = ep && ep.windowDays ? ep.windowDays : null;
    return '<div class="rag-note">' +
        'Drawn from the Managed Identity and Managed EDR telemetry' +
        (window ? ' over a trailing ' + window + '-day window' : '') + '. ' +
        'These are observed outcomes, not directory configuration: MFA enrolment ' +
        'and Conditional Access policy coverage are not carried by either feed and ' +
        'are therefore not reported.' +
      '</div>';
  }

  function renderControlCoverage(ctx) {
    var groups = [identityCoverageGroup(ctx), endpointCoverageGroup(ctx)].filter(Boolean);
    if (!groups.length) return null;
    return '<div class="cc-grid">' + groups.join('') + '</div>' + coverageNote(ctx);
  }

  // ── Threat Landscape ──────────────────────────────────────────────────────

  var THREAT_LABELS = {
    phishing:            'Phishing',
    malware_ransomware:  'Malware / Ransomware',
    data_breach:         'Data Breach',
    insider_threat:      'Insider Threat',
    ddos:                'Denial of Service',
    unauthorized_access: 'Unauthorised Access',
    other:               'Other',
  };

  function renderThreatLandscape(ctx) {
    var incidents = ((ctx.data.vulnFindings || {}).incidents) || [];
    var inPeriod = incidents.filter(function (i) { return monthOf(i.opened_at) === ctx.period; });
    if (!inPeriod.length) return null;

    var counts = {};
    inPeriod.forEach(function (i) {
      var k = i.incident_type || 'other';
      counts[k] = (counts[k] || 0) + 1;
    });

    var rows = Object.keys(counts)
      .map(function (k) { return { type: THREAT_LABELS[k] || titleCase(k), count: counts[k] }; })
      .sort(function (a, b) { return b.count - a.count; });

    var max = rows[0].count;
    var total = inPeriod.length;

    // Severity split gives the "how serious" dimension the raw volume lacks.
    var bySev = {};
    inPeriod.forEach(function (i) {
      var s = titleCase(i.severity || 'medium');
      bySev[s] = (bySev[s] || 0) + 1;
    });

    var bars = '<div class="tl-wrap">' +
        '<div class="tl-bars">' +
          rows.map(function (r) {
            return '<div class="tl-row">' +
                '<div class="tl-name">' + esc(r.type) + '</div>' +
                '<div class="tl-track"><div class="tl-fill" style="width:' +
                  Math.round((r.count / max) * 100) + '%"></div></div>' +
                '<div class="tl-n">' + r.count + '</div>' +
              '</div>';
          }).join('') +
        '</div>' +
        '<div class="tl-side">' +
          '<div class="tl-total">' + total + '</div>' +
          '<div class="tl-total-l">incidents this period</div>' +
          '<div class="tl-sev">' +
            ['Critical', 'High', 'Medium', 'Low'].filter(function (s) { return bySev[s]; })
              .map(function (s) {
                return '<div class="tl-sev-row">' +
                    '<span class="sev-dot" style="background:' + severityTone(s) + '"></span>' +
                    esc(s) + '<span class="tl-sev-n">' + bySev[s] + '</span>' +
                  '</div>';
              }).join('') +
          '</div>' +
        '</div>' +
      '</div>' +
      sectionComment(ctx, 'threatLandscape');

    // The ticket list is the operational evidence behind the bars above. It is
    // a second body rather than an appendix: together they would overflow, and
    // measured pagination makes the split free.
    var tickets = ticketsBlock(ctx);
    if (!tickets) return bars;

    return [bars, subHead('MDR tickets raised during ' + periodName(ctx.period)) + tickets];
  }

  // ── Resolution KPIs ───────────────────────────────────────────────────────

  // ── Resolution SLA: 24/7, measured in elapsed hours ───────────────────────
  //
  // Security operations run continuously, so the clock does too. This used to
  // be measured in BUSINESS hours against an 08:00–17:00 Mon–Fri window, which
  // is the right model for a service desk and the wrong one here: it stopped
  // the clock overnight and all weekend, so a ticket raised Friday evening and
  // closed Monday morning was reported as a couple of hours. The number
  // flattered the service and did not describe what the client experienced.
  //
  // Elapsed hours are what a board means by "resolved in 24 hours", and what a
  // 24/7 service should be held to. The deck reports the durations; it no
  // longer grades them.
  //
  /*
   * THE INCIDENT SLA IS GONE FROM THIS FILE ENTIRELY.
   *
   * IR_SLA_HOURS (Critical 24 h, High 48, Medium 72, Low 96), slaTargetFor(),
   * SLA_TARGET_PCT (95%) and slaTargetLabel() all lived here. They fed two
   * things: the KPI table's "Resolved within SLA" row and the Executive
   * Summary's "Resolution SLA met" tile. Both were removed on request, and
   * with them went every reader of these values.
   *
   * They are deleted rather than left in place, because a table of contracted
   * SLA targets sitting in the report module reads as a policy the deck
   * enforces — dead code is at its most expensive when it looks like a rule,
   * and the next person to find it would reasonably assume a client is being
   * graded against it somewhere.
   *
   * What remains is elapsedHoursBetween(), which measures duration and makes
   * no claim about whether a duration was acceptable. The KPI table still
   * reports mean and median time to resolve from it.
   *
   * If incident SLA reporting comes back, it starts here, and one definition
   * serves every place that states it — that was the point of the original
   * table and is worth keeping if it is ever rebuilt.
   */

  /**
   * Wall-clock hours between two timestamps.
   *
   * Returns null when either stamp is missing or unparseable, or when the end
   * precedes the start. Empties are rejected explicitly because new Date(null)
   * is the 1970 epoch rather than an invalid date, so a ticket missing a
   * timestamp would otherwise be measured from 1970 and report half a million
   * hours — which is how a single bad row can wreck an average.
   */
  /*
   * DELEGATES — it does not have its own arithmetic any more.
   *
   * The cohort timings moved into mdr-metrics.js so the server could compute
   * the MDR score from the same rule. For a moment that left two
   * implementations of "elapsed hours between two timestamps" in the product,
   * which is how a business-hours model got back in once already. This keeps
   * the export other callers and the test suite use, over one implementation.
   */
  function elapsedHoursBetween(startTs, endTs) {
    return MM.elapsedHours(startTs, endTs);
  }


  function irKpiBlock(ctx) {
    // Resolution KPIs describe MDR delivery. Without MDR there is nothing to
    // report, and an empty KPI table reads as a failed service.
    if (!componentInScope(ctx, 'incidentResponse')) return null;
    var tickets = ((ctx.data.mdr || {}).tickets) || [];
    var period  = ctx.period;

    /*
     * ONE COHORT: the tickets RAISED in the reporting month, followed through
     * to whenever they were resolved.
     *
     * This block used to count tickets raised in the month against tickets
     * RESOLVED in the month — two different populations, since a ticket
     * resolved in August may have been raised in June. Every figure below was
     * drawn from whichever of the two happened to suit it: the timings came
     * from the resolved-in-month set, so a June ticket closed in August put
     * June's duration into August's mean.
     *
     * The rule now lives in one place, shared with the server so the Managed
     * Detection and Response score in the maturity table above and these KPIs
     * describe the same tickets. They did not before.
     */
    var stat = MM.cohortStats(tickets, period);

    /*
     * Rendered whenever the period had ANY ticket activity, not only when it
     * had incidents.
     *
     * Returning null on `!stat.raised` would hide the one failure this filter
     * can produce: if a feed labels its incidents something other than
     * 'incident', every cohort empties and the section simply disappears from
     * the deck. A table reading "0 incidents raised, 6 tickets excluded as not
     * typed incident" is how that becomes visible instead.
     */
    if (!stat.raised && !stat.excluded) return null;

    var mttr   = stat.meanHours;
    var median = stat.medianHours;

    function hrs(v) {
      if (v == null) return '—';
      return v < 1 ? Math.round(v * 60) + ' min' : (Math.round(v * 10) / 10) + ' hrs';
    }

    /*
     * RESOLUTION ONLY.
     *
     * This table used to lead with "Mean time to respond (MTTR)" and "Median
     * time to respond" — both of which were measuring creation to RESOLUTION.
     * Nothing here has ever measured time to respond: the ticket feed carries
     * no acknowledgement stamp, so a response time cannot be computed at all.
     * The labels were describing a metric the data cannot produce, sitting
     * directly above a row about resolution, which is what made the block
     * unreadable.
     *
     * "Mean time to mitigate (EDR)" is gone for the same reason plus a worse
     * one: it came from a different platform on a different clock, so a reader
     * comparing it with the rows around it was comparing nothing.
     *
     * What the client contracted for is resolution inside a window, so that is
     * what the table reports.
     *
     * NO SLA ROW, AND NO TARGET COLUMN.
     *
     * "Resolved within SLA" was removed from this table on request. The Target
     * column went with it rather than being left behind: every remaining row
     * is a measurement with no contracted target, so the column held nothing
     * but em-dashes — and a column headed "Target" with no targets in it reads
     * on a board pack as a set of commitments nobody met.
     *
     * The "Not graded (severity unrecognised)" row is gone for the same
     * reason. It existed only to stop a partial SLA figure being read as a
     * complete one; with no SLA figure it qualifies nothing.
     */
    /*
     * The row label names what was actually counted. With the incident filter
     * applied these are incidents; on a feed carrying no ticket types it could
     * not be applied, and calling a support request an incident on a client's
     * board pack would be the lie the degrade-open guard exists to avoid.
     */
    var noun = stat.typeFiltered ? 'Incidents' : 'Tickets';

    var rows = [
      { kpi: 'Mean time to resolve',   actual: hrs(mttr),   ok: null },
      { kpi: 'Median time to resolve', actual: hrs(median), ok: null },
      { kpi: noun + ' raised this period', actual: String(stat.raised),   ok: null },
      { kpi: 'Of those, resolved',         actual: String(stat.resolved), ok: null },
    ];

    /*
     * THE RATE IS BACK, AND IT IS NOW ACTUALLY A RATE.
     *
     * It was removed because it divided tickets RESOLVED in the month by
     * tickets RAISED in the month — two different cohorts, so clearing a
     * backlog produced 125%, which a board reads either as an error or as a
     * boast. Neither was what happened.
     *
     * Within one cohort the numerator is a subset of the denominator, so it
     * cannot exceed 100% by construction. The row label says "of those" for
     * the same reason: the reader should be able to see the denominator
     * without being told what it is.
     */
    if (stat.resolutionRate !== null) {
      rows.push({ kpi: 'Resolution rate', actual: stat.resolutionRate + '%',
                  ok: null });
    }

    /*
     * What is left, rather than a "backlog change" comparing two cohorts.
     * Shown only when there is something open: a row reading "Still open 0" is
     * worth stating, but not at the cost of a row on every clean month, and
     * the rate above already says 100%.
     */
    if (stat.stillOpen > 0) {
      rows.push({ kpi: 'Still open', actual: String(stat.stillOpen), ok: false });
    }

    return D.dataTable({
      cols: [
        { label: 'KPI',    key: 'kpi',    width: '58%' },
        { label: 'Actual', key: 'actual', width: '42%', cls: 'num',
          raw: function (r) {
            if (r.ok === null) return esc(r.actual);
            return '<span class="' + (r.ok ? 'rag-yes' : 'rag-no') + '">' + esc(r.actual) + '</span>';
          } },
      ],
      rows: rows,
    }) +
    /*
     * THE AS-AT DATE IS NOT OPTIONAL.
     *
     * Following a cohort past its own month end is what makes these figures
     * fair — a ticket raised on the 30th and closed on the 2nd was resolved,
     * and freezing the count at month end would report it as a miss. The price
     * is that the figure can improve if the report is re-run later.
     *
     * Printing the date is what makes that reproducible: not that the number
     * never moves, but that it says what it was true of. A reader comparing two
     * copies of the August report can see why they differ.
     */
    '<div class="rag-note">Every figure above describes the <strong>' +
      esc(String(stat.raised)) + ' incident' + (stat.raised === 1 ? '' : 's') +
      ' raised in this period</strong>, followed through to resolution — so ' +
      'the resolution rate cannot exceed 100%, and an incident raised in an ' +
      'earlier month is not counted here even if it closed during it. ' +
      exclusionSentence(stat) +
      'Resolution status is as at <strong>' + esc(asAtLabel()) + '</strong>; ' +
      'incidents raised late in the period may since have closed. ' +
      'Security operations run <strong>24/7</strong>, so resolution time is ' +
      'measured in elapsed hours from creation to resolution — nights, ' +
      'weekends and public holidays included.</div>';
  }

  /**
   * What the incident filter removed, named by type.
   *
   * A support request answered in a week is not a slow incident response, so
   * only tickets typed 'incident' are measured. Saying which tickets were set
   * aside — and how many — keeps the denominator checkable against the ticket
   * list, and makes a mislabelled feed obvious: if every ticket is excluded
   * under one unexpected type, that reads as a filter to fix rather than as a
   * month with no incidents.
   */
  function exclusionSentence(stat) {
    if (!stat.typeFiltered) {
      // The feed carries no ticket types at all, so the filter could not be
      // applied. Claiming these are incidents would be the lie.
      return 'This feed does not classify tickets by type, so <strong>all ' +
             'tickets are counted</strong> rather than incidents alone. ';
    }
    if (!stat.excluded) return '';

    var kinds = Object.keys(stat.excludedTypes).sort(function (a, b) {
      return stat.excludedTypes[b] - stat.excludedTypes[a];
    }).map(function (k) { return stat.excludedTypes[k] + ' ' + k; });

    return esc(String(stat.excluded)) + ' further ticket' +
      (stat.excluded === 1 ? ' was' : 's were') + ' raised and are not counted ' +
      'here, being support and administrative work rather than incidents (' +
      esc(kinds.join(', ')) + '). ';
  }

  /** Today, for the as-at line on any figure that follows a cohort forward. */
  function asAtLabel() {
    var d = new Date();
    return d.toLocaleDateString('en-ZA',
      { day: 'numeric', month: 'long', year: 'numeric' });
  }

  // ── Security Maturity Trend ───────────────────────────────────────────────

  function maturityBlock(ctx) {
    var now  = componentScores(ctx);
    var prev = previousScores(ctx);
    if (now.overall == null) return null;

    var prevLabel = periodName(shiftPeriod(ctx.period, -1));
    var thisLabel = periodName(ctx.period);

    /*
     * Only domains the client actually buys. A row reading
     * "Vulnerability Management — 0/100, target 80, gap −80" for a client
     * without vulnerability management is not a finding, it is an invoice
     * question, and it dominates the slide it appears on.
     *
     * The Secure Score row is dropped when the mix is scoped: it carries the
     * composite, which counts the very controls this table has just stopped
     * showing, so leaving it would reintroduce the number by the back door.
     * The scoped score and its coverage have their own section.
     */
    var scoped = scopeRecorded(ctx);

    /*
     * The vulnerability row appears only for a client who buys Vulnerability
     * Management — componentInScope() below now resolves to exactly that.
     *
     * It briefly carried a second label, "Endpoint Patch Currency", for the
     * case where the engine scores an endpoint-only estate on patch currency
     * instead of a scan. That measure is real but it is not a deliverable of
     * any contracted service, so it does not belong in a client report at all;
     * the row is dropped rather than renamed.
     */
    /*
     * `how` is the measurement basis, in one sentence a board can read without
     * asking a follow-up question. A maturity table that prints 70 against a
     * target of 90 and says nothing about where 70 came from invites exactly
     * one question, and the answer should not depend on who is in the room.
     *
     * Each sentence describes what lib/secure-score.js actually computes. If a
     * scoring function changes, this text is wrong and must change with it —
     * tests/report-sla-services.test.js pins the arithmetic named here.
     */
    var domains = [
      { label: 'Vulnerability Management', key: 'vulnerabilities',  target: MATURITY_TARGETS.vulnerabilities,
        how: 'weighted finding density per asset scanned (critical findings ' +
             'count ten times a low one), capped by open criticals and by how ' +
             'much of the external estate the scan actually reached' },
      { label: 'Security Awareness',       key: 'awareness',        target: MATURITY_TARGETS.awareness,
        how: 'the share of assigned training that has been completed' },
      { label: 'Managed Detection and Response', key: 'incidentResponse', target: MATURITY_TARGETS.incidentResponse,
        how: 'the share of the tickets raised in the month that have been ' +
             'resolved, less up to 20 points where average resolution time ' +
             'runs beyond 24 hours' },
      { label: 'Secure Score',             key: 'overall',          target: MATURITY_TARGETS.overall,
        how: 'the domains above combined at the weights set by the services ' +
             'in scope' },
    ].filter(function (d) {
      if (d.key === 'overall') return !scoped;
      return componentInScope(ctx, d.key);
    });

    if (!domains.length) return null;

    var measured = now.measured || {};
    var rows = domains.map(function (d) {
      var cur = now[d.key], was = prev[d.key];
      var t = trendFor(cur, was);
      return {
        domain: d.label, key: d.key, prev: was, cur: cur, target: d.target, trend: t,
        how: d.how,
        gap: cur == null ? null : cur - d.target,
        measured: measured[d.key] !== false,
      };
    });
    var unmeasured = rows.filter(function (r) { return !r.measured; });

    // "No data has been supplied" is true but incomplete for a client who runs
    // their own awareness programme: the control exists, we have simply not been
    // shown it. A board reading the unqualified sentence would conclude their
    // people are untrained. (This used to add "and the weighting already
    // reflects that" — it no longer does, and the sentence below says so.)
    var w = (ctx.data.secureScore || {}).weights || {};
    var ownProgramme = !!(w.awarenessProgram === 'internal' &&
      rows.some(function (r) { return r.key === 'awareness' && !r.measured; }));

    return D.dataTable({
      cols: [
        { label: 'Domain', key: 'domain', width: '32%',
          raw: function (r) {
            return esc(r.domain) +
              (r.measured ? '' : ' <span class="rag-pill nd">No data</span>');
          } },
        { label: prevLabel || 'Previous', key: 'prev', width: '13%', cls: 'num',
          raw: function (r) { return r.prev == null ? '—' : String(r.prev); } },
        { label: thisLabel || 'Current', key: 'cur', width: '13%', cls: 'num',
          raw: function (r) { return r.cur == null ? '—' : '<b>' + r.cur + '</b>'; } },
        { label: 'Target', key: 'target', width: '12%', cls: 'num' },
        { label: 'Gap', key: 'gap', width: '12%', cls: 'num',
          raw: function (r) {
            if (r.gap == null) return '—';
            return r.gap >= 0
              ? '<span class="rag-yes">+' + r.gap + '</span>'
              : '<span class="rag-no">' + r.gap + '</span>';
          } },
        { label: 'Trend', key: 'trend', width: '18%',
          raw: function (r) {
            return '<span style="color:' + (r.trend.tone || '#8C8C8C') + '">' + esc(r.trend.mark) +
                   '</span> ' + esc(r.trend.label);
          } },
      ],
      rows: rows,
    }) +
    /*
     * How each score was arrived at, listed under the table it explains.
     *
     * Built from the rows actually shown, so a client never reads the
     * methodology for a domain that is not in their table — which would be a
     * description of a service they do not buy.
     */
    '<div class="rag-note"><strong>How each domain is measured.</strong> ' +
      rows.map(function (r) {
        return esc(r.domain) + ': ' + esc(r.how) + '.';
      }).join(' ') +
      // "All four" would be wrong the moment a client buys fewer services, and
      // the row list is already filtered by what they buy.
      ' Each is scored out of 100.</div>' +
    '<div class="rag-note">Gap is the distance from the agreed target score. ' +
      'A positive gap means the domain is at or above target.' +
      // Naming this is not optional on a client-facing page: a zero from an
      // absent upload and a zero from a bad result look identical in a table.
      (unmeasured.length
        ? ' <strong>' + unmeasured.map(function (r) { return esc(r.domain); }).join(' and ') +
          ' scored zero because no data has been supplied for ' +
          (unmeasured.length > 1 ? 'those domains' : 'that domain') +
          ', not because of an adverse result.</strong> An unmeasured control is ' +
          'treated as unmanaged rather than excluded, so the overall score reflects ' +
          'the gap in visibility.'
        : '') +
      (ownProgramme
        ? ' Security awareness training is run internally rather than through this ' +
          'platform, and no completion figures have been recorded. That component ' +
          'therefore scores zero for want of evidence rather than for want of a ' +
          'programme — recording the completion figures would have it scored on ' +
          'its own merits.'
        : '') +
      (prev.source === 'reconstructed'
        ? ' Prior-month figures are reconstructed from dated scan, training and ' +
          'ticket records rather than a stored measurement, so they reflect the ' +
          'data held today.'
        : '') +
    '</div>';
  }

  // ── Board Assurance Statement ─────────────────────────────────────────────

  /**
   * Draft the CISO assurance paragraph from the data. Editable before generation,
   * exactly like the Observations narrative — the wording is a starting point,
   * not an automated attestation.
   */
  function draftAssurance(ctx) {
    var now       = componentScores(ctx);
    var prev      = previousScores(ctx);
    var client    = ctx.clientName || 'the organisation';
    var label     = ctx.periodLabel || 'the reporting period';
    var breaches  = tileNum(ctx, 'confirmedBreaches');
    var material  = tileNum(ctx, 'materialIncidents');

    var parts = [];

    parts.push('Based on security monitoring, vulnerability assessment, MDR operations and ' +
      'awareness programme metrics, ' +
      (breaches === 0 || breaches == null
        ? 'there is no evidence of material compromise at ' + client + ' during ' + label + '.'
        : 'there ' + (breaches === 1 ? 'was 1 confirmed breach' : 'were ' + breaches + ' confirmed breaches') +
          ' at ' + client + ' during ' + label + '.'));

    if (material != null && material > 0) {
      parts.push(material + ' incident' + (material === 1 ? '' : 's') +
        ' met the materiality threshold and ' + (material === 1 ? 'was' : 'were') +
        ' escalated to executive management.');
    }

    var belowTarget = [];
    if (now.vulnerabilities != null && now.vulnerabilities < MATURITY_TARGETS.vulnerabilities) belowTarget.push('vulnerability management');
    if (now.awareness != null && now.awareness < MATURITY_TARGETS.awareness) belowTarget.push('security awareness');
    if (now.incidentResponse != null && now.incidentResponse < MATURITY_TARGETS.incidentResponse) belowTarget.push('incident response');

    if (belowTarget.length) {
      parts.push('Cyber risk remains elevated in ' + listPhrase(belowTarget) +
        '; compensating controls remain in effect and remediation is underway.');
    }

    if (now.overall != null) {
      var t = trendFor(now.overall, prev.overall);
      var dir = t.label === 'Improving' ? 'improving'
              : t.label === 'Increasing' ? 'deteriorating' : 'stable';
      parts.push('Overall risk posture is ' + dir + ' at ' + now.overall + ' out of 100 and ' +
        (now.overall >= MATURITY_TARGETS.overall
          ? 'is within the target threshold of ' + MATURITY_TARGETS.overall + '.'
          : 'remains below the target threshold of ' + MATURITY_TARGETS.overall + '.'));
    }

    return parts.join(' ');
  }

  /**
   * Draft the Executive Summary prose. Editable before generation, exactly like
   * the Observations narrative and the assurance statement — a starting point,
   * not an automated attestation.
   *
   * Paragraphs are separated by blank lines; renderExecSummary splits on those.
   */
  function draftExecSummary(ctx) {
    var client = ctx.clientName || 'the organisation';
    var label  = ctx.periodLabel || 'the reporting period';
    var now    = componentScores(ctx);
    var prev   = previousScores(ctx);
    var paras  = [];

    /*
     * 1. Where the posture stands and which way it is moving.
     *
     * THE SAME NUMBER THE TILE SHOWS. This paragraph used to report
     * `now.overall` — the composite — while the tile directly above it printed
     * headlineScore(), which is the in-scope score for any client with a
     * recorded service mix. An awareness-only client read "Secure Score
     * 60/100 · services in scope" and, immediately beneath, "the overall
     * security posture stands at 37 out of 100". An MDR-only client got 0
     * against 22. Neither figure was wrong; printing both without saying which
     * was which is what made the slide indefensible in the room.
     *
     * headlineScore() is the single copy of the rule and this asks it, exactly
     * as renderExecSummary does.
     */
    var head     = headlineScore(ctx.data.secureScore || {});
    var headline = head.score != null ? head.score : now.overall;

    if (headline != null) {
      /*
       * The trend compares against stored history, which holds COMPOSITES. For
       * a scoped client the headline is a different measure, so the movement
       * clause is dropped rather than comparing two unlike numbers and calling
       * the difference progress. Same decision the renderer makes when it
       * suppresses the trend arrow on a scoped tile.
       */
      var t = head.scoped ? { label: null } : trendFor(now.overall, prev.overall);
      var dir = t.label === 'Improving' ? 'improved'
              : t.label === 'Increasing' ? 'declined' : 'held steady';

      paras.push(
        (head.scoped
          ? 'The security posture for ' + client + ' across the services in scope stands at ' +
            headline + ' out of 100 for ' + label + '. '
          : 'The overall security posture for ' + client + ' stands at ' + headline +
            ' out of 100 for ' + label + ', having ' + dir +
            (prev.overall != null ? ' from ' + prev.overall + ' the previous month' : '') + '. ') +
        (headline >= MATURITY_TARGETS.overall
          ? 'This is at or above the agreed target of ' + MATURITY_TARGETS.overall + '.'
          : 'The agreed target is ' + MATURITY_TARGETS.overall + '.'));
    }

    // 2. What actually happened to the business. Both feeds, via the helper the
    //    tile uses — counting only the logged incidents told a client with a
    //    month of MDR activity that nothing had happened.
    var inc = incidentCount(ctx);
    var material = (((ctx.data.vulnFindings || {}).incidents) || []).filter(function (i) {
      if (monthOf(i.opened_at) !== ctx.period) return false;
      var s = String(i.severity || '').toLowerCase();
      return s === 'critical' || s === 'high';
    }).length;

    if (inc.total) {
      paras.push(inc.total + ' security incident' + (inc.total === 1 ? ' was' : 's were') +
        ' recorded during the period' +
        (inc.mdr && inc.ir ? ' (' + inc.mdr + ' raised by MDR, ' + inc.ir + ' logged)' : '') +
        ', of which ' + material +
        (material === 1 ? ' was' : ' were') + ' of critical or high severity. ' +
        (material ? 'Each was investigated and worked to closure.'
                  : 'None met the threshold for material business impact.'));
    } else {
      paras.push('No security incidents were recorded for ' + client + ' during ' + label + '.');
    }

    /*
     * 3. The dominant exposure, named rather than implied.
     *
     * TWO THINGS THIS MUST NOT CALL AN EXPOSURE.
     *
     *   a control the client does not buy   Its component scores 0 because
     *                                       nobody was engaged to manage it.
     *                                       Naming it as "the principal
     *                                       exposure" on their board pack is a
     *                                       statement about our order book
     *                                       dressed up as a finding about them.
     *
     *   a control with no evidence behind   measured === false means unmeasured,
     *                                       and unmeasured is not zero. The gap
     *                                       is in our data, and it is reported
     *                                       as such elsewhere; asserting the
     *                                       control is weak is a claim we cannot
     *                                       support if asked.
     *
     * Both gates default to permissive when no service mix is recorded, so a
     * client nobody has configured reads exactly what they read before.
     */
    var behind = [];
    function trailing(key, phrase) {
      if (now[key] == null) return;                       // never scored
      if (!now.measured[key]) return;                     // unmeasured is not zero
      if (!componentInScope(ctx, key)) return;            // not bought, not theirs
      if (now[key] < MATURITY_TARGETS[key]) behind.push(phrase);
    }
    trailing('vulnerabilities',  'vulnerability management');
    trailing('awareness',        'security awareness');
    trailing('incidentResponse', 'incident response');

    /*
     * The risk register is a vISO deliverable, and "requires a funded decision
     * from the board" is vISO language. Gated exactly as the tile above it is,
     * so the prose and the tiles make the same claim about what we were engaged
     * to do. Ungated for a client with no recorded mix, like every other gate
     * here.
     */
    var visoScoped = serviceInScope(ctx, 'viso');
    var above = visoScoped
      ? ((ctx.data.vulnFindings || {}).risks || []).filter(function (r) {
          return r.stage !== 'closed' && Number(r.risk_score) >= RISK_APPETITE_SCORE;
        }).length
      : 0;

    if (behind.length || above) {
      paras.push(
        (behind.length
          ? 'The principal exposure remains ' + listPhrase(behind) + ', which ' +
            (behind.length === 1 ? 'sits' : 'sit') + ' below target. '
          : '') +
        // The all-clear is itself a claim, and only ours to make where we hold
        // the register. Silence beats asserting a clean appetite position for a
        // client whose risks we were never engaged to track.
        (!visoScoped ? ''
          : above
            ? above + ' open risk' + (above === 1 ? '' : 's') + ' currently sit' +
              (above === 1 ? 's' : '') + ' above the agreed appetite and require a funded ' +
              'decision from the board.'
            : 'No open risk currently sits above the agreed appetite.'));
    }

    return paras.join('\n\n');
  }

  function listPhrase(items) {
    if (items.length === 1) return items[0];
    return items.slice(0, -1).join(', ') + ' and ' + items[items.length - 1];
  }

  function renderAssurance(ctx) {
    var text = (ctx.assurance || '').trim();
    if (!text) return null;

    var author = ctx.author || '';
    return '<div class="as-wrap">' +
        '<div class="as-quote">' + esc(text) + '</div>' +
        '<div class="as-sign">' +
          '<div class="as-rule"></div>' +
          (author ? '<div class="as-by">' + esc(author) + '</div>' : '') +
          '<div class="as-role">On behalf of the Managed Security Service</div>' +
          '<div class="as-date">' + esc(ctx.periodLabel || '') + '</div>' +
        '</div>' +
      '</div>';
  }

  // ── Recommendations ───────────────────────────────────────────────────────
  // Straight from /api/secure-score — the same list the Secure Score tab shows.
  // Nothing is authored here; generateRecommendations() in lib/secure-score.js
  // remains the single place that decides what to advise.

  var MAX_RECOMMENDATIONS = 5;

  var PRIORITY_TONES = {
    high:   '#e74c3c',
    medium: '#f39c12',
    low:    '#2E9E5B',
    info:   '#1077C7',
  };

  function recommendationsBlock(ctx) {
    var recs = (ctx.data.secureScore || {}).recommendations;
    if (!Array.isArray(recs) || !recs.length) return null;

    // Most urgent first, so a truncated list never drops the important items.
    var RANK = { high: 0, medium: 1, low: 2, info: 3 };
    var sorted = recs.slice().sort(function (a, b) {
      var ra = RANK[a.priority] === undefined ? 9 : RANK[a.priority];
      var rb = RANK[b.priority] === undefined ? 9 : RANK[b.priority];
      return ra - rb;
    });

    return '<div class="rec-list">' +
      sorted.slice(0, MAX_RECOMMENDATIONS).map(function (r) {
        var tone = PRIORITY_TONES[r.priority] || '#BFBFBF';
        return '<div class="rec-item" style="border-left-color:' + tone + '">' +
            '<div class="rec-body">' +
              '<div class="rec-area">' + esc(r.area || 'General') + '</div>' +
              '<div class="rec-text">' + esc(truncate(r.suggestion, 190)) + '</div>' +
            '</div>' +
            '<div class="rec-meta">' +
              '<span class="rec-chip" style="background:' + tone + '">' +
                esc(r.priority || 'info') +
              '</span>' +
              (r.impact ? '<span class="rec-impact">' + esc(r.impact) + ' impact</span>' : '') +
            '</div>' +
          '</div>';
      }).join('') +
    '</div>';
  }

  // ── Slide 4: Observations ─────────────────────────────────────────────────

  /**
   * Draft the Observations narrative from the data. Returns newline-separated
   * bullet lines; the Reports tab shows this in an editable textarea first.
   */
  function draftObservations(ctx) {
    var lines   = [];
    var client  = ctx.clientName || 'The client';
    var label   = ctx.periodLabel || 'the reporting period';
    var mdr     = ctx.data.mdr || {};
    var tickets = mdr.tickets || [];

    var sev = { HIGH: 0, MEDIUM: 0, LOW: 0 };
    tickets.forEach(function (t) {
      var k = String(t.severity || '').toUpperCase();
      if (sev[k] !== undefined) sev[k]++;
    });
    var closed = tickets.filter(function (t) { return t.status === 'closed'; }).length;

    if (tickets.length) {
      lines.push(sev.HIGH === 0
        ? client + '’s security posture has been good with no high severity incidents being observed during the ' + label + ' reporting period.'
        : client + '’s environment saw ' + sev.HIGH + ' high severity incident' +
          (sev.HIGH === 1
            ? ' during the ' + label + ' reporting period, which was investigated and escalated.'
            : 's during the ' + label + ' reporting period, each of which was investigated and escalated.'));
      lines.push('A total of ' + tickets.length + ' incident' + (tickets.length === 1 ? '' : 's') +
                 ' were raised' + (closed ? ' and ' + closed + ' resolved' : '') + '.');
      lines.push('Severity breakdown: ' + sev.HIGH + ' High, ' + sev.MEDIUM + ' Medium, and ' + sev.LOW + ' Low.');
    } else {
      lines.push('No MDR incidents were raised for ' + client + ' during the ' + label + ' reporting period.');
    }

    var a = ctx.data.awareness;
    if (a && (a.sessions || []).length) {
      // All-time, so the figure reflects the whole training programme rather than
      // whichever three campaigns happen to be the most recent.
      var t = allTimeTotals(a.sessions, 'Awareness Session');
      if (t.assigned) {
        lines.push('Security awareness completion stands at ' + t.completionPct +
          '% across ' + t.campaigns + ' session' + (t.campaigns === 1 ? '' : 's') + ' to date' +
          (t.completionPct < 70 ? ', which remains below the 70% target — manager follow-up is recommended.' : '.'));
      }
    }

    var vs = vulnSummaryFor(ctx);
    if (vs) {
      var crit = (vs.critical || 0) + (vs.high || 0);
      lines.push(crit > 0
        ? crit + ' critical or high severity vulnerabilities remain open and are tracked in the remediation plan.'
        : 'No critical or high severity vulnerabilities are currently outstanding.');
    }

    return lines.join('\n');
  }

  function observationBullets(ctx) {
    var text = (ctx.narrative || '').trim();
    if (!text) return null;
    var items = text.split(/\n+/)
      .map(function (l) { return l.replace(/^\s*[•\-\*]\s*/, '').trim(); })
      .filter(Boolean);
    if (!items.length) return null;
    return '<ul class="bl">' +
      items.map(function (l) { return '<li>' + esc(l) + '</li>'; }).join('') +
      '</ul>';
  }

  // ── Slide 5: Tickets Activity ─────────────────────────────────────────────

  function ticketsBlock(ctx) {
    var mdr = ctx.data.mdr || {};
    var tickets = (mdr.tickets || []).slice();
    if (!tickets.length) return null;

    // Most recently opened first, matching the reference deck.
    tickets.sort(function (a, b) {
      return new Date(b.createdAt || 0) - new Date(a.createdAt || 0);
    });

    var rows = tickets.slice(0, MAX_TICKET_ROWS).map(function (t) {
      var sev = String(t.severity || '').toUpperCase();
      var subject = String(t.subject || '');
      return {
        id:      t.ticketNumber,
        status:  t.status,
        desc:    (sev ? '[' + sev + '] ' : '') + truncate(subject, MAX_DESC_CHARS),
        opened:  fmtDateTime(t.createdAt),
        updated: fmtDateTime(t.updatedAt),
      };
    });

    return '<div class="tk-wrap">' + D.dataTable({
      cols: [
        { label: 'Ticket ID',    key: 'id',      width: '12%', cls: 'tk-id'   },
        { label: 'Status',       key: 'status',  width: '11%'                 },
        { label: 'Description',  key: 'desc',    width: '39%', cls: 'tk-desc' },
        { label: 'Opened',       key: 'opened',  width: '19%', cls: 'tk-when' },
        { label: 'Last Updated', key: 'updated', width: '19%', cls: 'tk-when' },
      ],
      rows: rows,
    }) + '</div>';
  }

  // ── Slide 6: Vulnerabilities ──────────────────────────────────────────────
  // No reference slide for this one — designed in the same visual language.

  var SEV_TONES = {
    Critical: '#8B1A2B',
    High:     '#D93025',
    Medium:   '#E08A1E',
    Low:      '#2E9E5B',
  };

  function topFindingsBlock(ctx) {
    var summary  = vulnSummaryFor(ctx);
    var tracker  = ctx.data.vulnFindings || {};
    var findings = (tracker.vulns || []).filter(function (f) {
      return f.status === 'open' || f.status === 'in-progress';
    });

    if (!summary && !findings.length) return null;

    var html = '';

    if (summary) {
      html += '<div class="sev-row">' +
        ['Critical', 'High', 'Medium', 'Low'].map(function (label) {
          var n = summary[label.toLowerCase()] || 0;
          return '<div class="sev-card">' +
              '<div class="sev-n" style="color:' + SEV_TONES[label] + '">' + n + '</div>' +
              '<div class="sev-l">' + label + '</div>' +
            '</div>';
        }).join('') +
      '</div>';
    }

    var RANK = { Critical: 0, High: 1, Medium: 2, Low: 3 };
    findings.sort(function (a, b) {
      var ra = RANK[a.risk] === undefined ? 9 : RANK[a.risk];
      var rb = RANK[b.risk] === undefined ? 9 : RANK[b.risk];
      return ra - rb;
    });

    html += D.dataTable({
      caption: 'Top Outstanding Findings' + (tracker.vulnMonthKey ? ' — ' + tracker.vulnMonthKey : ''),
      cols: [
        { label: 'Risk',   key: 'risk',   width: '11%' },
        { label: 'Finding', key: 'name',  width: '42%',
          raw: function (r) { return esc(truncate(r.name, 90)); } },
        { label: 'Host',   key: 'host',   width: '20%' },
        { label: 'CVE',    key: 'cve',    width: '15%',
          raw: function (r) { return esc(truncate(r.cve || '—', 22)); } },
        { label: 'Status', key: 'status', width: '12%' },
      ],
      rows: findings.slice(0, MAX_VULN_ROWS),
    });

    return html;
  }

  // ── Registry ──────────────────────────────────────────────────────────────


  // ── Thin wrappers over the extracted blocks ──────────────────────────────
  // The blocks above are composed directly by the folded sections; these keep
  // the one-block-per-section shape the registry still expects.

  // ══════════════════════════════════════════════════════════════════════════
  // GRC self-assessment
  //
  // Scores come from lib/grc-score.js via /api/grc/assessment — the deck never
  // does the weight maths itself, so a domain score here always matches the
  // same domain on the GRC tab.
  // ══════════════════════════════════════════════════════════════════════════

  var GRC_ANSWER_TONES  = { yes: '#2E9E5B', partial: '#f39c12', no: '#e74c3c', na: '#8C8C8C' };
  var GRC_ANSWER_LABELS = { yes: 'Yes', partial: 'Partial', no: 'No', na: 'N/A' };

  // Controls looked up by ITR id — stable, spreadsheet-sourced identifiers.
  var THIRD_PARTY_ITR = ['ITR-041', 'ITR-042', 'ITR-024'];
  var RESILIENCE_ITR  = ['ITR-038', 'ITR-039', 'ITR-040'];

  // Domains looked up by name. This is a documented coupling: renaming a
  // grc_questions.section value makes these read "Not assessed" rather than
  // throwing, so prefer ITR ids wherever both would work.
  var GRC_IDENTITY_SECTIONS   = ['Identity & Access', 'Privileged Access'];
  var GRC_PEOPLE_SECTION      = 'People & Awareness';
  var GRC_RESILIENCE_SECTIONS = ['Backup & Recovery', 'Business Continuity'];
  var GRC_THIRD_PARTY_SECTION = 'Third Party & Supply Chain';

  // ── Vendor inventory helpers ───────────────────────────────────────────────
  // inherent_score and residual_score are computed by lib/vendor-score.js on
  // every write, so the deck only reads them. Nothing here re-derives a score.

  /** Assurance values counting as independent evidence. Matches server.js. */
  var VENDOR_EVIDENCE = ['soc2', 'iso27001', 'both'];

  var VENDOR_ASSURANCE_LABEL = {
    both: 'SOC 2 + ISO', soc2: 'SOC 2', iso27001: 'ISO 27001',
    questionnaire: 'Questionnaire', none: 'None',
  };
  var VENDOR_TIER_LABEL = {
    critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low',
  };

  /** YYYY-MM-DD for a DATE string, an ISO timestamp or a Date. */
  function dayKey(value) {
    if (!value) return null;
    var s = String(value);
    if (/^\d{4}-\d{2}-\d{2}/.test(s)) return s.slice(0, 10);
    var d = new Date(value);
    return isNaN(d.getTime()) ? null : d.toISOString().slice(0, 10);
  }

  /**
   * Vendors still under management. 'terminated' relationships are history,
   * not exposure, so they never reach a board figure.
   */
  function vendorList(ctx) {
    var v = ctx.data.vendors;
    var rows = (v && v.vendors) || [];
    return rows.filter(function (r) { return r && r.status !== 'terminated'; });
  }

  /**
   * Last day of the reporting period, as YYYY-MM-DD.
   *
   * Review dates and certificate expiries are judged against the period end,
   * not against today, so re-printing March's report next year still shows
   * what was overdue in March. ctx.period is 'YYYY-MM'.
   */
  function vendorAsOf(ctx) {
    var m = /^(\d{4})-(\d{2})$/.exec(String(ctx.period || ''));
    if (!m) return dayKey(new Date());
    // Day 0 of the following month is the last day of this one.
    return dayKey(new Date(Date.UTC(+m[1], +m[2], 0)));
  }

  /**
   * Has the recorded assurance passed its expiry date?
   *
   * Distinct from vendorHasEvidence: a completed questionnaire never counts as
   * independent evidence, but that does not make it *expired*. Conflating the
   * two labels a current questionnaire "(expired)", which is simply untrue.
   */
  function vendorAssuranceExpired(v, asOf) {
    if (v.assurance === 'none') return false;
    var exp = dayKey(v.assurance_expires);
    return !!exp && exp < asOf;
  }

  /** Independent, unexpired third-party evidence on file. */
  function vendorHasEvidence(v, asOf) {
    if (VENDOR_EVIDENCE.indexOf(v.assurance) === -1) return false;
    return !vendorAssuranceExpired(v, asOf);
  }

  function vendorReviewOverdue(v, asOf) {
    var due = dayKey(v.next_review_date);
    return !!due && due < asOf;
  }

  /** The GRC payload, or null when no assessment has been completed. */
  function grcData(ctx) {
    var g = ctx.data.grcAssessment;
    return g && g.assessment ? g : null;
  }

  /**
   * Question bank indexed by ITR id and by section, with answers folded in.
   * Memoised on ctx — five sections read it and the bank is ~200 rows.
   */
  function grcIndex(ctx) {
    if (ctx._grcIndex !== undefined) return ctx._grcIndex;

    var q = ctx.data.grcQuestions;
    var g = grcData(ctx);
    if (!q || !q.sections || !g) { ctx._grcIndex = null; return null; }

    var byItr = {}, bySection = {}, answers = {};
    (g.answers || []).forEach(function (a) {
      var id = a.question_id != null ? a.question_id : a.questionId;
      if (id != null) answers[String(id)] = a;
    });
    Object.keys(q.sections).forEach(function (name) {
      bySection[name] = q.sections[name] || [];
      bySection[name].forEach(function (qq) {
        if (qq.external_risk_id) byItr[qq.external_risk_id] = qq;
      });
    });

    ctx._grcIndex = { byItr: byItr, bySection: bySection, answers: answers };
    return ctx._grcIndex;
  }

  /** { q, answer, notes } for an ITR id, or null when it isn't in the bank. */
  function grcControl(ctx, itrId) {
    var ix = grcIndex(ctx);
    if (!ix) return null;
    var q = ix.byItr[itrId];
    if (!q) return null;
    var a = ix.answers[String(q.id)] || {};
    return { q: q, answer: a.answer || null, notes: a.notes || '' };
  }

  /** { score, answered, total } straight off the server, or null. */
  function grcSectionScore(ctx, name) {
    var g = grcData(ctx);
    if (!g) return null;
    return (g.sectionScores || {})[name] || null;
  }

  /** Controls in `sections` answered 'no' or 'partial', worst weight first. */
  function grcGaps(ctx, sections, limit) {
    var ix = grcIndex(ctx);
    if (!ix) return [];
    var rank = { critical: 0, high: 1, medium: 2, low: 3 };
    var out = [];

    sections.forEach(function (name) {
      (ix.bySection[name] || []).forEach(function (q) {
        var a = (ix.answers[String(q.id)] || {}).answer;
        if (a === 'no' || a === 'partial') out.push({ q: q, answer: a });
      });
    });

    out.sort(function (a, b) {
      var ra = rank[a.q.weight] == null ? 9 : rank[a.q.weight];
      var rb = rank[b.q.weight] == null ? 9 : rank[b.q.weight];
      return ra - rb;
    });
    return limit == null ? out : out.slice(0, limit);
  }

  /** One control attestation row. */
  function gcItem(ctrl) {
    var a     = ctrl.answer;
    var tone  = a ? (GRC_ANSWER_TONES[a] || '#8C8C8C') : '#BFBFBF';
    var label = a ? (GRC_ANSWER_LABELS[a] || titleCase(a)) : 'Not assessed';

    return '<div class="gc-item" style="border-left-color:' + tone + '">' +
        '<div>' +
          '<span class="gc-ref">' + esc(ctrl.q.external_risk_id || '') +
            (ctrl.q.itoo_ref ? ' &middot; ' + esc(ctrl.q.itoo_ref) : '') +
          '</span>' +
          '<span class="gc-q">' + esc(truncate(ctrl.q.text || '', 150)) + '</span>' +
        '</div>' +
        '<div class="gc-a">' +
          '<span class="rag-pill" style="background:' + tone + '">' + esc(label) + '</span>' +
        '</div>' +
      '</div>';
  }

  /** A named GRC domain as a .cmp-card progress bar. '' when the domain is absent. */
  function grcDomainCard(ctx, name) {
    var s = grcSectionScore(ctx, name);
    if (!s) return '';
    var has  = s.score != null;
    var band = has ? scoreBand(s.score) : null;

    return '<div class="cmp-card">' +
        '<div class="cmp-head">' +
          '<span class="cmp-t">' + esc(name) + '</span>' +
          '<span class="cmp-w">' + s.answered + '/' + s.total + '</span>' +
        '</div>' +
        '<div class="cmp-bar">' +
          '<div class="cmp-fill" style="width:' + (has ? s.score : 0) + '%;background:' +
            (has ? band.color : '#D9D9D9') + '"></div>' +
        '</div>' +
        '<div class="cmp-score">' + (has ? s.score + '/100' : 'Not assessed') + '</div>' +
      '</div>';
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Chart primitives
  // ══════════════════════════════════════════════════════════════════════════

  /**
   * Heat-map cell tone. Deliberately the same bands as the Top Cyber Risks
   * rating pill, because risk_score is likelihood x impact — the matrix and the
   * table must never disagree about what "High" means.
   */
  function heatTone(score) {
    if (score >= 20) return '#c0392b';
    if (score >= 15) return '#e74c3c';
    if (score >= 10) return '#e67e22';
    if (score >= 5)  return '#f39c12';
    return '#2E9E5B';
  }

  /** Open risks bucketed into the 5x5 matrix. */
  function heatBuckets(risks) {
    var cells = {}, plotted = 0, skipped = 0;

    (risks || []).forEach(function (r) {
      if (r.stage === 'closed') return;
      var l = Number(r.likelihood), i = Number(r.impact);
      if (!(l >= 1 && l <= 5) || !(i >= 1 && i <= 5)) { skipped++; return; }
      cells[l + ':' + i] = (cells[l + ':' + i] || 0) + 1;
      plotted++;
    });

    return { cells: cells, plotted: plotted, skipped: skipped };
  }

  function heatMapGrid(buckets) {
    var rows = '';
    // Likelihood 5 at the top so the worst corner is top-right, as a risk
    // matrix is conventionally drawn.
    for (var l = 5; l >= 1; l--) {
      rows += '<div class="hm-rl">' + l + '</div>';
      for (var i = 1; i <= 5; i++) {
        var n = buckets.cells[l + ':' + i] || 0;
        rows += '<div class="hm-cell" style="background:' + heatTone(l * i) +
                ';opacity:' + (n ? 1 : 0.22) + '">' +
                (n ? '<span class="hm-n">' + n + '</span>' : '') +
              '</div>';
      }
    }

    var xl = '<div></div>';
    for (var x = 1; x <= 5; x++) xl += '<div class="hm-xl">' + x + '</div>';

    var legend = [
      { l: 'Low (1-4)',       t: heatTone(1) },
      { l: 'Moderate (5-9)',  t: heatTone(5) },
      { l: 'High (10-14)',    t: heatTone(10) },
      { l: 'Severe (15-19)',  t: heatTone(15) },
      { l: 'Critical (20+)',  t: heatTone(20) },
    ].map(function (k) {
      return '<span class="hm-key"><i class="hm-sw" style="background:' + k.t + '"></i>' +
             esc(k.l) + '</span>';
    }).join('');

    return '<div class="hm-wrap">' +
        '<div class="hm-ylab">Likelihood</div>' +
        '<div class="hm-main">' +
          '<div class="hm-grid">' + rows + '</div>' +
          '<div class="hm-xaxis">' + xl + '</div>' +
          '<div class="hm-xtitle">Impact</div>' +
        '</div>' +
      '</div>' +
      '<div class="hm-legend">' + legend + '</div>';
  }

  /** 12-month stacked severity columns from /api/vulns/trends. */
  function vulnTrendChart(rows) {
    if (!Array.isArray(rows) || !rows.length) return '';

    var order = ['critical', 'high', 'medium', 'low'];
    var tones = { critical: SEV_TONES.Critical, high: SEV_TONES.High,
                  medium: SEV_TONES.Medium, low: SEV_TONES.Low };

    // Oldest first, last 12, so the chart reads left to right chronologically.
    var series = rows.slice().sort(function (a, b) {
      return String(a.monthKey) < String(b.monthKey) ? -1 : 1;
    }).slice(-12);

    var max = 0;
    series.forEach(function (r) {
      var t = order.reduce(function (a, k) { return a + (Number(r[k]) || 0); }, 0);
      if (t > max) max = t;
    });
    if (!max) return '';

    var cols = series.map(function (r) {
      var segs = order.map(function (k) {
        var v = Number(r[k]) || 0;
        if (!v) return '';
        return '<div class="tr-seg" style="height:' + ((v / max) * 100) + '%;background:' +
               tones[k] + '"></div>';
      }).join('');
      return '<div class="tr-col">' + segs + '</div>';
    }).join('');

    var labels = series.map(function (r) {
      return '<div class="tr-xl">' + esc(String(r.monthKey || '').slice(5)) + '</div>';
    }).join('');

    var legend = order.map(function (k) {
      return '<span class="hm-key"><i class="hm-sw" style="background:' + tones[k] + '"></i>' +
             titleCase(k) + '</span>';
    }).join('');

    return '<div class="tr-chart">' + cols + '</div>' +
      '<div class="tr-xaxis">' + labels + '</div>' +
      '<div class="hm-legend">' + legend + '</div>';
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Human risk
  // ══════════════════════════════════════════════════════════════════════════

  /**
   * Did this person click? true, false, or null when the export did not say.
   *
   * `clicked` is authoritative; `clicked_at` only ever proves a click, and its
   * absence proves nothing on rows written before
   * db/migrate-awareness-clicked.sql — the old parser left it NULL for a real
   * non-click and for a value it could not read alike.
   */
  function clickState(s) {
    if (!s) return null;
    if (s.clicked === true || s.clicked === false) return s.clicked;
    if (s.clicked_at) return true;
    return null;
  }

  /**
   * Phishing simulation outcomes.
   *
   * `clickPct` is PER SIMULATION — click events over simulations sent — which
   * is what the Arctic Wolf console calls the click-rate. A board report that
   * disagreed with the vendor's own dashboard would be indefensible in the
   * room, and the per-person alternative is roughly five times larger: over
   * many simulations, most people click something eventually.
   *
   * `staffClickedPct` keeps that per-person view under its own name, for the
   * separate question of how much of the workforce has ever fallen for one.
   *
   * Rows whose click state is unknown are excluded from the denominator as
   * well as the numerator. This slide goes to a board: a rate computed over
   * rows we never had an answer for would be presented as fact, and the most
   * likely direction of that error is flattering.
   */
  function phishingMetrics(sessions) {
    var sims = (sessions || []).filter(function (s) {
      return s.session_type === 'Phishing Simulation';
    });
    var remed = (sessions || []).filter(function (s) {
      return s.session_type === 'Phishing Remediation Session';
    });
    if (!sims.length && !remed.length) return null;

    var known   = sims.filter(function (s) { return clickState(s) !== null; });
    var clicked = known.filter(function (s) { return clickState(s) === true; }).length;

    var email = function (s) { return (s.user_email || '').toLowerCase(); };
    var staffSent    = {}; var staffClicked = {};
    known.forEach(function (s) {
      staffSent[email(s)] = true;
      if (clickState(s) === true) staffClicked[email(s)] = true;
    });
    var sentCount    = Object.keys(staffSent).length;
    var clickedCount = Object.keys(staffClicked).length;

    return {
      sent:      sims.length,
      measured:  known.length,
      unknown:   sims.length - known.length,
      clicked:   clicked,
      clickPct:  known.length ? completionPct(clicked, known.length) : null,
      staffSent:       sentCount,
      staffClicked:    clickedCount,
      staffClickedPct: sentCount ? completionPct(clickedCount, sentCount) : null,
      assigned:  remed.length,
      completed: remed.filter(function (s) { return s.status === 'Complete'; }).length,
    };
  }

  /** The last N phishing campaigns, grouped by send date and title. */
  function phishingCampaigns(sessions, limit) {
    var buckets = {}, order = [];

    (sessions || []).forEach(function (s) {
      if (s.session_type !== 'Phishing Simulation' || !s.sent_date) return;
      var day = String(s.sent_date).slice(0, 10);
      var key = day + '||' + (s.title || '');
      if (!buckets[key]) {
        buckets[key] = { sentDate: day, title: s.title || '(untitled)', sent: 0, clicked: 0 };
        order.push(key);
      }
      var state = clickState(s);
      if (state === null) return;          // not measured — not in either total
      buckets[key].sent++;
      if (state === true) buckets[key].clicked++;
    });

    return order.map(function (k) { return buckets[k]; })
      // A campaign where nothing was measured has no rate to report; dropping
      // it beats printing a 0% next to a real campaign's 14%.
      .filter(function (c) { return c.sent > 0; })
      .sort(function (a, b) { return a.sentDate < b.sentDate ? 1 : -1; })
      .slice(0, limit || 3)
      .map(function (c) { c.clickPct = completionPct(c.clicked, c.sent); return c; });
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Executive decisions
  // ══════════════════════════════════════════════════════════════════════════

  /**
   * Decisions the board actually has to take, derived from breached thresholds
   * rather than authored. Ordered by how overdue the decision is.
   */
  function deriveDecisions(ctx) {
    var data  = ctx.data.vulnFindings || {};
    var risks = (data.risks || []).filter(function (r) { return r.stage !== 'closed'; });
    var out   = [];
    var today = new Date().toISOString().slice(0, 10);

    var overdue = risks.filter(function (r) { return r.due_date && String(r.due_date).slice(0, 10) < today; });
    if (overdue.length) {
      out.push({ area: 'Overdue risk remediation', tone: 'high', impact: 'Major',
        text: overdue.length + ' risk' + (overdue.length === 1 ? ' has' : 's have') +
              ' passed the agreed target closure date. Confirm revised dates with the ' +
              'accountable owners or accept the extended exposure.' });
    }

    var above = risks.filter(function (r) { return Number(r.risk_score) >= RISK_APPETITE_SCORE; });
    if (above.length) {
      out.push({ area: 'Risks above appetite', tone: 'high', impact: 'Major',
        text: above.length + ' open risk' + (above.length === 1 ? ' sits' : 's sit') +
              ' at or above the agreed appetite of ' + RISK_APPETITE_SCORE +
              '. Each requires funded mitigation or a documented acceptance.' });
    }

    var pastSla = (data.vulns || []).filter(function (v) {
      if (!VULN_OPEN_STATUSES[v.status]) return false;
      var k = sevKey(v.risk);
      var age = ageDays(v.firstSeenAt);
      return k && age != null && age > vulnSlaDays(k);
    });
    if (pastSla.length) {
      out.push({ area: 'Vulnerability remediation window', tone: 'medium', impact: 'Moderate',
        text: pastSla.length + ' finding' + (pastSla.length === 1 ? ' is' : 's are') +
              ' past the remediation SLA for their severity. Authorise a maintenance ' +
              'window or accept the residual exposure.' });
    }

    /*
     * TWO DIFFERENT INVESTMENT DECISIONS, KEPT APART.
     *
     *   below target      a service they DO buy is underperforming. Spend to
     *                     fix what is already in place.
     *   not consumed      a service they do NOT buy at all. Spend to acquire a
     *                     capability they have never had.
     *
     * Merging them would ask a board to approve one budget for two unrelated
     * things, and would let "vulnerability management is below target" stand in
     * for "you have no vulnerability management", which are not the same
     * sentence and do not have the same answer.
     */
    var now    = componentScores(ctx);
    var behind = [];
    /*
     * Same three gates as the Executive Summary prose: a control they never
     * bought scores 0 because nobody was engaged to manage it, and an
     * unmeasured one is a gap in our evidence rather than a weak result.
     * Neither is "below the agreed target" in any sense a board can act on —
     * and the unbought ones are covered by the recommendation below, where
     * they belong.
     */
    function trailingDomain(key, phrase) {
      if (now[key] == null) return;
      if (!(now.measured || {})[key]) return;
      if (!componentInScope(ctx, key)) return;
      if (now[key] < MATURITY_TARGETS[key]) behind.push(phrase);
    }
    trailingDomain('vulnerabilities',  'vulnerability management');
    trailingDomain('awareness',        'security awareness');
    trailingDomain('incidentResponse', 'managed detection and response');
    if (behind.length) {
      out.push({ area: 'Investment to reach target', tone: 'medium', impact: 'Moderate',
        text: listPhrase(behind) + ' ' + (behind.length === 1 ? 'is' : 'are') +
              ' below the agreed target score. Approve the investment needed to close ' +
              'the gap, or agree a revised target.' });
    }

    /*
     * Services the client does not consume, named individually.
     *
     * The list comes from the scoring payload (lib/services.js is its owner) so
     * a service added to the catalogue appears here without this file being
     * touched — the alternative was a second copy of the catalogue in the
     * browser, which would have been wrong the first time somebody added a
     * service and updated only one of them.
     *
     * `unpurchased` is null when no service mix is recorded, and this entry is
     * then omitted entirely. That is deliberate and it is the important case:
     * an unconfigured client has not been asked what they buy, and inferring
     * "they consume nothing" would print our entire price list into their board
     * pack as a set of recommendations.
     */
    var unpurchased = (((ctx.data || {}).secureScore || {}).scope || {}).unpurchased;
    if (Array.isArray(unpurchased) && unpurchased.length) {
      out.push({
        area: 'Services not currently consumed',
        // Commercial, not a control failure. A board that reads an upsell as a
        // red finding stops trusting the red findings.
        tone: 'info', impact: 'Commercial', chip: 'Option',
        text: 'The following are not part of the current engagement: ' +
              unpurchased.map(function (s) { return s.label; }).join('; ') +
              '. Each is available under the existing agreement and would extend ' +
              'coverage beyond what is reported here. This is a commercial ' +
              'option for consideration, not a finding against the controls in ' +
              'place.',
      });
    }

    var unowned = risks.filter(function (r) { return !String(r.owner || '').trim(); });
    if (unowned.length) {
      out.push({ area: 'Unassigned risk ownership', tone: 'low', impact: 'Governance',
        text: unowned.length + ' open risk' + (unowned.length === 1 ? ' has' : 's have') +
              ' no accountable owner. Assign ownership so remediation can be tracked.' });
    }

    return out;
  }

  // ══════════════════════════════════════════════════════════════════════════
  // The 15 board sections
  //
  // Several fold in what used to be separate sections. Where a folded body would
  // exceed the ~225mm a page can hold, the renderer returns an ARRAY of bodies:
  // measured pagination packs them without wasting a page, and a body that is
  // alone on a page and still too tall is silently cropped.
  // ══════════════════════════════════════════════════════════════════════════

  function subHead(text) {
    return '<div class="sec-sub">' + esc(text) + '</div>';
  }

  function block(inner) {
    return '<div class="sec-block">' + inner + '</div>';
  }

  // ── 1. Executive Summary ──────────────────────────────────────────────────

  function renderExecSummary(ctx) {
    var now   = componentScores(ctx);
    var prev  = previousScores(ctx);
    var data  = ctx.data.vulnFindings || {};
    var risks = (data.risks || []).filter(function (r) { return r.stage !== 'closed'; });
    var sum   = vulnSummaryFor(ctx);

    // Both feeds, counted once, by the helper the drafted prose also calls.
    var inc         = incidentCount(ctx);
    var irIncidents = inc.ir;
    var mdrRaised   = inc.mdr;
    var incidents   = inc.total;

    var crit = sum ? (Number(sum.critical) || 0) + (Number(sum.high) || 0) : null;
    var above = risks.filter(function (r) {
      return Number(r.risk_score) >= RISK_APPETITE_SCORE;
    }).length;

    // Awareness completion across the whole programme, not just this month.
    var aw = ctx.data.awareness;
    var awPct = null;
    if (aw && (aw.sessions || []).length) {
      var t = allTimeTotals(aw.sessions, 'Awareness Session');
      if (t.assigned) awPct = t.completionPct;
    }

    /*
     * THE HEADLINE IS THE IN-SCOPE SCORE, NOT THE OVERALL.
     *
     * The overall counts controls the client never bought as zero, so an
     * awareness-only client opened their board pack on "Secure Score 35" when
     * the service they pay for scored 100. The exec summary reports on the
     * engagement; the overall score and its coverage gaps have their own
     * section, which can be included or left out.
     *
     * Falls back to the overall when no service mix is recorded, which is the
     * behaviour every existing client keeps.
     */
    var ss = ctx.data.secureScore || {};
    // headlineScore() is the rule; this section does not get its own copy of
    // it. `now.overall` stays the fallback for a payload with neither
    // `overall` nor `score` — componentScores() recomputes it from components.
    var head = headlineScore(ss);
    var scoped = head.scoped;
    var headline = head.score != null ? head.score : now.overall;

    var band = headline != null ? scoreBand(headline) : null;
    // Trend still compares against the stored history, which holds composites.
    // Only meaningful on the unscoped number, so it is dropped when scoped
    // rather than silently comparing two different measures.
    var t2 = scoped ? { mark: '' } : trendFor(now.overall, prev.overall);

    var tiles = [
      { v: headline == null ? null : headline + '/100',
        l: 'Secure Score' + (scoped ? ' &middot; services in scope' : '') +
           (band ? ' &middot; ' + band.label : '') +
           (t2.mark ? ' ' + t2.mark : '') },
    ];

    // Coverage sits beside the score it qualifies, so the two are never read
    // apart. Only when a service mix is on file — otherwise there is no
    // coverage statement to make.
    if (scopeRecorded(ctx) && ss.coverage != null) {
      tiles.push({ v: ss.coverage + '%', l: 'Service coverage of posture' });
    }

    /*
     * Every remaining tile is gated on the service that produces it. A client
     * without vulnerability management does not get a vulnerability count —
     * not even a zero, which on a board pack reads as a clean scan rather than
     * as a service never purchased.
     */
    /*
     * Gated on the SERVICE THAT PRODUCES THE DATA, not on the score component.
     *
     * These are not the same thing and conflating them put an empty
     * "Critical & high vulnerabilities open — No data" tile in front of an MDR
     * client. The vulnerabilities COMPONENT is legitimately in scope for them:
     * MDR includes endpoint detection, so it is scored on endpoint patch
     * currency. But this tile is fed by SCAN findings, which come from the
     * Vulnerability Management service they do not buy.
     *
     * The component answers "what are they scored on". The service answers
     * "where does this number come from". A tile has to ask the second.
     */
    if (serviceInScope(ctx, 'vuln')) {
      tiles.push({ v: crit == null ? null : String(crit),
                   l: 'Critical &amp; high vulnerabilities open' });
    }
    if (serviceInScope(ctx, 'mdr')) {
      tiles.push({ v: String(incidents), l: 'Security incidents this period' +
        (mdrRaised && irIncidents ? ' (' + mdrRaised + ' MDR, ' + irIncidents + ' logged)' : '') });
      // A "Resolution SLA met" tile sat here and was removed on request. The
      // incident count stays: it is a statement of activity, not of attainment
      // against a target.
    }
    if (serviceInScope(ctx, 'awareness')) {
      tiles.push({ v: awPct == null ? null : awPct + '%', l: 'Awareness completion' });
    }
    // The risk register is a governance deliverable, not a technical feed.
    if (serviceInScope(ctx, 'viso')) {
      tiles.push({ v: String(above), l: 'Open risks above appetite' });
    }

    var prose = String(ctx.execSummary || '').trim();
    if (!prose && !tiles.some(function (t3) { return t3.v != null; })) return null;

    var html = '<div class="bi-grid tight">' +
      tiles.map(function (t3) {
        return '<div class="bi-cell">' +
            // `nd` lets a tile say WHY it is empty. "No data" is the default
            // because an unexplained blank is worse, but it is a claim about
            // our reporting and must not be made when the truth is that the
            // month had nothing to measure.
            '<div class="bi-v' + (t3.v == null ? ' nd' : '') + '">' +
              (t3.v == null ? esc(t3.nd || 'No data') : esc(t3.v)) + '</div>' +
            '<div class="bi-l">' + t3.l + '</div>' +
          '</div>';
      }).join('') +
    '</div>';

    if (prose) {
      html += '<div class="es-prose" style="margin-top:5mm">' +
        prose.split(/\n\s*\n/).map(function (p) {
          return '<p>' + esc(p.trim()).replace(/\r?\n/g, '<br>') + '</p>';
        }).join('') +
      '</div>';
    }

    // The Observations narrative keeps its input and its draft function; it just
    // no longer owns a section of its own.
    var obs = observationBullets(ctx);
    if (obs) html += subHead('Observations') + obs;

    return html + sectionComment(ctx, 'execSummary');
  }

  // ── 2. Cybersecurity Assurance Dashboard ──────────────────────────────────

  /* ── Service coverage ─────────────────────────────────────────────────────
   *
   * Three numbers, because one cannot answer both questions a board has:
   *
   *   Secure Score (in scope)   how are the services you buy performing?
   *   Service coverage          how much of your posture do they reach?
   *   Overall Secure Score      how are you doing, counting everything?
   *
   * A client who buys only awareness training was previously shown a single
   * composite around 35, which reads as failure and is really a statement
   * about our order book: they were scored 0 for two controls they never
   * bought. Their awareness result was 100.
   *
   * The three are NOT related by a formula. A client running their own
   * vulnerability programme is measured but not covered, so their overall can
   * exceed anything coverage would predict. The slide says so rather than
   * inviting the reader to multiply.
   *
   * Self-disabling when no service mix has been recorded: with nothing on
   * file, there is no coverage statement to make and the section skips
   * silently rather than printing an empty frame.
   */
  /* ── Scope gates ──────────────────────────────────────────────────────────
   *
   * A client is not shown a metric for a service they do not buy. Not as a
   * zero, not as "No data", not at all — an empty tile on a board pack reads
   * as a control that failed, and defending "you never bought that" in the
   * room is worse than never printing it.
   *
   * Both gates default to TRUE when no service mix is on file, so a client
   * nobody has configured sees exactly the report they saw before any of this
   * existed. Unrecorded is not a claim that they buy nothing.
   */

  /** Is a scored Secure Score component in scope? */
  function componentInScope(ctx, key) {
    var scope = ((ctx.data || {}).secureScore || {}).scope;
    if (!scope || !scope.recorded) return true;
    return (scope.covered || []).indexOf(key) >= 0;
  }

  /**
   * Is a service consumed? Keys are those in lib/services.js.
   *
   * Reads the EFFECTIVE set, so a client on MDR counts as having Managed EDR,
   * NDR and Identity — those are delivered inside MDR and they are not asked
   * to buy them separately. Falls back to the raw list only for payloads
   * predating that field.
   */
  function serviceInScope(ctx, key) {
    var scope = ((ctx.data || {}).secureScore || {}).scope;
    if (!scope || !scope.recorded) return true;
    var list = scope.effectiveServices || scope.services || [];
    return list.indexOf(key) >= 0;
  }

  /** Has a service mix been recorded at all? */
  function scopeRecorded(ctx) {
    var scope = ((ctx.data || {}).secureScore || {}).scope;
    return !!(scope && scope.recorded);
  }

  /**
   * WHICH SECURE SCORE THE CLIENT IS SHOWN. The only copy of this rule.
   *
   * The in-scope score when a service mix is on file, the overall composite
   * when nobody has recorded one. The overall counts controls the client never
   * bought as zero, so an awareness-only client opened their board pack on
   * "Secure Score 35" for a service that scored 100.
   *
   * Exported because the Reports tab's Overview tile needs the same answer and
   * was computing its own — off `secureScore.score`, the overall. That put a
   * different Secure Score on the Overview slide from the one on the Executive
   * Summary of the same deck, which is the failure this repo has already had
   * once with the vulnerability SLA. One rule, served, not copied.
   *
   * @param {Object} payload  a /api/secure-score response
   * @returns {{ score: number|null, scoped: boolean, rating: string|null }}
   */
  function headlineScore(payload) {
    var p = payload || {};
    var scoped = !!(p.scope && p.scope.recorded) && p.serviceScore != null;
    var raw = scoped ? p.serviceScore : (p.overall != null ? p.overall : p.score);
    return {
      score:  raw == null ? null : Math.round(Number(raw)),
      scoped: scoped,
      rating: (scoped ? p.serviceRating : p.rating) || null,
    };
  }

  function serviceCoverageBlock(ctx) {
    var ss = ctx.data.secureScore || {};
    var scope = ss.scope;
    if (!scope || !scope.recorded) return null;

    var tiles = [
      { v: ss.serviceScore == null ? 'n/a' : String(ss.serviceScore),
        l: 'Secure Score — services in scope',
        ok: ss.serviceScore != null && ss.serviceScore >= 70 },
      { v: ss.coverage == null ? '—' : ss.coverage + ' %',
        l: 'Service coverage of posture',
        ok: ss.coverage != null && ss.coverage >= 80 },
      { v: ss.overall == null ? '—' : String(ss.overall),
        l: 'Overall Secure Score',
        ok: ss.overall != null && ss.overall >= 70 },
    ];

    /*
     * ARCTIC WOLF SENSOR REACH — shown only when there IS a figure.
     *
     * Asymmetric with the staff tab on purpose, and worth stating so it is not
     * later "tidied up" into consistency: the tab tells a staff member when the
     * org is not linked, because a staff member is the person who can fix it. A
     * client's board does not need to read that we have not finished
     * configuring an internal mapping — and printing "no discount applied"
     * implies a discount was expected, which is a claim about their service
     * rather than about our records.
     */
    var awc = scope.mdrCoverage;
    var awApplied = !!(awc && awc.available && (scope.discountedPoints || 0) > 0);
    if (awApplied) {
      tiles.push({ v: awc.score + ' %', l: 'Arctic Wolf MDR coverage',
                   ok: awc.score >= 90 });
    }

    var grid = '<div class="bi-grid tight">' +
      tiles.map(function (t) {
        return '<div class="bi-cell' + (t.ok ? ' ok' : '') + '">' +
            '<div class="bi-v">' + esc(t.v) + '</div>' +
            '<div class="bi-l">' + esc(t.l) + '</div>' +
          '</div>';
      }).join('') + '</div>';

    // The arithmetic, attributed and dated. class="coverage-note" already maps
    // to a note block in lib/report-pptx.js, so the deck carries it unchanged.
    if (awApplied) {
      grid += '<p class="coverage-note">Service coverage of ' + esc(String(ss.coverage)) +
        '% is ' + esc(String(scope.coverageNominal)) + '% covered by the services in ' +
        'scope, less ' + esc(String(scope.discountedPoints)) + ' points because ' +
        'Arctic Wolf reports ' + esc(String(awc.score)) + '% sensor coverage of the estate' +
        (awc.weekCommencing ? ' (week commencing ' + esc(awc.weekCommencing) + ')' : '') +
        '. This reflects how much of the estate the service reaches; it does not ' +
        'change the Overall Secure Score.</p>';
    }

    var gaps = '';
    if ((scope.uncovered || []).length) {
      gaps = D.dataTable({
        cols: [
          { label: 'Control not covered', key: 'label',  width: '34%' },
          { label: 'Weight',              key: 'wt',     width: '13%', cls: 'num' },
          { label: 'Evidence',            key: 'ev',     width: '25%' },
          { label: 'Closed by',           key: 'by',     width: '28%' },
        ],
        rows: scope.uncovered.map(function (u) {
          return {
            label: u.label,
            wt:    Math.round((u.weight || 0) * 100) + ' %',
            // The distinction that stops a security gap being filed as a sales
            // opportunity, and vice versa.
            ev:    u.evidence === 'measured'
                     ? 'Measured, outside this engagement'
                     : 'None — not being measured',
            by:    (u.closedBy || []).join(' or ') || '—',
          };
        }),
      });
    }

    var blind = scope.blindSpotPoints || 0;
    var note = '<div class="rag-note">' +
      '<strong>Secure Score — services in scope</strong> covers only the controls ' +
      'delivered under the services contracted with Reflex, and is the fair measure ' +
      'of that delivery. <strong>Overall Secure Score</strong> counts every control ' +
      'that applies, whoever runs it. ' +
      (blind
        ? '<strong>' + blind + ' of the 100 points sit in controls that neither ' +
          'Reflex nor any evidence supplied covers</strong> — those are not weak ' +
          'results, they are unmeasured ones. '
        : 'Every control outside our services still has evidence behind it. ') +
      'The two scores are independent: a control measured outside these ' +
      'services still raises the overall score without changing coverage.</div>';

    return block(grid + (gaps ? subHead('Coverage gaps') + gaps : '') + note);
  }

  function renderServiceCoverage(ctx) { return serviceCoverageBlock(ctx); }

  function renderAssuranceDashboard(ctx) {
    var maturity = maturityBlock(ctx);
    var kpis     = irKpiBlock(ctx);
    var endpoint = endpointCoverageGroup(ctx);
    if (!maturity && !kpis && !endpoint) return null;

    var bodies = [];
    var first  = '';
    if (maturity) first += block(subHead('Maturity against target') + maturity);
    if (kpis)     first += block(subHead('Incident resolution') + kpis);
    if (first)    bodies.push(first);

    if (endpoint) {
      bodies.push(subHead('Endpoint protection') +
        '<div class="cc-grid">' + endpoint + '</div>' + coverageNote(ctx));
    }

    if (!bodies.length) return null;
    bodies[bodies.length - 1] += sectionComment(ctx, 'assuranceDashboard');
    return bodies.length === 1 ? bodies[0] : bodies;
  }

  // ── 3. Cyber Risk Heat Map ────────────────────────────────────────────────

  function renderRiskHeatMap(ctx) {
    var b = heatBuckets((ctx.data.vulnFindings || {}).risks);
    if (!b.plotted) return null;

    return heatMapGrid(b) +
      '<div class="rag-note">' +
        b.plotted + ' open risk' + (b.plotted === 1 ? '' : 's') + ' plotted by ' +
        'likelihood and impact, each scored 1&ndash;5. Cell colour follows the ' +
        'product of the two, the same rating used on the Top Cyber Risks register.' +
        (b.skipped
          ? ' ' + b.skipped + ' further open risk' + (b.skipped === 1 ? ' is' : 's are') +
            ' not plotted because no likelihood or impact has been recorded.'
          : '') +
      '</div>' +
      sectionComment(ctx, 'heatMap');
  }

  // ── 6. Risk Appetite Dashboard ────────────────────────────────────────────

  function renderRiskAppetite(ctx) {
    var areas = riskAreas(ctx);
    if (!areas.some(function (a) { return a.score != null; })) return null;

    var risks = ((ctx.data.vulnFindings || {}).risks || []).filter(function (r) {
      return r.stage !== 'closed';
    });
    var above   = risks.filter(function (r) { return Number(r.risk_score) >= RISK_APPETITE_SCORE; }).length;
    var outside = areas.filter(function (a) { return a.score != null && a.score < a.target; }).length;

    var tiles = '<div class="bi-grid tight">' +
        '<div class="bi-cell' + (above ? '' : ' ok') + '">' +
          '<div class="bi-v">' + above + '</div>' +
          '<div class="bi-l">Risks above appetite</div></div>' +
        '<div class="bi-cell' + (outside ? '' : ' ok') + '">' +
          '<div class="bi-v">' + outside + '</div>' +
          '<div class="bi-l">Domains below target</div></div>' +
        '<div class="bi-cell">' +
          '<div class="bi-v">' + RISK_APPETITE_SCORE + '</div>' +
          '<div class="bi-l">Appetite threshold (likelihood &times; impact)</div></div>' +
      '</div>';

    return tiles + '<div style="margin-top:5mm">' + riskAreaTable(ctx, areas) + '</div>';
  }

  // ── 9. Third-Party Risk Dashboard ─────────────────────────────────────────

  /** Inventory half: tiles plus the highest-residual-risk vendors. */
  function vendorInventoryBlock(ctx, vendors) {
    var asOf     = vendorAsOf(ctx);
    var highTier = vendors.filter(function (v) {
      return v.criticality === 'critical' || v.criticality === 'high';
    }).length;
    var overdue  = vendors.filter(function (v) { return vendorReviewOverdue(v, asOf); }).length;
    var noEvid   = vendors.filter(function (v) { return !vendorHasEvidence(v, asOf); }).length;

    var html = '<div class="bi-grid tight">' +
        '<div class="bi-cell">' +
          '<div class="bi-v">' + vendors.length + '</div>' +
          '<div class="bi-l">Vendors under management</div></div>' +
        '<div class="bi-cell">' +
          '<div class="bi-v">' + highTier + '</div>' +
          '<div class="bi-l">Critical &amp; high tier</div></div>' +
        '<div class="bi-cell' + (overdue ? '' : ' ok') + '">' +
          '<div class="bi-v">' + overdue + '</div>' +
          '<div class="bi-l">Reviews overdue</div></div>' +
        '<div class="bi-cell' + (noEvid ? '' : ' ok') + '">' +
          '<div class="bi-v">' + noEvid + '</div>' +
          '<div class="bi-l">No assurance evidence</div></div>' +
      '</div>';

    // Already ordered by residual_score DESC by the API; sort defensively so
    // the deck does not depend on the route's ORDER BY.
    var top = vendors.slice().sort(function (a, b) {
      return (b.residual_score || 0) - (a.residual_score || 0);
    }).slice(0, MAX_VENDOR_ROWS);

    html += subHead('Highest residual exposure') + D.dataTable({
      cols: [
        { label: 'Vendor', key: 'name', width: '26%',
          raw: function (v) { return esc(truncate(v.name || '', 30)); } },
        { label: 'Service', key: 'service', width: '24%',
          raw: function (v) { return esc(truncate(v.service || '—', 28)); } },
        { label: 'Tier', key: 'criticality', width: '12%',
          raw: function (v) { return esc(VENDOR_TIER_LABEL[v.criticality] || v.criticality || '—'); } },
        { label: 'Assurance', key: 'assurance', width: '18%',
          raw: function (v) {
            var label = VENDOR_ASSURANCE_LABEL[v.assurance] || v.assurance || 'None';
            if (vendorAssuranceExpired(v, asOf)) label += ' (expired)';
            return esc(label);
          } },
        { label: 'Residual', key: 'residual_score', width: '10%', cls: 'num' },
        { label: 'Next review', key: 'next_review_date', width: '10%', cls: 'num',
          raw: function (v) { return esc(fmtShortDate(v.next_review_date)); } },
      ],
      rows: top,
    });

    return html;
  }

  function renderThirdPartyRisk(ctx) {
    var vendors = vendorList(ctx);
    var grc     = grcData(ctx);

    var controls = grc
      ? THIRD_PARTY_ITR.map(function (id) { return grcControl(ctx, id); }).filter(Boolean)
      : [];

    // Neither an inventory nor a supplier-security self-assessment: there is
    // nothing to say, so say nothing rather than print a page of zeroes.
    if (!vendors.length && !controls.length) return null;

    var asOf = vendorAsOf(ctx);
    var bodies = [];

    if (vendors.length) bodies.push(vendorInventoryBlock(ctx, vendors));

    // Control-attestation half, kept as corroboration of the inventory.
    if (controls.length) {
      var score   = grcSectionScore(ctx, GRC_THIRD_PARTY_SECTION);
      var failing = controls.filter(function (c) { return c.answer === 'no'; }).length;

      var gov = '';
      // These two tiles are the whole story when there is no inventory; with
      // one, the inventory tiles above already carry the headline.
      if (!vendors.length) {
        gov += '<div class="bi-grid tight">' +
            '<div class="bi-cell">' +
              '<div class="bi-v' + (score && score.score != null ? '' : ' nd') + '">' +
                (score && score.score != null ? score.score + '/100' : 'Not assessed') + '</div>' +
              '<div class="bi-l">Supplier security domain</div></div>' +
            '<div class="bi-cell' + (failing ? '' : ' ok') + '">' +
              '<div class="bi-v">' + failing + '</div>' +
              '<div class="bi-l">Controls not in place</div></div>' +
          '</div>';
      }

      gov += subHead('Supplier security controls' +
        (score && score.score != null ? ' — ' + score.score + '/100' : '')) +
        '<div class="gc-list">' + controls.map(gcItem).join('') + '</div>';

      bodies.push(gov);
    }

    // Risks attributed to a vendor, or raised against one of the supplier
    // controls above. A risk can match on either, so dedupe by id.
    var ids = {};
    controls.forEach(function (c) { ids[c.q.id] = true; });
    var vendorNames = {};
    vendors.forEach(function (v) { vendorNames[v.id] = v.name; });

    var linked = ((ctx.data.vulnFindings || {}).risks || []).filter(function (r) {
      return r.stage !== 'closed' &&
             (ids[r.grc_question_id] || (r.vendor_id && vendorNames[r.vendor_id]));
    });

    var tail = '';
    if (linked.length) {
      tail += subHead('Linked risks') + D.dataTable({
        cols: [
          { label: 'Risk', key: 'title', width: '38%',
            raw: function (r) { return esc(truncate(r.title || '', 52)); } },
          { label: 'Vendor', key: 'vendor_id', width: '20%',
            raw: function (r) { return esc(truncate(vendorNames[r.vendor_id] || '—', 24)); } },
          { label: 'Rating', key: 'risk_score', width: '12%', cls: 'num' },
          { label: 'Owner', key: 'owner', width: '18%',
            raw: function (r) { return esc(truncate(r.owner || 'Unassigned', 22)); } },
          { label: 'Target', key: 'due_date', width: '12%', cls: 'num',
            raw: function (r) { return esc(fmtShortDate(r.due_date)); } },
        ],
        rows: linked.slice(0, MAX_LINKED_RISK_ROWS),
      });
    }

    // State the basis precisely. These scores are self-attested inherent risk,
    // not a tested assessment of the vendor's controls, and a board that reads
    // them as the latter has been misled.
    tail += '<div class="rag-note">';
    if (vendors.length) {
      tail += 'Vendor scores are <strong>inherent risk</strong> derived from the business ' +
        'criticality recorded for each supplier, the data they can reach, and the ' +
        'assurance evidence held on file — not a tested assessment of the vendor\'s ' +
        'own controls. Assurance past its expiry date earns no reduction. Review ' +
        'dates are judged as at ' + esc(fmtShortDate(asOf)) + '. ';
      tail += controls.length
        ? 'The supplier-security controls above are the client\'s own self-assessment.'
        : 'No supplier-security self-assessment has been completed, so no control ' +
          'attestation is shown alongside the inventory.';
    } else {
      tail += 'Third-party exposure is assessed from the supplier-security controls in the ' +
        'self-assessment and the risk-register entries linked to them. No vendors have ' +
        'been recorded on the Third-Party Risk tab, so this is a control-attestation ' +
        'view rather than a per-vendor risk score.';
    }
    tail += '</div>';

    bodies[bodies.length - 1] += tail;
    return bodies;
  }

  // ── 10. Identity and Access Risk Dashboard ────────────────────────────────

  function renderIdentityRisk(ctx) {
    var telemetry = identityCoverageGroup(ctx);
    var hasGrc    = !!grcData(ctx);
    if (!telemetry && !hasGrc) return null;

    var bodies = [];

    if (telemetry) {
      bodies.push('<div class="cc-grid">' + telemetry + '</div>' + coverageNote(ctx));
    }

    if (hasGrc) {
      var cards = GRC_IDENTITY_SECTIONS.map(function (n) { return grcDomainCard(ctx, n); })
                                       .filter(Boolean).join('');
      var gaps  = grcGaps(ctx, GRC_IDENTITY_SECTIONS, MAX_IDENTITY_GAPS);
      var grcHtml = '';
      if (cards) {
        grcHtml += subHead('Access control self-assessment') +
          '<div class="cmp-row" style="grid-template-columns:repeat(2,1fr)">' + cards + '</div>';
      }
      if (gaps.length) {
        grcHtml += '<div class="gc-list" style="margin-top:4mm">' +
          gaps.map(gcItem).join('') + '</div>';
      }
      if (grcHtml) bodies.push(grcHtml);
    }

    if (!bodies.length) return null;
    return bodies.length === 1 ? bodies[0] : bodies;
  }

  // ── 11. Vulnerability Dashboard ───────────────────────────────────────────

  function renderVulnDashboard(ctx) {
    var bodies = [];

    var exposure = vulnExposureBlock(ctx);
    if (exposure) bodies.push(exposure);

    var trend    = vulnTrendChart(ctx.data.vulnTrends);
    var findings = topFindingsBlock(ctx);
    var second   = '';
    if (trend)    second += block(subHead('Severity trend, last 12 months') + trend);
    if (findings) second += block(findings);
    if (second)   bodies.push(second);

    var pages = remediationPages(ctx);
    if (pages) bodies = bodies.concat(Array.isArray(pages) ? pages : [pages]);

    if (!bodies.length) return null;
    return bodies.length === 1 ? bodies[0] : bodies;
  }

  // ── 12. Human Risk Dashboard ──────────────────────────────────────────────

  function renderHumanRisk(ctx) {
    var a = ctx.data.awareness;
    if (!a || !(a.sessions || []).length) return null;

    var sessions = a.sessions;
    var sess = allTimeTotals(sessions, 'Awareness Session');
    var quiz = allTimeTotals(sessions, 'Quiz');
    var ph   = phishingMetrics(sessions);

    var tiles = [
      { v: sess.assigned ? sess.completionPct + '%' : null, l: 'Session completion', ok: sess.completionPct >= 70 },
      { v: quiz.assigned ? quiz.completionPct + '%' : null, l: 'Quiz completion',    ok: quiz.completionPct >= 70 },
      { v: ph && ph.clickPct != null ? ph.clickPct + '%' : null, l: 'Phishing click rate', ok: ph && ph.clicked === 0 },
      { v: ph && ph.assigned ? ph.completed + '/' + ph.assigned : null, l: 'Remediation completed' },
    ];

    var first = '<div class="bi-grid tight">' +
      tiles.map(function (t) {
        return '<div class="bi-cell' + (t.ok ? ' ok' : '') + '">' +
            '<div class="bi-v' + (t.v == null ? ' nd' : '') + '">' +
              (t.v == null ? 'No data' : esc(t.v)) + '</div>' +
            '<div class="bi-l">' + esc(t.l) + '</div>' +
          '</div>';
      }).join('') +
    '</div>';

    var camps = phishingCampaigns(sessions, 3);
    if (camps.length) {
      first += subHead('Recent phishing simulations') + D.dataTable({
        cols: [
          { label: 'Date', key: 'sentDate', width: '18%',
            raw: function (r) { return esc(fmtLongDate(r.sentDate)); } },
          { label: 'Campaign', key: 'title', width: '46%',
            raw: function (r) { return esc(truncate(r.title, 52)); } },
          { label: 'Sent',    key: 'sent',    width: '12%', cls: 'num' },
          { label: 'Clicked', key: 'clicked', width: '12%', cls: 'num' },
          { label: 'Click %', key: 'clickPct', width: '12%', cls: 'num',
            raw: function (r) { return esc(Number(r.clickPct).toFixed(2)) + ' %'; } },
        ],
        rows: camps,
      });
    }

    if (grcData(ctx)) {
      var card = grcDomainCard(ctx, GRC_PEOPLE_SECTION);
      var gaps = grcGaps(ctx, [GRC_PEOPLE_SECTION], 3);
      if (card) {
        first += subHead('People and awareness controls') +
          '<div class="cmp-row" style="grid-template-columns:1fr">' + card + '</div>';
      }
      if (gaps.length) {
        first += '<div class="gc-list" style="margin-top:4mm">' + gaps.map(gcItem).join('') + '</div>';
      }
    }

    var second = awarenessBlock(ctx);
    return second ? [first, second] : first;
  }

  // ── 13. Recovery and Resilience Dashboard ─────────────────────────────────

  function renderResilience(ctx) {
    if (!grcData(ctx)) return null;

    var controls = RESILIENCE_ITR.map(function (id) { return grcControl(ctx, id); })
                                 .filter(Boolean);
    if (!controls.length) return null;

    var incidents = ((ctx.data.vulnFindings || {}).incidents || []);
    var inPeriod  = incidents.filter(function (i) { return monthOf(i.opened_at) === ctx.period; });
    var recovering = incidents.filter(function (i) {
      return i.phase === 'recovery' && i.status !== 'closed' && i.status !== 'resolved';
    }).length;
    /*
     * Already the right cohort — incidents OPENED in the period, of those the
     * ones closed — but it was doing its own millisecond arithmetic, which made
     * three copies of "elapsed hours" in the product. Same helper as the MDR
     * timings now, so a change to how duration is measured cannot reach one
     * section and miss another.
     */
    var closed = inPeriod.filter(function (i) { return i.closed_at; });
    var hours  = closed
      .map(function (i) { return MM.elapsedHours(i.opened_at, i.closed_at); })
      .filter(function (h) { return h !== null; });
    var meanHours = hours.length
      ? Math.round((hours.reduce(function (x, y) { return x + y; }, 0) / hours.length) * 10) / 10
      : null;

    var cards = GRC_RESILIENCE_SECTIONS.map(function (n) { return grcDomainCard(ctx, n); })
                                       .filter(Boolean).join('');

    return '<div class="gc-list">' + controls.map(gcItem).join('') + '</div>' +
      (cards
        ? subHead('Resilience domains') +
          '<div class="cmp-row" style="grid-template-columns:repeat(2,1fr)">' + cards + '</div>'
        : '') +
      subHead('Observed recovery') +
      '<div class="bi-grid tight">' +
        '<div class="bi-cell' + (recovering ? '' : ' ok') + '">' +
          '<div class="bi-v">' + recovering + '</div>' +
          '<div class="bi-l">Incidents in recovery</div></div>' +
        '<div class="bi-cell">' +
          '<div class="bi-v">' + closed.length + '</div>' +
          '<div class="bi-l">Incidents closed this period</div></div>' +
        '<div class="bi-cell">' +
          '<div class="bi-v' + (meanHours == null ? ' nd' : '') + '">' +
            (meanHours == null ? 'No data' : meanHours + ' hrs') + '</div>' +
          '<div class="bi-l">Mean time to close</div></div>' +
      '</div>' +
      '<div class="rag-note">' +
        'No recovery-time or recovery-point objective is recorded in the platform, so ' +
        'this reports control attestation and observed incident-closure time rather ' +
        'than measured RTO or RPO attainment.' +
      '</div>';
  }

  // ── 14. Compliance Dashboard ──────────────────────────────────────────────

  var MAX_DOMAIN_ROWS = 11;

  /* ── Firewall Configuration Review ────────────────────────────────────────
   *
   * WHAT THIS SLIDE DELIBERATELY DOES NOT CONTAIN.
   *
   * No policy ids, no interface names, no tunnel names — none of the `evidence`
   * a finding carries internally. Together those are a working map of where
   * this client's firewall is weakest, and this deck is emailed, forwarded and
   * left on laptops. It is the same reason the portal withholds the
   * vulnerability finding list.
   *
   * The client gets what they need to act: the finding, how serious it is, and
   * what to do. The analyst tab has the detail for the conversation that
   * follows.
   */
  /**
   * Email Security Dashboard.
   *
   * ══ WHAT THIS SECTION DELIBERATELY DOES NOT CLAIM ══
   *
   * It does not report a percentage of mail blocked. The Acronis alert feed
   * counts threats, not messages scanned, so there is no denominator for that
   * figure and inventing one would put a number on a board slide that nobody
   * downstream could check. What is reported instead is CONTAINMENT — of the
   * threats whose outcome was stated, how many were stopped — and the size of
   * the population it was computed over travels with it, in the section body.
   *
   * It also carries no per-message detail: no subjects, no sender addresses, no
   * alert ids. Targeted MAILBOXES are named, because the client owns that data
   * and the whole operational point is knowing who to train. What is withheld
   * is the attacker's side of it, which is a working map of what gets through.
   */
  /* A finding's category label, from the rollup the audit carries. */
  function categoryLabelOf(key, audit) {
    if (!key) return 'Not categorised';
    var hit = (audit.byCategory || []).filter(function (c) { return c.key === key; })[0];
    return hit ? hit.label : key;
  }

  /* Where a category sits in report order; uncategorised sorts last. */
  function categoryRank(key, audit) {
    if (!key) return 999;
    var list = audit.byCategory || [];
    for (var i = 0; i < list.length; i++) if (list[i].key === key) return i;
    return 998;
  }

  function renderEmailSecurity(ctx) {
    var payload = ctx.data.email;
    var s = payload && payload.summary;
    if (!s) return null;

    var t = s.threats || {};
    var c = s.containment || {};

    // null is not zero. A containment rate of 0% says everything got through;
    // no data says nobody recorded an outcome. The tile shows the difference.
    var rate = c.rate == null ? 'No data' : c.rate + '%';

    var tiles = '<div class="bi-grid tight">' +
        '<div class="bi-cell"><div class="bi-v">' + esc(t.total || 0) + '</div>' +
          '<div class="bi-l">Email threats detected</div></div>' +
        '<div class="bi-cell"><div class="bi-v' + (c.rate == null ? ' nd' : '') + '">' +
          esc(rate) + '</div><div class="bi-l">Threats contained</div></div>' +
        '<div class="bi-cell"><div class="bi-v">' + esc(c.delivered || 0) + '</div>' +
          '<div class="bi-l">Reached a mailbox</div></div>' +
        '<div class="bi-cell"><div class="bi-v">' + esc(t.targetedUsers || 0) + '</div>' +
          '<div class="bi-l">People targeted</div></div>' +
      '</div>';

    var head = '<div class="rag-note" style="margin-bottom:4mm">' +
      'Over the last ' + esc(s.windowDays) + ' days, Acronis raised ' +
      '<strong>' + esc(t.total || 0) + '</strong> email security alert' +
      ((t.total || 0) === 1 ? '' : 's') + ' across <strong>' +
      esc(t.targetedUsers || 0) + '</strong> mailbox' +
      ((t.targetedUsers || 0) === 1 ? '' : 'es') + ', from ' +
      esc(t.senderDomains || 0) + ' sending domain' +
      ((t.senderDomains || 0) === 1 ? '' : 's') + '. ' +
      /*
       * The denominator, in the report and not only on the internal tab. A
       * board reading "98% contained" is entitled to know it was computed over
       * a third of the alerts, and this is the only place it will be told.
       */
      (c.knownDisposition
        ? 'The containment figure covers the ' + esc(c.knownDisposition) + ' alert' +
          (c.knownDisposition === 1 ? '' : 's') + ' that recorded an outcome' +
          (c.unknownDisposition
            ? '; ' + esc(c.unknownDisposition) + ' did not state one and ' +
              'are excluded rather than assumed blocked.'
            : ' — every alert in the period.')
        : 'No alert in this period recorded what happened to the message, so no ' +
          'containment figure can be given. This is a reporting gap rather than ' +
          'a clean period.') +
      ' These are counts of threats, not of mail volume: the alert feed does not ' +
      'report how many messages were scanned.</div>';

    var order = ['bec', 'phishing', 'malware', 'url', 'attachment', 'spam', 'dlp', 'unclassified'];
    var names = {
      bec: 'Business email compromise', phishing: 'Phishing', malware: 'Malware',
      url: 'Malicious link', attachment: 'Malicious attachment', spam: 'Spam / bulk',
      dlp: 'Data loss', unclassified: 'Unclassified',
    };
    var classRows = (s.byClass || []).slice().sort(function (a, b) {
      var ai = order.indexOf(a.label), bi = order.indexOf(b.label);
      return (ai < 0 ? 99 : ai) - (bi < 0 ? 99 : bi);
    }).map(function (r) {
      return { kind: names[r.label] || r.label, count: r.count };
    });

    var classTable = classRows.length ? D.dataTable({
      cols: [
        { label: 'Threat type', key: 'kind',  width: '60%' },
        { label: 'Detected',    key: 'count', width: '40%' },
      ],
      rows: classRows,
    }) : '';

    /*
     * Targeted mailboxes: the actionable half of this section. Named because
     * the client owns this data and because "three people absorbed 40% of the
     * phishing aimed at you" is the sentence that gets awareness training
     * budgeted.
     */
    var targets = (s.topRecipients || []).slice(0, 8);
    var targetTable = targets.length ? '<div class="sec-sub">Most targeted mailboxes</div>' +
      D.dataTable({
        cols: [
          { label: 'Mailbox',       key: 'label',     width: '60%' },
          { label: 'Threats aimed', key: 'count',     width: '20%' },
          { label: 'Reached inbox', key: 'delivered', width: '20%' },
        ],
        rows: targets,
      }) : '';

    return tiles + head + classTable + targetTable + sectionComment(ctx, 'emailSecurity');
  }

  /*
   * AI Visibility, from DNSFilter.
   *
   * AGGREGATES ONLY. The staff tab names the people using AI tools; this section
   * never reads that panel. A board pack travels, and a named employee's AI use
   * is an HR conversation, not a board finding.
   *
   * Every figure the source could not read renders as "No data", not 0: a
   * client whose DNSFilter reports were unreadable has not stopped using AI.
   */
  function renderAiUsage(ctx) {
    var s = ctx.data.ai;
    if (!s || !s.configured) return null;
    var u = envData(s.usage);
    var a = envData(s.apps);
    var p = envData(s.policy);
    if (!u && !a) return null;

    var lookups = u ? (u.allowed || 0) + (u.blocked || 0) : null;
    var blockedPct = u && lookups ? Math.round((u.blocked / lookups) * 100) : null;
    var rows = a && Array.isArray(a.rows) ? a.rows : [];
    var shadow = a ? (a.shadowCount || 0) : null;
    var unreviewed = a ? (a.unreviewedCount || 0) : null;

    var policies = p && Array.isArray(p.rows) ? p.rows : [];
    var known = policies.filter(function (r) { return r.aiBlocked !== null && r.aiBlocked !== undefined; });
    var blockedPolicies = known.filter(function (r) { return r.aiBlocked; }).length;
    var policyText = !known.length ? 'No data'
      : blockedPolicies === known.length ? 'Blocked'
      : blockedPolicies ? 'Partly blocked' : 'Allowed';

    var nd = function (v) { return v == null ? ' nd' : ''; };
    var tiles = '<div class="bi-grid tight">' +
        '<div class="bi-cell"><div class="bi-v' + nd(lookups) + '">' + esc(lookups == null ? 'No data' : lookups) + '</div>' +
          '<div class="bi-l">AI tool lookups</div></div>' +
        '<div class="bi-cell"><div class="bi-v' + nd(a ? rows.length : null) + '">' + esc(a ? rows.length : 'No data') + '</div>' +
          '<div class="bi-l">AI tools in use</div></div>' +
        '<div class="bi-cell"><div class="bi-v' + nd(shadow) + '">' + esc(shadow == null ? 'No data' : shadow) + '</div>' +
          '<div class="bi-l">Unsanctioned tools reached</div></div>' +
        '<div class="bi-cell"><div class="bi-v' + (known.length ? '' : ' nd') + '">' + esc(policyText) + '</div>' +
          '<div class="bi-l">Generative AI category</div></div>' +
      '</div>';

    var head = '<div class="rag-note" style="margin-bottom:4mm">' +
      'Over the last ' + esc(s.windowDays) + ' days, DNSFilter recorded ' +
      (lookups == null ? 'no readable AI usage figures' :
        '<strong>' + esc(lookups) + '</strong> lookup' + (lookups === 1 ? '' : 's') + ' to generative AI services' +
        (blockedPct == null ? '' : ', of which ' + esc(blockedPct) + '% were blocked')) +
      (u && u.sharePct != null ? ' (' + esc(u.sharePct) + '% of all DNS lookups)' : '') + '. ' +
      (a ? esc(rows.length) + ' distinct AI tool' + (rows.length === 1 ? ' was' : 's were') + ' seen; ' +
        esc(shadow) + (shadow === 1 ? ' is' : ' are') + ' marked unsanctioned but still reachable, and ' +
        esc(unreviewed) + ' ' + (unreviewed === 1 ? 'has' : 'have') + ' not yet been reviewed. ' : '') +
      'Counts are DNS lookups, which measure how often a tool is reached, not how much is shared with it.</div>';

    var labels = { sanctioned: 'Sanctioned', unsanctioned: 'Unsanctioned', under_review: 'Under review', unreviewed: 'Not yet reviewed' };
    var table = rows.length ? D.dataTable({
      cols: [
        { label: 'AI tool',  key: 'name',    width: '40%' },
        { label: 'Status',   key: 'state',   width: '24%' },
        { label: 'Lookups',  key: 'lookups', width: '18%' },
        { label: 'Blocked',  key: 'blocked', width: '18%' },
      ],
      rows: rows.slice(0, 8).map(function (r) {
        return { name: r.name, state: labels[r.status] || labels.unreviewed,
                 lookups: (r.allowed || 0) + (r.blocked || 0), blocked: r.blocked || 0 };
      }),
    }) : '';

    return tiles + head + table + sectionComment(ctx, 'aiUsage');
  }

  function renderFirewallAudit(ctx) {
    var payload = ctx.data.firewall;
    var a = payload && payload.audit;
    if (!a) return null;

    var findings = a.findings || [];
    var fails = findings.filter(function (f) { return f.status === 'fail'; });
    var na    = findings.filter(function (f) { return f.status === 'not-assessable'; });

    var order = { critical: 0, high: 1, medium: 2, low: 3 };
    /*
     * Severity first, then category, so the table opens with what matters most
     * rather than with whichever category happens to sort first. A board reads
     * the top three rows.
     */
    fails.sort(function (x, y) {
      var d = (order[x.severity] || 9) - (order[y.severity] || 9);
      if (d !== 0) return d;
      return categoryRank(x.category, a) - categoryRank(y.category, a);
    });

    var scoreLabel = a.score == null ? 'Not assessed' : a.score + '/100';

    var tiles = '<div class="bi-grid tight">' +
        '<div class="bi-cell"><div class="bi-v' + (a.score == null ? ' nd' : '') + '">' +
          esc(scoreLabel) + '</div><div class="bi-l">Configuration posture' +
          (a.band && a.band.label ? ' &middot; ' + esc(a.band.label) : '') + '</div></div>' +
        '<div class="bi-cell"><div class="bi-v">' + esc(a.failed) + '</div>' +
          '<div class="bi-l">Findings to address</div></div>' +
        '<div class="bi-cell"><div class="bi-v">' + esc(a.coverage) + '%</div>' +
          '<div class="bi-l">Benchmark coverage</div></div>' +
      '</div>';

    var device = a.device || {};
    var head = '<div class="rag-note" style="margin-bottom:4mm">Reviewed ' +
      (device.model ? '<strong>' + esc(device.model) + '</strong>' : 'the FortiGate') +
      (device.firmware ? ' running FortiOS <strong>' + esc(device.firmware) + '</strong>' : '') +
      ' against the CIS FortiGate Benchmark and Reflex\'s own checks. ' +
      esc(a.assessed) + ' of ' + esc(a.totalChecks) + ' checks could be evaluated ' +
      'from the configuration supplied.' +
      // The configuration is not kept, and the client should know that.
      ' The configuration file itself was not retained.</div>';

    /*
     * THE CATEGORY TABLE.
     *
     * This is what makes the section comparable with the firewall assessment
     * reports a client may already hold: the same five policy categories, each
     * with its own score, so the two documents can be read side by side.
     *
     * A category with nothing assessable prints "Not assessed", never 0. A zero
     * says the rulebase failed every check in that area; "not assessed" says we
     * could not look. Printing the first when the second is true is the single
     * easiest way for this report to mislead a board.
     */
    var cats = a.byCategory || [];
    var catTable = cats.length ? '<div class="sec-sub">Posture by category</div>' +
      D.dataTable({
        cols: [
          { label: 'Category', key: 'label', width: '34%' },
          { label: 'Score', key: 'score', width: '14%',
            raw: function (r) {
              return r.score == null
                ? '<span class="nd">Not assessed</span>'
                : esc(r.score) + '/100';
            } },
          { label: 'Findings', key: 'failed', width: '14%' },
          { label: 'Assessed', key: 'assessed', width: '18%',
            raw: function (r) {
              return esc(r.assessed) + ' of ' + esc(r.total) +
                (r.notAssessable
                  ? ' <span class="sev-sla">' + esc(r.notAssessable) + ' not assessable</span>'
                  : '');
            } },
          { label: 'What it covers', key: 'blurb', width: '20%',
            raw: function (r) { return esc(r.blurb || ''); } },
        ],
        rows: cats,
      }) + '<div class="rag-note" style="margin-bottom:4mm">Each category is ' +
      'scored on the checks that could be evaluated within it, using the same ' +
      'severity weighting as the overall score. A category showing ' +
      '&ldquo;Not assessed&rdquo; had nothing this configuration could answer — ' +
      'that is a gap in what we could see, not a clean result.</div>'
      : '';

    var table = fails.length ? D.dataTable({
      cols: [
        { label: 'Severity', key: 'severity', width: '14%',
          raw: function (r) {
            return '<span class="sev-dot" style="background:' +
              severityTone(r.severity.charAt(0).toUpperCase() + r.severity.slice(1)) +
              '"></span> ' + esc(r.severity.charAt(0).toUpperCase() + r.severity.slice(1));
          } },
        { label: 'Finding', key: 'title', width: '32%',
          raw: function (r) {
            return esc(r.title) +
              (r.cis ? '<span class="sev-sla">CIS ' + esc(r.cis) + '</span>' : '');
          } },
        { label: 'Category', key: 'category', width: '16%',
          raw: function (r) { return esc(categoryLabelOf(r.category, a)); } },
        { label: 'What to do', key: 'remediation', width: '38%',
          raw: function (r) { return esc(r.remediation || ''); } },
      ],
      rows: fails,
    }) : '<div class="rag-note">No findings. Every check that could be evaluated ' +
         'passed.</div>';

    /*
     * What could not be assessed, stated rather than omitted.
     *
     * A score computed over 22 of 30 checks is not the same claim as one
     * computed over all 30, and a reader who is not told cannot tell the
     * difference. Masking the config is the responsible thing for a client to
     * do, and this is what it costs.
     */
    var naNote = na.length
      ? '<div class="rag-note" style="margin-top:3mm">' + esc(na.length) +
        ' check' + (na.length === 1 ? '' : 's') + ' could not be assessed from the ' +
        'configuration supplied — either the section was absent or the values were ' +
        'password-masked. These are excluded from the score rather than counted ' +
        'against it, and are confirmed directly on the device.</div>'
      : '';

    var unreadNote = (a.unreadSections || []).length
      ? '<div class="rag-note">' + esc(a.unreadSections.length) + ' configuration ' +
        'section(s) were present but outside the scope of this review.</div>'
      : '';

    return tiles + head + catTable + table + naNote + unreadNote +
      sectionComment(ctx, 'firewallAudit');
  }

  function renderCompliance(ctx) {
    var g = grcData(ctx);
    if (!g) return null;

    var fw = g.frameworkScores || {};
    var cards = [
      { label: 'Overall self-assessment', score: g.assessment.grc_score },
      { label: 'NIST CSF',                score: fw.NIST_CSF },
      { label: 'CIS Controls v8',         score: fw.CIS_V8 },
    ].map(function (c) {
      var has  = c.score != null;
      var band = has ? scoreBand(c.score) : null;
      return '<div class="cmp-card">' +
          '<div class="cmp-head"><span class="cmp-t">' + esc(c.label) + '</span></div>' +
          '<div class="cmp-bar"><div class="cmp-fill" style="width:' + (has ? c.score : 0) +
            '%;background:' + (has ? band.color : '#D9D9D9') + '"></div></div>' +
          '<div class="cmp-score">' + (has ? c.score + '/100' : 'Not scored') + '</div>' +
          (has ? '<div class="cmp-d">' + esc(band.label) + '</div>' : '') +
        '</div>';
    }).join('');

    var scores = g.sectionScores || {};
    var rows = Object.keys(scores).sort().map(function (name) {
      var s = scores[name];
      return { domain: name, score: s.score, answered: s.answered, total: s.total };
    });

    function domainTable(subset) {
      return D.dataTable({
        cols: [
          { label: 'Domain', key: 'domain', width: '40%',
            raw: function (r) { return esc(truncate(r.domain, 42)); } },
          { label: 'Score', key: 'score', width: '26%',
            raw: function (r) {
              if (r.score == null) return '<span class="rag-unknown">Not assessed</span>';
              return '<div class="sb-bar"><div class="sb-fill" style="width:' + r.score +
                     '%;background:' + scoreBand(r.score).color + '"></div></div>';
            } },
          { label: 'Rating', key: 'rating', width: '20%',
            raw: function (r) { return r.score == null ? '&mdash;' : esc(scoreBand(r.score).label); } },
          { label: 'Answered', key: 'answered', width: '14%', cls: 'num',
            raw: function (r) { return r.answered + ' / ' + r.total; } },
        ],
        rows: subset,
      });
    }

    var note = '<div class="rag-note">' +
        'Point-in-time self-assessment' +
        (g.assessment.assessed_at ? ', assessed ' + esc(fmtShortDate(g.assessment.assessed_at)) : '') +
        '. One assessment is retained per client, so there is no prior assessment to ' +
        'compare against and no trend can be shown. Controls marked not applicable or ' +
        'left unanswered are excluded from every denominator.' +
      '</div>';

    var head = '<div class="cmp-row">' + cards + '</div>';
    if (!rows.length) return head + note;

    if (rows.length <= MAX_DOMAIN_ROWS) {
      return head + subHead('Control domains') + domainTable(rows) + note;
    }

    return [
      head + subHead('Control domains') + domainTable(rows.slice(0, MAX_DOMAIN_ROWS)),
      subHead('Control domains (continued)') + domainTable(rows.slice(MAX_DOMAIN_ROWS)) + note,
    ];
  }

  // ── 15. Executive Decisions and Recommendations ───────────────────────────

  function renderDecisions(ctx) {
    var decisions = deriveDecisions(ctx);
    var recs      = recommendationsBlock(ctx);
    if (!decisions.length && !recs) return null;

    var bodies = [];

    if (decisions.length) {
      bodies.push('<div class="rec-list">' +
        decisions.map(function (d) {
          var tone = PRIORITY_TONES[d.tone] || '#8C8C8C';
          return '<div class="rec-item" style="border-left-color:' + tone + '">' +
              '<div class="rec-body">' +
                '<div class="rec-area">' + esc(d.area) + '</div>' +
                '<div class="rec-text">' + esc(d.text) + '</div>' +
              '</div>' +
              '<div class="rec-meta">' +
                // Not everything here is a decision the board is OBLIGED to
                // take. A service they do not buy is an option to consider;
                // labelling it "Decision" beside an overdue risk remediation
                // puts a commercial suggestion and a control failure in the
                // same category, which is how a board learns to skim both.
                '<span class="rec-chip" style="background:' + tone + '">' +
                  esc(d.chip || 'Decision') + '</span>' +
                (d.impact ? '<span class="rec-impact">' + esc(d.impact) + '</span>' : '') +
              '</div>' +
            '</div>';
        }).join('') +
      '</div>' +
      '<div class="rag-note">Each item marked <strong>Decision</strong> needs a board ' +
        'decision: fund it, accept the risk, or revise the target.' +
        (decisions.some(function (d) { return d.chip === 'Option'; })
          ? ' Items marked <strong>Option</strong> are commercial choices, not ' +
            'findings — nothing is failing because they have not been taken up.'
          : '') +
      '</div>');
    }

    if (recs) bodies.push(subHead('Recommended actions') + recs);

    bodies[bodies.length - 1] += sectionComment(ctx, 'recommendations');
    return bodies.length === 1 ? bodies[0] : bodies;
  }

  /** Controls shown as gaps on the Identity dashboard before it gets crowded. */
  var MAX_IDENTITY_GAPS = 4;

  function renderExecRisk(ctx) {
    var areas = riskAreas(ctx);
    if (!areas.some(function (a) { return a.score != null; })) return null;
    return riskAreaTable(ctx, areas);
  }

  function renderObservations(ctx) { return observationBullets(ctx); }

  // Thin wrappers over the extracted blocks. The folded sections compose the
  // blocks directly; these keep the registry working unchanged.
  function renderMaturityTrend(ctx) { return maturityBlock(ctx); }
  function renderIrKpis(ctx) { return irKpiBlock(ctx); }
  function renderRemediation(ctx) { return remediationPages(ctx); }
  function renderTickets(ctx) { return ticketsBlock(ctx); }
  function renderVulns(ctx) { return topFindingsBlock(ctx); }
  function renderVulnExposure(ctx) { return vulnExposureBlock(ctx); }
  function renderRecommendations(ctx) { return recommendationsBlock(ctx); }
  function renderAwareness(ctx) { return awarenessBlock(ctx); }

  // ══════════════════════════════════════════════════════════════════════════
  // The board report, in reading order.
  //
  // Slide order IS array order. Ids are load-bearing: prefs.sections and
  // prefs.comments in localStorage are keyed on them, so a surviving section
  // keeps its id even when its label changes.
  // ══════════════════════════════════════════════════════════════════════════
  var SECTIONS = [
    { n: 1,  id: 'execSummary',        label: 'Executive Summary',                       group: 'Executive',
      services: null,          // always offered, whatever the client buys
      requires: [],
      optional: ['secureScore', 'secureScoreHistory', 'vulnFindings', 'mdr', 'awareness', 'vulnSummary'],
      render: renderExecSummary, commentable: true },

    { n: 2,  id: 'assuranceDashboard', label: 'Cybersecurity Assurance Dashboard',       group: 'Executive',
      services: null,          // always offered, whatever the client buys
      requires: ['secureScore'], optional: ['secureScoreHistory', 'mdr', 'edr'],
      render: renderAssuranceDashboard, commentable: true },

    /*
     * Sits right after the assurance dashboard, where the composite has just
     * been shown, so the reader meets the coverage caveat on the same spread
     * as the number it qualifies rather than twelve pages later.
     *
     * `services: null` — always OFFERED, whatever the client buys, because a
     * coverage statement is exactly the thing a narrow-service client needs.
     * It self-disables when no service mix has been recorded, so it costs
     * nothing on a client nobody has configured. Toggle it off in the Reports
     * tab to leave the overall score and the gap table out of the deck.
     */
    { n: 3,  id: 'serviceCoverage',     label: 'Service Coverage and Overall Score',      group: 'Executive',
      services: null,
      requires: ['secureScore'],
      render: renderServiceCoverage, commentable: true },

    { n: 4,  id: 'heatMap',            label: 'Cyber Risk Heat Map',                     group: 'Risk',
      services: ['viso'],
      requires: ['vulnFindings'],                  render: renderRiskHeatMap, commentable: true },

    { n: 5,  id: 'assurance',          label: 'Board Assurance Statement',               group: 'Executive',
      services: null,          // always offered, whatever the client buys
      requires: [],                                render: renderAssurance },

    { n: 6,  id: 'topRisks',           label: 'Top Cyber Risks',                         group: 'Risk',
      services: ['viso'],
      requires: ['vulnFindings'],                  render: renderTopRisks, commentable: true },

    { n: 7,  id: 'execRisk',           label: 'Risk Appetite Dashboard',                 group: 'Risk',
      services: ['viso'],
      requires: ['secureScore'], optional: ['edr', 'o365', 'vulnFindings', 'secureScoreHistory'],
      render: renderRiskAppetite, commentable: true },

    { n: 8,  id: 'businessImpact',     label: 'Business Impact Summary',                 group: 'Risk',
      services: ['viso'],
      requires: ['vulnFindings'],                  render: renderBusinessImpact, commentable: true },

    { n: 9,  id: 'threatLandscape',    label: 'Threat Landscape Overview',               group: 'Dashboards',
      services: ['mdr', 'edr', 'ndr', 'viso'],
      requires: ['vulnFindings'], optional: ['mdr'],
      render: renderThreatLandscape, commentable: true },

    { n: 10,  id: 'thirdParty',         label: 'Third-Party Risk Dashboard',              group: 'Dashboards',
      services: ['viso'],
      requires: [], optional: ['vendors', 'grcAssessment', 'grcQuestions', 'vulnFindings'],
      render: renderThirdPartyRisk },

    { n: 11, id: 'identityRisk',       label: 'Identity and Access Risk Dashboard',      group: 'Dashboards',
      services: ['identity', 'viso'],
      requires: [], optional: ['o365', 'grcAssessment', 'grcQuestions'],
      render: renderIdentityRisk },

    { n: 12, id: 'vulnDashboard',      label: 'Vulnerability Dashboard',                 group: 'Dashboards',
      services: ['vuln'],
      requires: ['vulnFindings'], optional: ['vulnSummary', 'vulnTrends'],
      render: renderVulnDashboard },

    { n: 13, id: 'humanRisk',          label: 'Human Risk Dashboard',                    group: 'Dashboards',
      services: ['awareness'],
      requires: ['awareness'], optional: ['grcAssessment', 'grcQuestions'],
      render: renderHumanRisk },

    { n: 14, id: 'resilience',         label: 'Recovery and Resilience Dashboard',       group: 'Dashboards',
      services: ['mdr', 'edr', 'viso'],
      requires: ['grcAssessment', 'grcQuestions'], optional: ['vulnFindings'],
      render: renderResilience },

    { n: 15, id: 'compliance',         label: 'Compliance Dashboard',                    group: 'Governance',
      services: ['viso'],
      requires: ['grcAssessment', 'grcQuestions'], render: renderCompliance },

    { n: 16, id: 'firewallAudit',      label: 'Firewall Configuration Review',           group: 'Dashboards',
      services: ['firewall'],
      requires: ['firewall'], render: renderFirewallAudit, commentable: true },

    { n: 17, id: 'emailSecurity',      label: 'Email Security Dashboard',                group: 'Dashboards',
      services: ['email'],
      requires: ['email'], render: renderEmailSecurity, commentable: true },

    { n: 18, id: 'aiUsage',            label: 'AI Usage Dashboard',                      group: 'Dashboards',
      services: ['ai_visibility'],
      requires: ['ai'], render: renderAiUsage, commentable: true },

    { n: 19, id: 'recommendations',    label: 'Executive Decisions and Recommendations', group: 'Executive',
      services: null,          // always offered, whatever the client buys
      requires: ['secureScore'], optional: ['vulnFindings'],
      render: renderDecisions, commentable: true },
  ];

  // ══════════════════════════════════════════════════════════════════════════
  // Which sections apply to which services
  // ══════════════════════════════════════════════════════════════════════════

  /**
   * The services that make a section relevant. null means "always relevant".
   *
   * Read from the section itself rather than a second lookup table, so a new
   * section cannot be added without someone deciding who it is for — a
   * separate map would just silently omit it.
   */
  function servicesForSection(id) {
    var sec = null;
    SECTIONS.forEach(function (s) { if (s.id === id) sec = s; });
    return sec ? (sec.services || null) : null;
  }

  /**
   * defaultSectionsFor(services) — the starting tick-state for a client.
   *
   * @param {Array<string>|null} services  what the client buys, or null when
   *        nobody has recorded it yet.
   * @returns {Object<string, boolean>} keyed by section id.
   *
   * THE null CASE IS NOT AN EDGE CASE. Most clients will be unconfigured on the
   * day this ships, and treating "not recorded" as "buys nothing" would quietly
   * reduce every one of their reports to four sections. Unknown therefore means
   * everything, which is exactly the behaviour that existed before.
   *
   * This sets a STARTING POINT. The analyst can tick anything back on; sections
   * are still self-disabling when their data is missing, so ticking a section
   * for a service the client does not buy costs nothing worse than a skip.
   */
  function defaultSectionsFor(services) {
    var known = Array.isArray(services);
    var out = {};

    SECTIONS.forEach(function (s) {
      if (!s.services) { out[s.id] = true; return; }   // always offered
      if (!known)      { out[s.id] = true; return; }   // not recorded => all
      out[s.id] = s.services.some(function (k) { return services.indexOf(k) >= 0; });
    });

    return out;
  }

  // Exported for the SLA test suite.
  SECTIONS.elapsedHoursBetween = elapsedHoursBetween;
  SECTIONS.phishingMetrics     = phishingMetrics;
  SECTIONS.servicesForSection  = servicesForSection;
  SECTIONS.defaultSectionsFor  = defaultSectionsFor;
  SECTIONS.draftObservations = draftObservations;
  SECTIONS.draftAssurance    = draftAssurance;
  SECTIONS.draftExecSummary  = draftExecSummary;
  SECTIONS.scoreBand         = scoreBand;
  SECTIONS.tileValue         = tileValue;
  SECTIONS.headlineScore     = headlineScore;
  // Every deck figure is derived from a tab's own data; nothing is attested by
  // hand, so the Reports tab has no manual-entry form to render.
  SECTIONS.MANUAL_METRICS    = [];

  return SECTIONS;
})();
