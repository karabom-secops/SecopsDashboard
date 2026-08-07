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
   * /api/vulns/latest-summary returns an ARRAY — one row per tenant for a
   * superadmin, a single row otherwise. Pick the row for the client being
   * reported on and hand back its flat summary object.
   */
  function vulnSummaryFor(ctx) {
    var rows = ctx.data.vulnSummary;
    if (!Array.isArray(rows) || !rows.length) return null;
    var row = rows.length === 1
      ? rows[0]
      : rows.filter(function (r) { return String(r.tenantId) === String(ctx.tenantId); })[0];
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
    { key: 'incidentResponse', label: 'Incident Response',  desc: 'Ticket resolution & speed' },
  ];

  function componentCard(c, comp) {
    var score  = Math.round(Number(comp.score) || 0);
    var weight = comp.weight != null ? Math.round(comp.weight * 100) + '%' : '';
    var band   = scoreBand(score);

    return '<div class="cmp-card">' +
        '<div class="cmp-head">' +
          '<span class="cmp-t">' + esc(c.label) + '</span>' +
          (weight ? '<span class="cmp-w">(' + esc(weight) + ')</span>' : '') +
        '</div>' +
        '<div class="cmp-bar">' +
          '<div class="cmp-fill" style="width:' + score + '%;background:' + band.color + '"></div>' +
        '</div>' +
        '<div class="cmp-score">' + score + '/100</div>' +
        '<div class="cmp-d">' + esc(c.desc) + '</div>' +
      '</div>';
  }

  /** The weighted breakdown row, or '' when no score data is available. */
  function componentRow(ctx) {
    var comps = (ctx.data.secureScore || {}).components;
    if (!comps) return '';

    var cards = COMPONENTS
      .filter(function (c) { return comps[c.key] && comps[c.key].score != null; })
      .map(function (c) { return componentCard(c, comps[c.key]); });

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

  function renderAwareness(ctx) {
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

  /** Days from first_seen_at within which a finding of each severity must be fixed. */
  var VULN_SLA_DAYS = { Critical: 7, High: 30, Medium: 90, Low: 180 };

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

  /** Normalise a vuln severity label to a VULN_SLA_DAYS key. */
  function sevKey(risk) {
    var t = titleCase(risk);
    return VULN_SLA_DAYS[t] !== undefined ? t : null;
  }

  // ── Remediation Tracker ───────────────────────────────────────────────────
  // Left column: what was closed out during the reporting period.
  // Right column: what is due in the month after it.
  //
  // Sources are the same combined payload the Remediation Tracker tab uses
  // (/api/remediation-tracker): vuln findings, pentest findings and risks.
  //
  // All three carry a target date: pentest findings and risks have one entered by
  // hand, vuln findings get one from the severity SLA (first detected + 1 week for
  // Critical, 2 weeks High, 1 month Medium, 2 months Low — see lib/vuln-parser.js).

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

  function renderRemediation(ctx) {
    var data = ctx.data.vulnFindings;
    if (!data) return null;

    var period = ctx.period;
    var next   = shiftPeriod(period, 1);
    if (!next) return null;

    var done     = collectRemediated(data, period);
    var upcoming = collectScheduled(data, next);
    if (!done.length && !upcoming.length) return null;

    var slaNote = 'Scan findings are dated by remediation SLA: Critical 1 week, High 2 weeks, ' +
                  'Medium 1 month, Low 2 months from first detection.';

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

  /** Effective tile value as a number, or null when neither set nor derived. */
  function tileNum(ctx, id) {
    var raw = tileValue(((ctx.data.metrics || {}).tiles) || {}, id);
    if (raw == null || raw === '') return null;
    var n = parseFloat(String(raw).replace(/[^0-9.\-]/g, ''));
    return isNaN(n) ? null : n;
  }

  /** Component scores from /api/secure-score, rounded. */
  function componentScores(ctx) {
    var c = (ctx.data.secureScore || {}).components || {};
    function s(k) {
      return c[k] && c[k].score != null ? Math.round(Number(c[k].score)) : null;
    }
    return {
      vulnerabilities:  s('vulnerabilities'),
      awareness:        s('awareness'),
      incidentResponse: s('incidentResponse'),
      overall: (ctx.data.secureScore || {}).score != null
        ? Math.round(Number(ctx.data.secureScore.score)) : null,
    };
  }

  /** The prior month's component scores from /api/secure-score/history. */
  function previousScores(ctx) {
    var h = ctx.data.secureScoreHistory;
    var rows = Array.isArray(h) ? h : (h && h.history) || [];
    // History is newest-first; [0] is the current month, [1] the comparison.
    var prev = rows[1];
    if (!prev) return {};
    return {
      vulnerabilities:  prev.vulnScore      != null ? Math.round(prev.vulnScore)      : null,
      awareness:        prev.awarenessScore != null ? Math.round(prev.awarenessScore) : null,
      incidentResponse: prev.mdrScore       != null ? Math.round(prev.mdrScore)       : null,
      overall:          prev.score          != null ? Math.round(prev.score)          : null,
    };
  }

  // ── Executive Risk Assessment ─────────────────────────────────────────────

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
        target: 90, basis: 'MFA, Conditional Access, modern auth & risk handling' },
      { label: 'Endpoint Protection',         score: (endpointMetrics(ctx) || {}).agentCurrency, prev: null,
        target: 98, basis: 'EDR agent currency' },
    ];
  }

  function renderExecRisk(ctx) {
    var areas = riskAreas(ctx);
    if (!areas.some(function (a) { return a.score != null; })) return null;

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
      '</div>';
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
        'incident worked to closure; material means critical or high severity.</div>';
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

  function renderVulnExposure(ctx) {
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
        if (age > VULN_SLA_DAYS[k]) b.overdue++; else withinSla++;
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
                   '<span class="sev-sla">' + VULN_SLA_DAYS[r.severity] + 'd SLA</span>';
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
   * Weights for the Identity Security composite. Each term is a measured ratio;
   * any term that is unavailable drops out and the rest are re-normalised, so a
   * partial signal still scores rather than dragging the result down.
   */
  var IDENTITY_WEIGHTS = {
    mfaRate:      0.40,
    caCoverage:   0.25,
    modernAuth:   0.20,
    riskHandled:  0.15,
  };

  /**
   * Identity posture from the Managed Office 365 tab (/api/o365/summary).
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

    var signins = (g && g.signins) || {};
    var risky   = (g && g.riskyUsers) || {};
    var legacy  = (signins.legacyAuth && signins.legacyAuth.total) || 0;
    var total   = signins.total || 0;

    var m = {
      // Sign-ins that required and satisfied multi-factor authentication.
      mfaRate: tallyShare(signins.authRequirement, function (l) {
        return l.indexOf('multifactor') !== -1;
      }),
      // Sign-ins a Conditional Access policy actually evaluated. 'notApplied'
      // is the real coverage gap: no policy looked at that sign-in.
      caCoverage: tallyShare(signins.caStatus, function (l) {
        return l !== 'notapplied' && l !== 'not applied';
      }),
      modernAuth: total ? pct(total - legacy, total) : null,
      // Flagged users that were remediated or dismissed rather than left open.
      riskHandled: tallyShare(risky.byState, function (l) {
        return l === 'remediated' || l === 'dismissed' || l === 'confirmedsafe';
      }),
      deviceCompliant: tallyShare(signins.deviceCompliance, function (l) {
        return l === 'true' || l === '1';
      }),

      legacyAuth:   total ? legacy : null,
      caFailures:   signins.caFailures != null ? signins.caFailures : null,
      riskyUsers:   risky.distinct != null ? risky.distinct : null,
      failedLogins: d && d.signins ? d.signins.failed : null,
    };

    // Weighted composite over whichever terms are actually measured.
    var num = 0, den = 0;
    Object.keys(IDENTITY_WEIGHTS).forEach(function (k) {
      if (m[k] == null) return;
      num += m[k] * IDENTITY_WEIGHTS[k];
      den += IDENTITY_WEIGHTS[k];
    });
    m.score      = den ? Math.round((num / den) * 10) / 10 : null;
    m.basedOn    = den ? Math.round((den / 1) * 100) / 100 : 0;
    m.termsUsed  = Object.keys(IDENTITY_WEIGHTS).filter(function (k) { return m[k] != null; });

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

  function renderControlCoverage(ctx) {
    var id  = identityMetrics(ctx);
    var ep  = endpointMetrics(ctx);
    if (!id && !ep) return null;

    var groups = [];

    if (id) {
      groups.push('<div class="cc-group">' +
        '<div class="cc-gh">Identity &mdash; Managed Office 365</div>' +
        '<div class="cc-items">' +
          ccItem('MFA-satisfied sign-ins', id.mfaRate, { unit: '%', target: 95 }) +
          ccItem('Conditional Access coverage', id.caCoverage, { unit: '%', target: 95 }) +
          ccItem('Modern auth coverage', id.modernAuth, { unit: '%', target: 99 }) +
          ccItem('Risky users handled', id.riskHandled, { unit: '%', target: 90 }) +
          ccItem('Compliant-device sign-ins', id.deviceCompliant, { unit: '%', target: 90 }) +
          ccItem('Legacy auth sign-ins', id.legacyAuth, { lowerIsBetter: true }) +
          ccItem('Users flagged at risk', id.riskyUsers, { lowerIsBetter: true }) +
          // Neither of these is a defect count, so neither is coloured as one:
          // a Conditional Access failure is a policy block working as intended,
          // and some failed sign-ins are expected in any population.
          ccItem('Conditional Access blocks', id.caFailures, {}) +
          ccItem('Failed sign-ins', id.failedLogins, {}) +
        '</div></div>');
    }

    if (ep) {
      groups.push('<div class="cc-group">' +
        '<div class="cc-gh">Endpoints &mdash; Managed EDR</div>' +
        '<div class="cc-items">' +
          ccItem('Endpoints protected', ep.protected, {}) +
          ccItem('Agent currency', ep.agentCurrency, { unit: '%', target: 98 }) +
          ccItem('Agents online', ep.online, { unit: '%', target: 95 }) +
          ccItem('Not reporting', ep.stale, { lowerIsBetter: true }) +
          ccItem('Endpoints with active threats', ep.infected, { lowerIsBetter: true }) +
        '</div></div>');
    }

    var window = ep && ep.windowDays ? ep.windowDays : null;
    var missing = id && id.termsUsed
      ? Object.keys(IDENTITY_WEIGHTS).filter(function (k) { return id.termsUsed.indexOf(k) === -1; })
      : [];

    return '<div class="cc-grid">' + groups.join('') + '</div>' +
      '<div class="rag-note">' +
        'Drawn from the Managed Office 365 and Managed EDR telemetry' +
        (window ? ' over a trailing ' + window + '-day window' : '') + '. ' +
        'Identity percentages are measured across the sign-ins that carry each ' +
        'field. These are sign-in outcomes, not directory configuration: they show ' +
        'whether MFA and Conditional Access <i>took effect</i>, not how many accounts ' +
        'are enrolled.' +
        (missing.length
          ? ' Not available from this tenant’s log fields: ' + esc(missing.join(', ')) + '.'
          : '') +
      '</div>';
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

    return '<div class="tl-wrap">' +
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
      '</div>';
  }

  // ── Detection & Response KPIs ─────────────────────────────────────────────

  /** Target hours to resolution by ticket severity. */
  var MDR_SLA_HOURS = { HIGH: 4, MEDIUM: 24, LOW: 72 };
  var SLA_TARGET_PCT = 95;

  function renderIrKpis(ctx) {
    var tickets = ((ctx.data.mdr || {}).tickets) || [];
    var period  = ctx.period;

    // /api/mdr aliases its columns to camelCase — see the ticket query in server.js.
    var raised   = tickets.filter(function (t) { return monthOf(t.createdAt) === period; });
    var resolved = tickets.filter(function (t) {
      return t.resolvedAt && monthOf(t.resolvedAt) === period;
    });

    var hours = [];
    var slaMet = 0, slaTotal = 0;
    resolved.forEach(function (t) {
      var a = new Date(t.createdAt), b = new Date(t.resolvedAt);
      if (isNaN(a.getTime()) || isNaN(b.getTime())) return;
      var h = (b.getTime() - a.getTime()) / 3600000;
      if (h < 0) return;
      hours.push(h);
      var target = MDR_SLA_HOURS[(t.severity || 'MEDIUM').toUpperCase()];
      if (target != null) { slaTotal++; if (h <= target) slaMet++; }
    });

    if (!raised.length && !resolved.length) return null;

    hours.sort(function (a, b) { return a - b; });
    var mttr   = hours.length ? hours.reduce(function (s, h) { return s + h; }, 0) / hours.length : null;
    var median = hours.length ? hours[Math.floor(hours.length / 2)] : null;
    var slaPct = slaTotal ? Math.round((slaMet / slaTotal) * 1000) / 10 : null;
    var resRate = raised.length ? Math.round((resolved.length / raised.length) * 1000) / 10 : null;

    // EDR carries its own mean-time-to-mitigate, which is the closest thing to a
    // detection-side measure available; the ticket feed has no detection stamp.
    var edr  = endpointMetrics(ctx) ? ctx.data.edr : null;
    var mttm = edr && edr.threats && edr.threats.mttmHours != null ? edr.threats.mttmHours : null;

    function hrs(v) {
      if (v == null) return '—';
      return v < 1 ? Math.round(v * 60) + ' min' : (Math.round(v * 10) / 10) + ' hrs';
    }

    var rows = [
      { kpi: 'Mean time to respond (MTTR)', target: '—',                    actual: hrs(mttr), ok: null },
      { kpi: 'Mean time to mitigate (EDR)', target: '—',                    actual: hrs(mttm), ok: null },
      { kpi: 'Median time to respond',      target: '—',                    actual: hrs(median), ok: null },
      { kpi: 'Resolution SLA achievement',  target: SLA_TARGET_PCT + ' %',  actual: slaPct == null ? '—' : slaPct + ' %',
        ok: slaPct == null ? null : slaPct >= SLA_TARGET_PCT },
      { kpi: 'Tickets raised',              target: '—',                    actual: String(raised.length), ok: null },
      { kpi: 'Tickets resolved',            target: '—',                    actual: String(resolved.length), ok: null },
      { kpi: 'Resolution rate',             target: '—',                    actual: resRate == null ? '—' : resRate + ' %', ok: null },
    ];

    return D.dataTable({
      cols: [
        { label: 'KPI',    key: 'kpi',    width: '46%' },
        { label: 'Target', key: 'target', width: '18%', cls: 'num' },
        { label: 'Actual', key: 'actual', width: '36%', cls: 'num',
          raw: function (r) {
            if (r.ok === null) return esc(r.actual);
            return '<span class="' + (r.ok ? 'rag-yes' : 'rag-no') + '">' + esc(r.actual) + '</span>';
          } },
      ],
      rows: rows,
    }) +
    '<div class="rag-note">Response time is measured from ticket creation to resolution. ' +
      'SLA targets: High ' + MDR_SLA_HOURS.HIGH + ' hrs, Medium ' + MDR_SLA_HOURS.MEDIUM +
      ' hrs, Low ' + MDR_SLA_HOURS.LOW + ' hrs. ' +
      'Mean time to detect is not reported: the ticket feed carries no detection ' +
      'timestamp, so mean time to mitigate from the EDR platform is shown instead.</div>';
  }

  // ── Security Maturity Trend ───────────────────────────────────────────────

  function renderMaturityTrend(ctx) {
    var now  = componentScores(ctx);
    var prev = previousScores(ctx);
    if (now.overall == null) return null;

    var prevLabel = periodName(shiftPeriod(ctx.period, -1));
    var thisLabel = periodName(ctx.period);

    var domains = [
      { label: 'Vulnerability Management', key: 'vulnerabilities',  target: MATURITY_TARGETS.vulnerabilities },
      { label: 'Security Awareness',       key: 'awareness',        target: MATURITY_TARGETS.awareness },
      { label: 'Incident Response',        key: 'incidentResponse', target: MATURITY_TARGETS.incidentResponse },
      { label: 'Secure Score',             key: 'overall',          target: MATURITY_TARGETS.overall },
    ];

    var rows = domains.map(function (d) {
      var cur = now[d.key], was = prev[d.key];
      var t = trendFor(cur, was);
      return {
        domain: d.label, prev: was, cur: cur, target: d.target, trend: t,
        gap: cur == null ? null : cur - d.target,
      };
    });

    return D.dataTable({
      cols: [
        { label: 'Domain', key: 'domain', width: '32%' },
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
    '<div class="rag-note">Gap is the distance from the agreed target score. ' +
      'A positive gap means the domain is at or above target.</div>';
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

  function renderRecommendations(ctx) {
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

  function renderObservations(ctx) {
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

  function renderTickets(ctx) {
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

  function renderVulns(ctx) {
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

  var REGISTRY = [
    { id: 'overview',     label: 'Managed Cybersecurity Overview', group: 'Stats',
      requires: ['metrics'],                     render: renderOverview },
    // `metrics` is not required — it only supplies an optional override for the
    // Secure Score gauge, and the section must still render without it.
    { id: 'awareness',    label: 'Managed Security Awareness',     group: 'Awareness',
      requires: ['awareness'],                   render: renderAwareness },
    { id: 'observations', label: 'Observations',                   group: 'MDR Tickets',
      requires: [],                              render: renderObservations },
    { id: 'tickets',      label: 'Tickets Activity',               group: 'MDR Tickets',
      requires: ['mdr'],                         render: renderTickets },
    { id: 'vulns',        label: 'Vulnerabilities',                group: 'Vulnerabilities',
      requires: ['vulnSummary', 'vulnFindings'], render: renderVulns },
    { id: 'remediation',  label: 'Remediation Tracker',            group: 'Vulnerabilities',
      requires: ['vulnFindings'],                render: renderRemediation },
    { id: 'recommendations', label: 'Recommendations',             group: 'Stats',
      requires: ['secureScore'],                 render: renderRecommendations },
  ];

  // Executive risk assurance sections. Ordered so the board-level view comes
  // first and the assurance statement closes the deck; SECTIONS above supplies
  // the operational detail in between.
  var EXEC_SECTIONS = [
    { id: 'execRisk',     label: 'Executive Risk Assessment',      group: 'Executive',
      requires: ['secureScore'], optional: ['edr', 'o365', 'vulnFindings', 'secureScoreHistory'],
      render: renderExecRisk,        order: 'lead' },
    { id: 'businessImpact', label: 'Business Impact Summary',      group: 'Executive',
      requires: ['vulnFindings'],                render: renderBusinessImpact,  order: 'lead' },
    { id: 'topRisks',     label: 'Top Cyber Risks',                group: 'Executive',
      requires: ['vulnFindings'],                render: renderTopRisks,        order: 'lead' },
    { id: 'vulnExposure', label: 'Vulnerability Exposure',         group: 'Executive',
      requires: ['vulnFindings'],                render: renderVulnExposure,    order: 'lead' },
    { id: 'controlCoverage', label: 'Cyber Defence Coverage',      group: 'Executive',
      requires: [], optional: ['edr', 'o365'],   render: renderControlCoverage, order: 'lead' },
    { id: 'threatLandscape', label: 'Threat Landscape',            group: 'Executive',
      requires: ['vulnFindings'],                render: renderThreatLandscape, order: 'lead' },
    { id: 'irKpis',       label: 'Detection & Response KPIs',      group: 'Executive',
      requires: ['mdr'], optional: ['edr'],      render: renderIrKpis,          order: 'lead' },
    { id: 'maturityTrend', label: 'Security Maturity Trend',       group: 'Executive',
      requires: ['secureScore'], optional: ['secureScoreHistory'],
      render: renderMaturityTrend,   order: 'lead' },
    { id: 'assurance',    label: 'Board Assurance Statement',      group: 'Executive',
      requires: [],                              render: renderAssurance,       order: 'tail' },
  ];

  // Executive sections bracket the operational ones: risk assurance up front,
  // the board statement last. Slide order is registry order.
  var ORDERED = []
    .concat(EXEC_SECTIONS.filter(function (s) { return s.order === 'lead'; }))
    .concat(REGISTRY)
    .concat(EXEC_SECTIONS.filter(function (s) { return s.order === 'tail'; }));

  ORDERED.draftObservations = draftObservations;
  ORDERED.draftAssurance    = draftAssurance;
  ORDERED.scoreBand         = scoreBand;
  ORDERED.tileValue         = tileValue;
  // Every deck figure is now derived from a tab's own data; nothing is attested
  // by hand, so the Reports tab has no manual-entry form to render.
  ORDERED.MANUAL_METRICS    = [];

  return ORDERED;
})();
