'use strict';

/**
 * Section registry for the client report deck.
 *
 * Each entry declares the data it needs (`requires`, resolved to URLs by the
 * DATA_SOURCES map in tab-reports.js) and returns a slide body as an HTML
 * string. Returning null self-disables the section — the generator then skips
 * it without consuming a page number.
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
        awarenessTable('Last 3 Sessions', sessions, totals.sessions, allTime.sessions) +
      '</div>' +
      '<div>' +
        awarenessTable('Last 3 Quizzes', quizzes, totals.quizzes, allTime.quizzes) +
      '</div>';

    return html;
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

  function remediationTable(rows, dateLabel) {
    if (!rows.length) return null;
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
      rows: rows.slice(0, MAX_REMEDIATION_ROWS),
    });
  }

  function remediationColumn(heading, sub, rows, dateLabel, emptyMsg, caveat) {
    var table = remediationTable(rows, dateLabel);
    return '<div class="rem-col">' +
        '<div class="rem-h">' + esc(heading) + '</div>' +
        '<div class="rem-sub">' + esc(sub) + '</div>' +
        (table || '<div class="rem-empty">' + esc(emptyMsg) + '</div>') +
        (rows.length > MAX_REMEDIATION_ROWS
          ? '<div class="rem-more">+ ' + (rows.length - MAX_REMEDIATION_ROWS) +
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

    return '<div class="rem-cols">' +
        remediationColumn(
          'Remediated', 'Closed out during ' + periodName(period),
          done, 'Closed',
          'Nothing was closed out during ' + periodName(period) + '.') +
        remediationColumn(
          'Scheduled', 'Due during ' + periodName(next),
          upcoming, 'Due',
          'Nothing is currently scheduled for ' + periodName(next) + '.',
          'Scan findings are dated by remediation SLA: Critical 1 week, High 2 weeks, ' +
          'Medium 1 month, Low 2 months from first detection.') +
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

  REGISTRY.draftObservations = draftObservations;
  REGISTRY.scoreBand         = scoreBand;
  REGISTRY.tileValue         = tileValue;

  return REGISTRY;
})();
