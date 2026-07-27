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
  // Budget: ~130mm of body height per slide. A ticket row wraps to at most 3
  // lines at 105 chars in a 39%-wide column, so 7 rows fit with headroom.
  var MAX_AWARENESS_ROWS = 3;
  var MAX_TICKET_ROWS    = 7;
  var MAX_VULN_ROWS      = 9;
  var MAX_DESC_CHARS     = 105;

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

  var CULTURE_BANDS = [
    { max: 60,       label: 'Vulnerable' },
    { max: 70,       label: 'At Risk'    },
    { max: 90,       label: 'Strong'     },
    { max: Infinity, label: 'Excellent'  },
  ];

  function cultureRating(score) {
    for (var i = 0; i < CULTURE_BANDS.length; i++) {
      if (score < CULTURE_BANDS[i].max) return CULTURE_BANDS[i].label;
    }
    return 'Excellent';
  }

  // ── Slide 2: Managed Cybersecurity Overview ───────────────────────────────

  var ICONS = {
    coverage:      '<svg class="ov-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M12 2 4 5v6c0 5 3.4 9.3 8 11 4.6-1.7 8-6 8-11V5l-8-3z"/><path d="M9 12l2 2 4-4"/></svg>',
    tickets:       '<svg class="ov-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    observations:  '<svg class="ov-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z"/><circle cx="12" cy="12" r="3"/></svg>',
    investigations:'<svg class="ov-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.7" y2="16.7"/></svg>',
    incidents:     '<svg class="ov-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="3" y="4" width="18" height="16" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="12" y1="13" x2="12" y2="16"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>',
  };

  function overviewCard(icon, title, desc, valueHtml) {
    return '<div class="ov-card">' +
        icon +
        '<div class="ov-t">' + esc(title) + '</div>' +
        '<div class="ov-d">' + esc(desc) + '</div>' +
        valueHtml +
      '</div>';
  }

  function pill(value, tone) {
    if (value == null) return '<div class="ov-nodata">no data</div>';
    return '<div class="ov-pill ' + tone + '">' + esc(value) + '</div>';
  }

  function bigNumber(value, compact) {
    if (value == null) return '<div class="ov-nodata">no data</div>';
    var shown = compact && /^\d+$/.test(value) ? compactNumber(value) : value;
    return '<div class="ov-num">' + esc(shown) + '</div>';
  }

  function renderOverview(ctx) {
    var tiles = (ctx.data.metrics || {}).tiles;
    if (!tiles) return null;

    var coverage = tileValue(tiles, 'coverageScore');
    if (coverage != null && /^\d+(\.\d+)?$/.test(coverage)) coverage = coverage + '%';

    return '<div class="ov-row top">' +
        overviewCard(ICONS.coverage, 'Coverage Score',
          'The Coverage Score represents your engagement with the MDR service.',
          pill(coverage, 'green')) +
        overviewCard(ICONS.tickets, 'Open Tickets',
          'The number of open tickets that still require action.',
          pill(tileValue(tiles, 'openTickets'), 'amber')) +
      '</div>' +
      '<div class="ov-row bot">' +
        overviewCard(ICONS.observations, 'Observations',
          'Number of data points we received from your environment.',
          bigNumber(tileValue(tiles, 'observations'), true)) +
        overviewCard(ICONS.investigations, 'Investigations',
          'Potential incidents that were examined from your environment.',
          bigNumber(tileValue(tiles, 'investigations'), false)) +
        overviewCard(ICONS.incidents, 'Ticketed Incidents',
          'Security incidents brought to your attention.',
          bigNumber(tileValue(tiles, 'ticketedIncidents'), false)) +
      '</div>';
  }

  // ── Slide 3: Managed Security Awareness ───────────────────────────────────

  function awarenessTable(caption, rows, totals) {
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
    return D.dataTable({
      caption:  caption,
      cols:     cols,
      rows:     rows.slice(0, MAX_AWARENESS_ROWS),
      totalRow: rows.length ? totals : null,
    });
  }

  function cultureLegend() {
    return '<div class="gauge-legend">' +
        '<div class="lg-h">Score</div>' +
        '<table>' +
          '<tr><td>&lt; 60</td><td>Vulnerable</td></tr>' +
          '<tr><td>&lt; 70</td><td>At Risk</td></tr>' +
          '<tr><td>&lt; 90</td><td>Strong</td></tr>' +
          '<tr><td>&gt; 90</td><td>Excellent</td></tr>' +
        '</table>' +
      '</div>';
  }

  function renderAwareness(ctx) {
    var a = ctx.data.awarenessSummary;
    if (!a) return null;
    if (!(a.sessions || []).length && !(a.quizzes || []).length) return null;

    // A manual override on the culture tile wins over the derived score.
    var overrideScore = tileValue(((ctx.data.metrics || {}).tiles) || {}, 'cultureScore');
    var score = overrideScore != null && /^\d+(\.\d+)?$/.test(overrideScore)
      ? Number(overrideScore)
      : (a.culture ? a.culture.derivedScore : null);

    // Height budget is tight: two 4-row tables plus the gauge must fit ~136mm of
    // body with overflow:hidden. Drop the gauge rather than crop it if both
    // tables are full.
    var html =
      '<div style="margin-bottom:4mm">' +
        awarenessTable('Last 3 Sessions', a.sessions || [], (a.totals || {}).sessions) +
      '</div>' +
      '<div style="margin-bottom:3.5mm">' +
        awarenessTable('Last 3 Quizzes', a.quizzes || [], (a.totals || {}).quizzes) +
      '</div>';

    if (score != null) {
      html +=
        '<div class="dt-cap">Secure Culture Score</div>' +
        '<div class="gauge-wrap">' +
          D.gaugeSemi(score, { rating: cultureRating(score), pxWidth: 49 }) +
          cultureLegend() +
        '</div>';
    }

    return html;
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

    var a = ctx.data.awarenessSummary;
    if (a && a.totals && a.totals.sessions && a.totals.sessions.assigned) {
      var pct = a.totals.sessions.completionPct;
      lines.push('Security awareness session completion stands at ' + pct + '%' +
        (pct < 70 ? ', which remains below the 70% target — manager follow-up is recommended.' : '.'));
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
    // culture score, and the section must still render without it.
    { id: 'awareness',    label: 'Managed Security Awareness',     group: 'Awareness',
      requires: ['awarenessSummary'],            render: renderAwareness },
    { id: 'observations', label: 'Observations',                   group: 'MDR Tickets',
      requires: [],                              render: renderObservations },
    { id: 'tickets',      label: 'Tickets Activity',               group: 'MDR Tickets',
      requires: ['mdr'],                         render: renderTickets },
    { id: 'vulns',        label: 'Vulnerabilities',                group: 'Vulnerabilities',
      requires: ['vulnSummary', 'vulnFindings'], render: renderVulns },
  ];

  REGISTRY.draftObservations = draftObservations;
  REGISTRY.cultureRating     = cultureRating;
  REGISTRY.tileValue         = tileValue;

  return REGISTRY;
})();
