/* tab-email.js — Managed Email Security (Acronis).
 *
 * Threats stopped in mail, who was targeted, and what got through.
 *
 * ══ THE ONE THING TO KNOW BEFORE READING A NUMBER HERE ══
 *
 * Everything on this page is derived from ALERTS. The Acronis Alert Manager API
 * reports things that went wrong; it does not report how much mail was scanned.
 * So there is no "99.7% of messages blocked" figure on this page, because there
 * is no honest denominator for one — and a made-up denominator on a board slide
 * is not something a reader could ever catch.
 *
 * What this page does report is CONTAINMENT: of the threats whose outcome the
 * alert actually stated, how many were stopped rather than delivered. Its
 * denominator is printed beside it, every time.
 *
 * ══ HOW THE PAGE IS ORGANISED, AND WHY ══
 *
 * It used to be one long column: eight stat cards, two paragraphs of caveat,
 * a chart, five stacked breakdowns, then two hundred alert rows. The question
 * an analyst actually opens this tab with — "did anything reach a mailbox, and
 * whose?" — was a number near the top that nothing could be done with, and the
 * answer was somewhere in those two hundred rows.
 *
 * So: what happened, then what it was, then which messages. The alert list is
 * filtered THROUGH THE SERVER (it already took threatClass, disposition and
 * severity parameters that nothing ever sent), so a filter searches the whole
 * window rather than the page that happens to be loaded. The counts that can be
 * acted on are buttons that set those filters.
 *
 * Two rules the layout must not break:
 *   - the containment denominator stays beside the containment rate;
 *   - nothing is truncated silently. A capped list says it was capped.
 */

window.EmailTab = (function () {
  'use strict';

  var BASE = (function () {
    var base = document.querySelector('base');
    return base ? base.href : '/';
  })();

  function apiUrl(path) { return BASE + 'api/' + path; }

  /* The server caps at 500; this is what the tab asks for, and it is stated on
     screen whenever it is reached rather than quietly cutting the list off. */
  var ALERT_LIMIT = 200;

  var _summary = null;
  var _alerts  = [];
  var _days    = 30;
  var _err     = null;
  var _available = true;

  // Alert-list filters. The first three are sent to the server; _q is a
  // client-side narrowing of what came back, and the count line says so.
  var _fClass = '';
  var _fDisp  = '';
  var _fSev   = '';
  var _q      = '';
  var _expanded = {};   // alertId → true
  var _busy   = false;

  // Presentation order for threat classes, most severe first. 'unclassified' is
  // last and is NOT a threat kind — it is the classifier admitting a gap.
  var CLASS_LABELS = {
    bec:          'Business email compromise',
    phishing:     'Phishing',
    malware:      'Malware',
    url:          'Malicious link',
    attachment:   'Malicious attachment',
    spam:         'Spam / bulk',
    dlp:          'Data loss',
    unclassified: 'Unclassified',
  };
  var CLASS_ORDER = ['bec', 'phishing', 'malware', 'url', 'attachment', 'spam', 'dlp', 'unclassified'];

  var DISPOSITION_LABELS = {
    blocked:     'Blocked',
    quarantined: 'Quarantined',
    remediated:  'Remediated after delivery',
    delivered:   'Delivered',
    unknown:     'Not stated by the alert',
  };

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function tenantParam(sep) {
    var isSA = window.currentUser && window.currentUser.role === 'superadmin';
    if (!isSA || !window.globalTenantId) return '';
    return sep + 'tenantId=' + encodeURIComponent(window.globalTenantId);
  }

  function qs(extra) {
    var parts = ['days=' + encodeURIComponent(_days)];
    var isSA = window.currentUser && window.currentUser.role === 'superadmin';
    if (isSA && window.globalTenantId) {
      parts.push('tenantId=' + encodeURIComponent(window.globalTenantId));
    }
    if (extra) parts.push(extra);
    return '?' + parts.join('&');
  }

  /** The alert query, with whatever filters are set. */
  function alertsQs() {
    var extra = ['limit=' + ALERT_LIMIT];
    if (_fClass) extra.push('threatClass=' + encodeURIComponent(_fClass));
    if (_fDisp)  extra.push('disposition=' + encodeURIComponent(_fDisp));
    if (_fSev)   extra.push('severity=' + encodeURIComponent(_fSev));
    return qs(extra.join('&'));
  }

  function serverFiltered() { return !!(_fClass || _fDisp || _fSev); }
  function anyFilter() { return serverFiltered() || !!String(_q).trim(); }

  async function get(path) {
    var res = await fetch(apiUrl(path), { credentials: 'same-origin' });
    var j = await res.json().catch(function () { return null; });
    if (!res.ok) throw new Error((j && j.error) || ('HTTP ' + res.status));
    return j;
  }

  function fmtDate(v) {
    if (!v) return '—';
    var d = new Date(v);
    if (isNaN(d.getTime())) return '—';
    return d.toLocaleString('en-ZA', {
      day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit',
    });
  }

  function fmtDay(v) {
    if (!v) return '';
    var d = new Date(v);
    if (isNaN(d.getTime())) return String(v);
    return d.toLocaleDateString('en-ZA', { day: 'numeric', month: 'short' });
  }

  function humanise(v) {
    if (!v) return '—';
    return String(v).replace(/[_-]/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); });
  }

  function classLabel(key) {
    return CLASS_LABELS[key] || humanise(key);
  }

  function dispositionLabel(key) {
    return DISPOSITION_LABELS[key] || humanise(key);
  }

  // ── Rendering ─────────────────────────────────────────────────────────────

  /**
   * A number that might not exist.
   *
   * null renders as an em dash with a "no data" class, never as 0. A containment
   * rate of 0% means every threat got through; null means no alert stated an
   * outcome. Those must not look the same, and on this page they do not.
   */
  function num(v, suffix) {
    if (v === null || v === undefined) return '<span class="em-nd">—</span>';
    return esc(v) + (suffix || '');
  }

  function statCard(card) {
    var body =
      '<div class="stat-label">' + esc(card.label) + '</div>' +
      '<div class="stat-value">' + card.value + '</div>' +
      (card.sub ? '<div class="em-stat-sub">' + card.sub + '</div>' : '');
    /*
     * A count you can act on is a control. "Reached a mailbox: 3" was a dead
     * number — the next question is always "which three?", and answering it
     * meant reading two hundred rows by eye.
     */
    if (card.filter) {
      return '<button type="button" class="stat-card accent-' + card.accent +
        ' em-stat-btn" data-disposition="' + esc(card.filter) +
        '" title="Show these alerts">' + body +
        '<span class="em-stat-go">Show these ›</span></button>';
    }
    return '<div class="stat-card accent-' + card.accent + '">' + body + '</div>';
  }

  function statCards(s) {
    var t = s.threats;
    var c = s.containment;

    // Two tiers. The first four answer "how did we do"; the rest are context.
    var lead = [
      { label: 'Email threats detected (' + s.windowDays + 'd)', value: num(t.total), accent: 'blue' },
      { label: 'Stopped', value: num(c.contained), accent: 'green' },
      { label: 'Reached a mailbox', value: num(c.delivered),
        accent: c.delivered > 0 ? 'red' : 'green',
        filter: c.delivered > 0 ? 'delivered' : null },
      { label: 'Containment rate', value: num(c.rate, '%'), accent: 'green',
        sub: c.knownDisposition
          ? 'of ' + esc(c.knownDisposition) + ' alert(s) that stated an outcome'
          : '<span class="em-nd">no outcome was stated</span>' },
    ];

    var secondary = [
      { label: 'Pulled back after delivery', value: num(c.remediated), accent: 'amber',
        filter: c.remediated > 0 ? 'remediated' : null },
      { label: 'People targeted', value: num(t.targetedUsers), accent: 'amber' },
      { label: 'Sending domains', value: num(t.senderDomains), accent: 'blue' },
      { label: 'Unclassified threats', value: num(t.unclassified),
        accent: t.unclassified > 0 ? 'amber' : 'green' },
    ];

    return '<div class="stats-grid em-stats-lead">' + lead.map(statCard).join('') + '</div>' +
      '<div class="stats-grid em-stats-more">' + secondary.map(statCard).join('') + '</div>';
  }

  /**
   * The honesty block. Not an aside — it is placed directly under the numbers it
   * qualifies, because a containment rate computed over a third of the alerts is
   * a different claim from one computed over all of them, and the reader cannot
   * tell which they are looking at unless it says.
   */
  function denominatorNote(s) {
    var c = s.containment;

    var coverage = c.knownDisposition === 0
      ? '<div class="em-note em-warn"><strong>No containment rate can be shown.</strong> ' +
        'None of the ' + esc(s.threats.total) + ' alert(s) in this window stated what ' +
        'happened to the message. This is a reporting gap, not a clean month.</div>'
      : '<div class="em-note">The containment rate above is calculated over the ' +
        esc(c.knownDisposition) + ' of ' + esc(s.threats.total) + ' alert(s) that stated ' +
        'an outcome (' + num(c.coverage, '%') + ' of the window). ' +
        (c.unknownDisposition > 0
          ? esc(c.unknownDisposition) + ' alert(s) did not say what happened to the ' +
            'message and are excluded rather than assumed blocked.'
          : 'Every alert in the window stated an outcome.') +
        '</div>';

    return coverage +
      '<div class="em-note">' +
        '<strong>These are threat counts, not mail volume.</strong> Acronis reports ' +
        'alerts, not the number of messages scanned, so this page cannot show what ' +
        'share of all mail was clean. A percentage-of-all-mail figure has to come ' +
        'from the Acronis console or the mail platform itself.' +
      '</div>';
  }

  /**
   * Detected-vs-contained trend, drawn as inline SVG.
   *
   * Hand-drawn rather than Chart.js on purpose: this module renders its whole
   * page from a string, and a canvas chart in that flow needs destroy/recreate
   * bookkeeping on every re-render. It also means the renderer is assertable in
   * a test without a DOM that can paint.
   *
   * The bar behind is the day's total and the bar in front is what was stopped,
   * so the visible remainder is what was NOT stopped. That remainder is drawn in
   * the alarming colour and the stopped part in the reassuring one: it used to
   * be the other way round, with the part that mattered rendered as the faint
   * background of the part that did not.
   */
  function trendChart(daily) {
    if (!daily || !daily.length) return '';

    var max = daily.reduce(function (m, d) { return Math.max(m, d.count); }, 0);
    if (max === 0) {
      return '<h3 class="em-h">Daily volume</h3>' +
        '<div class="em-note">No email threats were detected in this window.</div>';
    }

    var W = 100, H = 30, n = daily.length;
    var bw = W / n;

    var bars = daily.map(function (d, i) {
      var x = i * bw;
      var total = (d.count / max) * H;
      var cont  = (d.contained / max) * H;
      var through = Math.max(0, d.count - d.contained);
      return '<rect x="' + (x + bw * 0.12).toFixed(2) + '" y="' + (H - total).toFixed(2) +
             '" width="' + (bw * 0.76).toFixed(2) + '" height="' + total.toFixed(2) +
             '" class="em-bar-total"><title>' + esc(d.date) + ': ' + esc(d.count) +
             ' detected, ' + esc(d.contained) + ' stopped, ' + esc(through) +
             ' not stopped or not stated</title></rect>' +
             '<rect x="' + (x + bw * 0.12).toFixed(2) + '" y="' + (H - cont).toFixed(2) +
             '" width="' + (bw * 0.76).toFixed(2) + '" height="' + cont.toFixed(2) +
             '" class="em-bar-contained"></rect>';
    }).join('');

    /*
     * Dates live in HTML beneath the chart, not inside it: the SVG is stretched
     * to the panel width (preserveAspectRatio="none"), which would stretch any
     * text drawn in it out of shape along with the bars.
     */
    var first = fmtDay(daily[0].date);
    var last  = fmtDay(daily[daily.length - 1].date);
    var mid   = daily.length > 2 ? fmtDay(daily[Math.floor(daily.length / 2)].date) : '';

    return '<h3 class="em-h">Daily volume</h3>' +
      '<div class="em-chart">' +
        '<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none" ' +
          'role="img" aria-label="Email threats detected per day, with the share stopped">' +
          bars + '</svg>' +
        '<div class="em-dates"><span>' + esc(first) + '</span>' +
          (mid ? '<span>' + esc(mid) + '</span>' : '') +
          '<span>' + esc(last) + '</span></div>' +
        '<div class="em-legend">' +
          '<span class="em-key em-k-contained"></span> Stopped ' +
          '<span class="em-key em-k-total"></span> Not stopped or not stated ' +
          '<span class="em-axis">Peak ' + esc(max) + '/day</span>' +
        '</div>' +
      '</div>';
  }

  function breakdown(title, rows, labelFn) {
    if (!rows || !rows.length) return '';
    var max = rows.reduce(function (m, r) { return Math.max(m, r.count); }, 0) || 1;
    return '<h3 class="em-h">' + esc(title) + '</h3>' +
      '<div class="em-bars">' + rows.map(function (r) {
        return '<div class="em-bar-row">' +
            '<span class="em-bar-l">' + esc(labelFn ? labelFn(r.label) : r.label) + '</span>' +
            '<span class="em-bar-track"><span class="em-bar-fill" style="width:' +
              ((r.count / max) * 100).toFixed(1) + '%"></span></span>' +
            '<span class="em-bar-n">' + esc(r.count) + '</span>' +
          '</div>';
      }).join('') + '</div>';
  }

  /** One breakdown in its own panel, so four of them can sit in a grid. */
  function card(html) {
    return html ? '<section class="em-card">' + html + '</section>' : '';
  }

  function byClassBlock(s) {
    // Sorted into a fixed severity order rather than by count, so the same kind
    // of threat sits in the same place from one month's screenshot to the next.
    var rows = (s.byClass || []).slice().sort(function (a, b) {
      var ai = CLASS_ORDER.indexOf(a.label), bi = CLASS_ORDER.indexOf(b.label);
      return (ai < 0 ? 99 : ai) - (bi < 0 ? 99 : bi);
    });
    return breakdown('By threat type', rows, classLabel);
  }

  function targetedBlock(s) {
    var rows = s.topRecipients || [];
    if (!rows.length) {
      return '<h3 class="em-h">Most targeted people</h3>' +
        '<div class="em-note">No alert in this window named a recipient.</div>';
    }
    return '<h3 class="em-h">Most targeted people</h3>' +
      '<p class="em-note">Who to aim the next awareness campaign at. ' +
      '&ldquo;Reached inbox&rdquo; counts threats that were delivered rather than stopped.</p>' +
      '<table class="data-table em-table"><thead><tr>' +
        '<th>Mailbox</th><th class="em-r">Threats</th><th class="em-r">Reached inbox</th>' +
      '</tr></thead><tbody>' +
      rows.map(function (r) {
        return '<tr>' +
          '<td>' + esc(r.label) + '</td>' +
          '<td class="em-r">' + esc(r.count) + '</td>' +
          '<td class="em-r' + (r.delivered > 0 ? ' em-bad' : '') + '">' +
            esc(r.delivered) + '</td>' +
        '</tr>';
      }).join('') + '</tbody></table>';
  }

  /**
   * Alert types Acronis sent that we did not read as email security.
   *
   * Usually correct and boring — backup and patching alerts share this API. It
   * is on the page anyway because the failure it guards against is silent: if
   * Acronis ships a new Advanced Email Security type, the only other symptom is
   * a chart that quietly stops rising. Folded shut, because "usually correct and
   * boring" does not deserve a screen of its own between the reader and the
   * alerts; the count stays visible on the summary line.
   */
  function unrecognisedBlock(s) {
    var rows = s.unrecognisedTypes || [];
    if (!rows.length) return '';
    return '<details class="em-unrec"><summary class="em-h em-sum">' +
      'Alert types not read as email security (' + esc(rows.length) + ')</summary>' +
      '<p class="em-note">Acronis raises backup, recovery and patching alerts through the ' +
      'same API, so most of these are correctly excluded. Check the list if a number ' +
      'above looks low — an email-security type missing from the classifier shows up ' +
      'here and nowhere else.</p>' +
      '<div class="em-types">' + rows.map(function (r) {
        return '<span class="em-type">' + esc(r.label) +
          '<span class="em-type-n">' + esc(r.count) + '</span></span>';
      }).join('') + '</div></details>';
  }

  // ── The alert list ────────────────────────────────────────────────────────

  function optionList(values, selected, labelFn) {
    return values.map(function (v) {
      return '<option value="' + esc(v.value) + '"' +
        (String(selected) === String(v.value) ? ' selected' : '') + '>' +
        esc(labelFn ? labelFn(v.value) : v.label) + '</option>';
    }).join('');
  }

  /**
   * Filters over the alert list.
   *
   * The options are built from THIS window's own tallies, so the list never
   * offers a filter that would come back empty — except by way of the free-text
   * box, which says how many it hid.
   */
  function alertTools(s) {
    var classes = (s.byClass || []).map(function (r) {
      return { value: r.label, label: classLabel(r.label) + ' (' + r.count + ')' };
    });
    var disps = (s.byDisposition || []).map(function (r) {
      return { value: r.label, label: dispositionLabel(r.label) + ' (' + r.count + ')' };
    });
    var sevs = (s.bySeverity || []).map(function (r) {
      return { value: r.label, label: humanise(r.label) + ' (' + r.count + ')' };
    });

    return '<div class="em-tools" id="em-alerts-tools">' +
      '<label class="em-f"><span>Type</span><select id="em-f-class" class="form-input">' +
        '<option value="">All types</option>' + optionList(classes, _fClass) +
      '</select></label>' +
      '<label class="em-f"><span>Outcome</span><select id="em-f-disp" class="form-input">' +
        '<option value="">All outcomes</option>' + optionList(disps, _fDisp) +
      '</select></label>' +
      (sevs.length ? '<label class="em-f"><span>Severity</span><select id="em-f-sev" class="form-input">' +
        '<option value="">All severities</option>' + optionList(sevs, _fSev) +
      '</select></label>' : '') +
      '<label class="em-f em-f-q"><span class="em-sr">Search alerts</span>' +
        '<input type="search" id="em-q" class="form-input" autocomplete="off" ' +
          'placeholder="Search recipient, sender or subject…" value="' + esc(_q) + '"></label>' +
      '<button type="button" class="em-clear" id="em-clear"' +
        (anyFilter() ? '' : ' hidden') + '>Clear filters</button>' +
      '</div>';
  }

  /** Rows left after the client-side search box. */
  function visibleAlerts() {
    var q = String(_q).trim().toLowerCase();
    if (!q) return _alerts;
    return _alerts.filter(function (a) {
      return [a.recipient, a.sender, a.subject, a.alertType, a.threatClass, a.disposition]
        .filter(Boolean).join(' ').toLowerCase().indexOf(q) >= 0;
    });
  }

  /**
   * What the list is showing, and what it is not.
   *
   * The old header said "Recent alerts (200)" whether the window held 200 or
   * 2,000 — a cap presented as a total. Every number here is stated against
   * something.
   */
  function alertCount(rows) {
    var total = _summary && _summary.threats ? _summary.threats.total : null;
    var bits = [];

    if (serverFiltered()) {
      bits.push('Showing ' + rows.length + ' matching alert' + (rows.length === 1 ? '' : 's'));
    } else if (total !== null && _alerts.length < total) {
      bits.push('Showing the most recent ' + _alerts.length + ' of ' + total);
    } else {
      bits.push('Showing ' + rows.length + ' alert' + (rows.length === 1 ? '' : 's'));
    }

    if (_alerts.length >= ALERT_LIMIT) {
      bits.push('capped at ' + ALERT_LIMIT + ' — narrow the window or the filters to see the rest');
    }
    if (String(_q).trim() && rows.length !== _alerts.length) {
      bits.push('the search hid ' + (_alerts.length - rows.length) + ' of the ' + _alerts.length + ' loaded');
    }

    return '<div class="em-count">' + esc(bits.join(' · ')) +
      (anyFilter() ? ' <button type="button" class="em-clear" id="em-clear-2">Clear filters</button>' : '') +
      '</div>';
  }

  function alertRow(a, i) {
    var disp = a.disposition;
    var dispCls = disp === 'delivered' ? 'em-bad' : disp ? 'em-good' : 'em-nd';
    var id = a.alertId != null ? String(a.alertId) : String(i);
    var open = !!_expanded[id];

    var main = '<tr class="em-row' + (open ? ' is-open' : '') + '" data-alert="' + esc(id) + '">' +
      '<td class="em-caret">' + (open ? '▾' : '▸') + '</td>' +
      '<td>' + esc(fmtDate(a.createdAt)) + '</td>' +
      '<td>' + esc(classLabel(a.threatClass || 'unclassified')) + '</td>' +
      '<td>' + esc(a.recipient || '—') + '</td>' +
      '<td>' + esc(a.sender || '—') + '</td>' +
      '<td class="em-subject">' + esc(a.subject || '—') + '</td>' +
      // An alert with no stated outcome says so, rather than showing a blank
      // cell that reads as "nothing happened".
      '<td class="' + dispCls + '">' +
        esc(DISPOSITION_LABELS[disp] || (disp ? humanise(disp) : 'Not stated')) + '</td>' +
    '</tr>';

    if (!open) return main;

    /*
     * The subject is clamped in the row because it is attacker-authored and can
     * be arbitrarily long. Clamping it was all the page ever did with it, so the
     * full text was unreadable; here it wraps, still escaped.
     */
    var fields = [
      ['Subject', a.subject || '—'],
      ['Recipient', a.recipient || '—'],
      ['Sender', a.sender || '—'],
      ['Acronis alert type', a.alertType || '—'],
      ['Severity', a.severity ? humanise(a.severity) : '—'],
      ['Status', a.status ? humanise(a.status) : '—'],
      ['First seen', fmtDate(a.createdAt)],
      ['Last updated', fmtDate(a.updatedAt)],
      ['Resolved', a.resolvedAt ? fmtDate(a.resolvedAt) : 'Not resolved'],
      ['Alert id', a.alertId || '—'],
    ];

    return main + '<tr class="em-detail"><td></td><td colspan="6"><dl class="em-dl">' +
      fields.map(function (f) {
        return '<dt>' + esc(f[0]) + '</dt><dd>' + esc(f[1]) + '</dd>';
      }).join('') + '</dl></td></tr>';
  }

  function alertsTable() {
    var rows = visibleAlerts();

    if (!_alerts.length) {
      return alertCount(rows) +
        '<div class="em-note">' +
        (serverFiltered()
          ? 'No alert in this window matches these filters.'
          : 'No email alerts in this window.') + '</div>';
    }
    if (!rows.length) {
      return alertCount(rows) +
        '<div class="em-note">Nothing in the loaded alerts matches that search.</div>';
    }

    return alertCount(rows) +
      '<div class="em-scroll"><table class="data-table em-table"><thead><tr>' +
        '<th></th><th>When</th><th>Type</th><th>Recipient</th><th>Sender</th>' +
        '<th>Subject</th><th>Outcome</th>' +
      '</tr></thead><tbody>' +
      rows.map(alertRow).join('') + '</tbody></table></div>';
  }

  function alertsBlock(s) {
    return '<h3 class="em-h">Alerts</h3>' +
      '<p class="em-note">Every alert Acronis raised in this window. The three ' +
      'dropdowns filter on the server, so they search the whole window; the ' +
      'search box narrows what is loaded below. Click a row for the full subject.</p>' +
      alertTools(s) +
      '<div id="em-alerts-panel">' + alertsTable() + '</div>';
  }

  // ── Chrome ────────────────────────────────────────────────────────────────

  /**
   * Whether these numbers were ever collected.
   *
   * A client whose Acronis integration has never run has no alerts, and every
   * counter on this page would read 0 — "no threats" rather than "we have not
   * looked". Same rule as everywhere else here: not recorded is not none.
   */
  function neverCollected(s) {
    return !s || !s.sync || !s.sync.last_synced_at;
  }

  function syncStrip(s) {
    var sync = s && s.sync;
    if (!sync) {
      return '<div class="em-strip em-warn">⚠ No Acronis integration is configured for ' +
        'this client. Set it up under Admin &rarr; Integrations.</div>';
    }
    if (!sync.last_synced_at) {
      return '<div class="em-strip em-warn">⚠ Configured, but nothing has been collected yet. ' +
        'Press Sync Now on the Acronis card under Admin &rarr; Integrations.</div>';
    }
    var bad = sync.last_sync_status && sync.last_sync_status !== 'ok';
    return '<div class="em-strip' + (bad ? ' em-warn' : '') + '">' +
      (bad ? '✗' : '✓') + ' Last synced ' + esc(fmtDate(sync.last_synced_at)) +
      (bad && sync.last_sync_message ? ' — ' + esc(sync.last_sync_message) : '') +
      '</div>';
  }

  function rangePicker() {
    var opts = [7, 30, 90, 180, 365];
    return '<label class="em-range">Window ' +
      '<select id="em-range" class="form-input">' +
        opts.map(function (d) {
          return '<option value="' + d + '"' + (d === _days ? ' selected' : '') + '>' +
            d + ' days</option>';
        }).join('') +
      '</select></label>';
  }

  function render() {
    var host = document.getElementById('tab-email');
    if (!host) return;

    var head = '<div class="page-head"><h2>Managed Email Security</h2>' +
      '<p class="page-sub">Email threats detected by Acronis — what was stopped, ' +
      'what reached a mailbox, and who is being targeted.</p></div>';

    var body;
    if (_err) {
      body = '<div class="em-note em-warn">Could not load email security data: ' +
        esc(_err) + '</div>';
    } else if (!_available) {
      // The migration has not been run. Distinct from "no data" and it says so —
      // otherwise someone spends an afternoon debugging an integration that was
      // never the problem.
      body = '<div class="em-note em-warn">Email security storage is not set up on ' +
        'this database yet. Run <code>db/migrate-email-security.sql</code>, then ' +
        'configure the Acronis integration under Admin &rarr; Integrations.</div>';
    } else if (!_summary) {
      body = '<div class="em-note">Select a client to see their email security posture.</div>';
    } else if (neverCollected(_summary)) {
      // Deliberately NOT the stat cards: eight zeros would be a claim about this
      // client's mail, and nothing has been read to support it.
      body = syncStrip(_summary) +
        '<div class="em-note">Nothing has been collected for this client yet, so there ' +
        'are no figures to show. This is not the same as a month with no threats — ' +
        'once a sync has run, a quiet month will show zeros here.</div>';
    } else {
      body = syncStrip(_summary) +
        statCards(_summary) +
        denominatorNote(_summary) +
        trendChart(_summary.daily) +
        '<div class="em-grid">' +
          card(byClassBlock(_summary)) +
          card(breakdown('By outcome', _summary.byDisposition, dispositionLabel)) +
          card(breakdown('By severity', _summary.bySeverity, humanise)) +
          card(breakdown('Top sending domains', _summary.topSenderDomains)) +
        '</div>' +
        card(targetedBlock(_summary)) +
        alertsBlock(_summary) +
        unrecognisedBlock(_summary);
    }

    host.innerHTML = head +
      '<div class="em-toolbar">' + rangePicker() +
        '<button type="button" class="btn btn-sm" id="em-refresh">Refresh</button>' +
      '</div>' +
      '<div class="em-body">' + body + '</div>';

    wire();
  }

  /** Redraw only the list, so the filter controls keep focus and caret. */
  function renderAlertsPanel() {
    var panel = document.getElementById('em-alerts-panel');
    if (!panel) return;
    panel.innerHTML = alertsTable();
    var clear = document.getElementById('em-clear');
    if (clear) clear.hidden = !anyFilter();
    wireAlertRows();
  }

  function wireAlertRows() {
    document.querySelectorAll('#tab-email .em-row').forEach(function (tr) {
      tr.onclick = function () {
        var id = tr.dataset.alert;
        if (_expanded[id]) delete _expanded[id]; else _expanded[id] = true;
        renderAlertsPanel();
      };
    });
    ['em-clear', 'em-clear-2'].forEach(function (id) {
      var el = document.getElementById(id);
      if (el) el.onclick = clearFilters;
    });
  }

  function clearFilters() {
    _fClass = ''; _fDisp = ''; _fSev = ''; _q = '';
    reloadAlerts();
  }

  /** Re-fetch the alert list with the current filters, then redraw just it. */
  async function reloadAlerts() {
    if (_busy) return;
    _busy = true;
    var panel = document.getElementById('em-alerts-panel');
    if (panel) panel.innerHTML = '<div class="em-note">Loading alerts…</div>';
    try {
      _alerts = (await get('email/alerts' + alertsQs())) || [];
    } catch (err) {
      _alerts = [];
    } finally {
      _busy = false;
    }
    // The selects show the filter state, so they are redrawn with it.
    render();
  }

  function wire() {
    var sel = document.getElementById('em-range');
    if (sel) {
      sel.onchange = function () {
        _days = parseInt(sel.value, 10) || 30;
        _expanded = {};
        loadAndRender();
      };
    }

    var refresh = document.getElementById('em-refresh');
    if (refresh) refresh.onclick = function () { loadAndRender(); };

    var fc = document.getElementById('em-f-class');
    if (fc) fc.onchange = function () { _fClass = fc.value; reloadAlerts(); };
    var fd = document.getElementById('em-f-disp');
    if (fd) fd.onchange = function () { _fDisp = fd.value; reloadAlerts(); };
    var fs = document.getElementById('em-f-sev');
    if (fs) fs.onchange = function () { _fSev = fs.value; reloadAlerts(); };

    // Typing never re-renders the input it is typed into.
    var q = document.getElementById('em-q');
    if (q) q.oninput = function () { _q = q.value; renderAlertsPanel(); };

    document.querySelectorAll('#tab-email .em-stat-btn').forEach(function (b) {
      b.onclick = function () {
        _fDisp = b.dataset.disposition;
        _fClass = ''; _fSev = ''; _q = '';
        reloadAlerts().then(function () {
          var el = document.getElementById('em-alerts-panel');
          if (el && el.scrollIntoView) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });
      };
    });

    wireAlertRows();
  }

  async function loadAndRender() {
    var host = document.getElementById('tab-email');
    if (!host) return;
    _err = null;

    try {
      var payload = await get('email/summary' + qs());

      // null means "superadmin with no client selected" — a UI state, not an
      // error, and not an empty dataset either.
      if (payload === null) {
        _summary = null; _alerts = []; _available = true;
        render();
        return;
      }

      _available = payload.available !== false;
      _summary   = payload.summary || null;

      // The alert list is supporting detail. Losing it must not blank the
      // headline numbers that did load.
      try { _alerts = _available ? (await get('email/alerts' + alertsQs())) || [] : []; }
      catch (err) { _alerts = []; }

      render();
    } catch (err) {
      _err = err.message;
      render();
    }
  }

  return {
    loadAndRender: loadAndRender,
    // Seams for the test harness.
    _render: render,
    _apiUrl: apiUrl,
    _statCards: statCards,
    _denominatorNote: denominatorNote,
    _alertsTable: alertsTable,
    _targetedBlock: targetedBlock,
    _unrecognisedBlock: unrecognisedBlock,
    _trendChart: trendChart,
    _classLabel: classLabel,
    _alertsQs: alertsQs,
    _alertCount: alertCount,
    _neverCollected: neverCollected,
    _syncStrip: syncStrip,
    _setSummary: function (s) { _summary = s; },
    _setAlerts: function (a) { _alerts = a; },
    _setAvailable: function (v) { _available = v; },
    _setFilters: function (f) {
      f = f || {};
      _fClass = f.threatClass || '';
      _fDisp  = f.disposition || '';
      _fSev   = f.severity || '';
      _q      = f.q || '';
      if (f.expanded) _expanded = f.expanded;
    },
  };
})();
