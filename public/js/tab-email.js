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
 */

window.EmailTab = (function () {
  'use strict';

  var BASE = (function () {
    var base = document.querySelector('base');
    return base ? base.href : '/';
  })();

  function apiUrl(path) { return BASE + 'api/' + path; }

  var _summary = null;
  var _alerts  = [];
  var _types   = [];
  var _days    = 30;
  var _err     = null;
  var _available = true;

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

  function humanise(v) {
    if (!v) return '—';
    return String(v).replace(/[_-]/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); });
  }

  function classLabel(key) {
    return CLASS_LABELS[key] || humanise(key);
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

  function statCards(s) {
    var t = s.threats;
    var c = s.containment;

    var cards = [
      { label: 'Email threats detected (' + s.windowDays + 'd)', value: num(t.total), accent: 'blue' },
      { label: 'Stopped', value: num(c.contained), accent: 'green' },
      { label: 'Reached a mailbox', value: num(c.delivered),
        accent: c.delivered > 0 ? 'red' : 'green' },
      { label: 'Pulled back after delivery', value: num(c.remediated), accent: 'amber' },
      { label: 'Containment rate', value: num(c.rate, '%'), accent: 'green' },
      { label: 'People targeted', value: num(t.targetedUsers), accent: 'amber' },
      { label: 'Sending domains', value: num(t.senderDomains), accent: 'blue' },
      { label: 'Unclassified threats', value: num(t.unclassified),
        accent: t.unclassified > 0 ? 'amber' : 'green' },
    ];

    return '<div class="stats-grid">' + cards.map(function (card) {
      return '<div class="stat-card accent-' + card.accent + '">' +
        '<div class="stat-label">' + esc(card.label) + '</div>' +
        '<div class="stat-value">' + card.value + '</div></div>';
    }).join('') + '</div>';
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
      // Detected drawn behind, contained in front: the visible remainder is what
      // was NOT contained, which is the part worth looking at.
      return '<rect x="' + (x + bw * 0.12).toFixed(2) + '" y="' + (H - total).toFixed(2) +
             '" width="' + (bw * 0.76).toFixed(2) + '" height="' + total.toFixed(2) +
             '" class="em-bar-total"><title>' + esc(d.date) + ': ' + esc(d.count) +
             ' detected, ' + esc(d.contained) + ' stopped</title></rect>' +
             '<rect x="' + (x + bw * 0.12).toFixed(2) + '" y="' + (H - cont).toFixed(2) +
             '" width="' + (bw * 0.76).toFixed(2) + '" height="' + cont.toFixed(2) +
             '" class="em-bar-contained"></rect>';
    }).join('');

    return '<h3 class="em-h">Daily volume</h3>' +
      '<div class="em-chart">' +
        '<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none" ' +
          'role="img" aria-label="Email threats detected per day">' + bars + '</svg>' +
        '<div class="em-legend">' +
          '<span class="em-key em-k-total"></span> Detected ' +
          '<span class="em-key em-k-contained"></span> Stopped ' +
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
   * a chart that quietly stops rising.
   */
  function unrecognisedBlock(s) {
    var rows = s.unrecognisedTypes || [];
    if (!rows.length) return '';
    return '<h3 class="em-h">Alert types not read as email security (' + esc(rows.length) + ')</h3>' +
      '<p class="em-note">Acronis raises backup, recovery and patching alerts through the ' +
      'same API, so most of these are correctly excluded. Check the list if a number ' +
      'above looks low — an email-security type missing from the classifier shows up ' +
      'here and nowhere else.</p>' +
      '<div class="em-types">' + rows.map(function (r) {
        return '<span class="em-type">' + esc(r.label) +
          '<span class="em-type-n">' + esc(r.count) + '</span></span>';
      }).join('') + '</div>';
  }

  function alertsTable() {
    if (!_alerts.length) {
      return '<h3 class="em-h">Recent alerts</h3>' +
        '<div class="em-note">No email alerts in this window.</div>';
    }
    return '<h3 class="em-h">Recent alerts (' + esc(_alerts.length) + ')</h3>' +
      '<div class="em-scroll"><table class="data-table em-table"><thead><tr>' +
        '<th>When</th><th>Type</th><th>Recipient</th><th>Sender</th>' +
        '<th>Subject</th><th>Outcome</th>' +
      '</tr></thead><tbody>' +
      _alerts.map(function (a) {
        var disp = a.disposition;
        var dispCls = disp === 'delivered' ? 'em-bad'
                    : disp ? 'em-good' : 'em-nd';
        return '<tr>' +
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
      }).join('') + '</tbody></table></div>';
  }

  function syncNote(s) {
    var sync = s && s.sync;
    if (!sync) {
      return '<div class="em-note em-warn">No Acronis integration has been synced for ' +
        'this client. Configure it under Admin &rarr; Integrations.</div>';
    }
    var when = sync.last_synced_at ? fmtDate(sync.last_synced_at) : 'never';
    var bad = sync.last_sync_status && sync.last_sync_status !== 'ok';
    return '<div class="em-note' + (bad ? ' em-warn' : '') + '">Last synced ' + esc(when) +
      (sync.last_sync_status ? ' &middot; ' + esc(sync.last_sync_status) : '') +
      (sync.last_sync_message ? ' &middot; ' + esc(sync.last_sync_message) : '') + '</div>';
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
    } else {
      body = statCards(_summary) +
        denominatorNote(_summary) +
        trendChart(_summary.daily) +
        byClassBlock(_summary) +
        breakdown('By outcome', _summary.byDisposition, function (l) {
          return DISPOSITION_LABELS[l] || humanise(l);
        }) +
        breakdown('By severity', _summary.bySeverity, humanise) +
        targetedBlock(_summary) +
        breakdown('Top sending domains', _summary.topSenderDomains) +
        alertsTable() +
        unrecognisedBlock(_summary) +
        syncNote(_summary);
    }

    host.innerHTML = head +
      '<div class="em-toolbar">' + rangePicker() + '</div>' +
      '<div class="em-body">' + body + '</div>';

    wire();
  }

  function wire() {
    var sel = document.getElementById('em-range');
    if (sel) {
      sel.onchange = function () {
        _days = parseInt(sel.value, 10) || 30;
        loadAndRender();
      };
    }
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
      try { _alerts = _available ? (await get('email/alerts' + qs())) || [] : []; }
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
    _setSummary: function (s) { _summary = s; },
    _setAlerts: function (a) { _alerts = a; },
    _setAvailable: function (v) { _available = v; },
  };
})();
