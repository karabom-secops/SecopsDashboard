/* portal-vulns.js — vulnerability posture: counts, SLA state, trend.
 *
 * NO FINDING LIST, deliberately. Host, port, CVE and remediation steps for open
 * findings is a working map of the client's unpatched internet-facing services.
 * It is their data and they may have it — through a report their team has
 * reviewed, not standing behind a portal password. The omission is a decision,
 * and the page says so rather than looking incomplete.
 */
(function () {
  'use strict';

  var P = window.Portal;

  // Accents are the dashboard's, and only critical/high get a warm colour: a
  // red tile beside three neutral ones is a signal, four accented tiles are
  // wallpaper.
  var SEVERITIES = [
    { key: 'critical', label: 'Critical', accent: 'red' },
    { key: 'high',     label: 'High',     accent: 'orange' },
    { key: 'medium',   label: 'Medium',   accent: 'amber' },
    { key: 'low',      label: 'Low',      accent: '' },
  ];

  function trendTable(trend) {
    if (!trend || trend.length < 2) return '';
    return '<h3 class="portal-card-title">Trend</h3>' +
      P.table([
        { label: 'Month', raw: function (r) { return P.esc(r.monthKey); } },
        { label: 'Critical', cls: 'col-num', raw: function (r) { return P.esc(r.critical); } },
        { label: 'High',     cls: 'col-num', raw: function (r) { return P.esc(r.high); } },
      ], trend.slice().reverse(), { emptyTitle: 'No history yet' });
  }

  function render(data) {
    var el = document.getElementById('tab-vulns');
    var head = P.viewHead('Vulnerabilities',
      'What our external scanning found on your internet-facing systems.');

    if (!data || !data.available) {
      el.innerHTML = head + P.emptyState('No scan results yet',
        (data && data.reason) || 'Results appear here after your first scan.');
      return;
    }

    var c = data.counts || {};
    var cards = SEVERITIES.map(function (s) {
      var n = Number(c[s.key]) || 0;
      return { label: s.label, value: n, accent: n > 0 ? s.accent : '' };
    });
    cards.push({
      label: 'Past target date', value: data.pastSla || 0,
      accent: (data.pastSla || 0) > 0 ? 'red' : 'green',
      sub: 'Open beyond the agreed remediation window',
    });

    el.innerHTML = head +
      P.statCards(cards) +
      '<p class="portal-note">Scan of ' + P.esc(data.monthKey) +
        (data.scannedHosts ? ', covering ' + P.esc(data.scannedHosts) + ' host' +
          (data.scannedHosts === 1 ? '' : 's') : '') + '.</p>' +
      trendTable(data.trend) +
      // Both limits stated plainly. A client who assumes this covers their
      // servers has been misled by omission.
      '<p class="portal-note"><strong>Scope.</strong> ' + P.esc(data.note || '') + '</p>' +
      '<p class="portal-note">Individual findings are not listed here. They are ' +
        'included in your board report, where they come with our team\'s ' +
        'assessment and remediation advice.</p>';
  }

  window.PortalVulns = {
    async load() {
      var el = document.getElementById('tab-vulns');
      try {
        render(await P.get('vulns'));
      } catch (err) {
        el.innerHTML = P.viewHead('Vulnerabilities') + P.errorState(err.message);
      }
    },
    render: render,
  };
})();
