/* portal-score.js — the Secure Score panel on the Overview view.
 *
 * Shows the score, its three components and the trend. Deliberately NOT the
 * weighting model: exposure points, patch relief and "weighted at half pending
 * evidence" are explanations written for a colleague, and read to the customer
 * being weighted as an invitation to argue about arithmetic rather than posture.
 */
(function () {
  'use strict';

  var P = window.Portal;

  function band(score) {
    var n = Number(score) || 0;
    if (n >= 80) return { label: 'Excellent', accent: 'green' };
    if (n >= 70) return { label: 'Good',      accent: 'green' };
    if (n >= 50) return { label: 'Fair',      accent: 'amber' };
    return { label: 'Needs attention', accent: 'red' };
  }

  /** A sparkline as inline SVG — no chart library on this page. */
  function sparkline(points) {
    if (points.length < 2) return '';
    var w = 240, h = 48, pad = 4;
    var xs = points.map(function (p, i) {
      return pad + (i * (w - pad * 2)) / (points.length - 1);
    });
    // Fixed 0-100 domain: an auto-scaled axis makes a two-point wobble look
    // like a collapse, which is the classic way a sparkline misleads.
    var ys = points.map(function (p) {
      return h - pad - (Math.max(0, Math.min(100, p.score)) / 100) * (h - pad * 2);
    });
    var d = xs.map(function (x, i) {
      return (i ? 'L' : 'M') + x.toFixed(1) + ' ' + ys[i].toFixed(1);
    }).join(' ');

    return '<svg class="portal-spark" viewBox="0 0 ' + w + ' ' + h + '" role="img" ' +
      'aria-label="Score trend over the last ' + points.length + ' readings">' +
      '<path d="' + d + '" fill="none" stroke="currentColor" stroke-width="2" ' +
      'stroke-linecap="round" stroke-linejoin="round"/>' +
      '<circle cx="' + xs[xs.length - 1].toFixed(1) + '" cy="' + ys[ys.length - 1].toFixed(1) +
      '" r="3" fill="currentColor"/></svg>';
  }

  function monthLabel(key) {
    var m = /^(\d{4})-(\d{2})$/.exec(String(key || ''));
    if (!m) return String(key || '');
    return new Date(Date.UTC(+m[1], +m[2] - 1, 1))
      .toLocaleDateString('en-ZA', { month: 'long', year: 'numeric', timeZone: 'UTC' });
  }

  /**
   * What changed, month by month. The summary is always visible; the evidence
   * behind it opens on request. Everything here is written by the server in
   * terms of findings, training and incidents — never in points — so there is
   * nothing to strip.
   */
  function changesHtml(changes) {
    if (!changes || !changes.length) return '';
    return '<h4 class="portal-changes-title">What changed</h4>' +
      '<ul class="portal-changes">' + changes.map(function (c) {
        var tone = c.delta == null || c.delta === 0 ? 'flat' : c.delta > 0 ? 'up' : 'down';
        return '<li class="portal-change">' +
          '<details>' +
            '<summary>' +
              '<span class="portal-change-month">' + P.esc(monthLabel(c.monthKey)) + '</span>' +
              '<span class="portal-change-delta portal-change-' + tone + '">' +
                P.esc(c.delta == null ? '—' : (c.delta > 0 ? '+' : '') + c.delta) + '</span>' +
              '<span class="portal-change-summary">' + P.esc(c.summary) + '</span>' +
            '</summary>' +
            '<ul class="portal-change-details">' +
              (c.details || []).map(function (t) { return '<li>' + P.esc(t) + '</li>'; }).join('') +
            '</ul>' +
          '</details>' +
        '</li>';
      }).join('') + '</ul>';
  }

  function render(d) {
    if (!d || !d.available) {
      return '<div class="portal-card">' +
        '<h3 class="portal-card-title">Security posture</h3>' +
        P.emptyState('No score yet',
          (d && d.reason) || 'Your score appears once we have assessed your environment.') +
        '</div>';
    }

    var b = band(d.score);
    var trend = d.trend || [];
    var delta = trend.length > 1 ? d.score - trend[0].score : null;
    var deltaTxt = delta === null ? ''
      : delta > 0 ? '+' + delta + ' since ' + P.fmtDate(trend[0].date)
      : delta < 0 ? delta + ' since ' + P.fmtDate(trend[0].date)
      : 'Unchanged since ' + P.fmtDate(trend[0].date);

    return '<div class="portal-card">' +
      '<h3 class="portal-card-title">Security posture</h3>' +
      '<div class="portal-score accent-' + b.accent + '">' +
        '<div class="portal-score-number">' + P.esc(d.score) + '<span>/100</span></div>' +
        '<div class="portal-score-band">' + P.esc(b.label) +
          (deltaTxt ? '<span class="portal-score-delta">' + P.esc(deltaTxt) + '</span>' : '') +
        '</div>' +
        '<div class="portal-score-spark">' + sparkline(trend) + '</div>' +
      '</div>' +
      '<ul class="portal-components">' +
        (d.components || []).map(function (c) {
          var cb = band(c.score);
          return '<li><span class="portal-component-label">' + P.esc(c.label) + '</span>' +
            '<span class="portal-bar accent-' + cb.accent + '">' +
              '<i style="width:' + Math.max(0, Math.min(100, c.score)) + '%"></i></span>' +
            '<span class="portal-bar-num">' + P.esc(c.score) + '</span></li>';
        }).join('') +
      '</ul>' +
      changesHtml(d.changes) +
      '<p class="portal-note">As at ' + P.esc(P.fmtDate(d.asOf)) + '.</p>' +
      '</div>';
  }

  window.PortalScore = { render: render };
})();
