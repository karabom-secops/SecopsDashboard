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
    if (score >= 80) return { label: 'Excellent', tone: 'good' };
    if (score >= 70) return { label: 'Good',      tone: 'good' };
    if (score >= 50) return { label: 'Fair',      tone: 'warn' };
    return { label: 'Needs attention', tone: 'bad' };
  }

  /** A sparkline as inline SVG — no chart library on this page. */
  function sparkline(points) {
    if (points.length < 2) return '';
    var w = 240, h = 48, pad = 4;
    var xs = points.map(function (p, i) { return pad + (i * (w - pad * 2)) / (points.length - 1); });
    // Fixed 0-100 domain: an auto-scaled axis makes a two-point wobble look
    // like a collapse, which is the classic way a sparkline misleads.
    var ys = points.map(function (p) { return h - pad - (Math.max(0, Math.min(100, p.score)) / 100) * (h - pad * 2); });
    var d = xs.map(function (x, i) { return (i ? 'L' : 'M') + x.toFixed(1) + ' ' + ys[i].toFixed(1); }).join(' ');

    return '<svg class="portal-spark" viewBox="0 0 ' + w + ' ' + h + '" role="img" ' +
      'aria-label="Score trend over the last ' + points.length + ' readings">' +
      '<path d="' + d + '" fill="none" stroke="currentColor" stroke-width="2" ' +
      'stroke-linecap="round" stroke-linejoin="round"/>' +
      '<circle cx="' + xs[xs.length - 1].toFixed(1) + '" cy="' + ys[ys.length - 1].toFixed(1) +
      '" r="3" fill="currentColor"/></svg>';
  }

  function render(d) {
    if (!d || !d.available) {
      return '<section class="portal-card">' +
        '<h2 class="portal-card-title">Security posture</h2>' +
        P.emptyState('◍', 'No score yet',
          (d && d.reason) || 'Your score appears once we have assessed your environment.') +
        '</section>';
    }

    var b = band(d.score);
    var trend = d.trend || [];
    var delta = trend.length > 1 ? d.score - trend[0].score : null;
    var deltaTxt = delta === null ? ''
      : (delta > 0 ? '+' + delta + ' since ' + P.fmtDate(trend[0].date)
         : delta < 0 ? delta + ' since ' + P.fmtDate(trend[0].date)
         : 'Unchanged since ' + P.fmtDate(trend[0].date));

    return '<section class="portal-card portal-score-card">' +
      '<h2 class="portal-card-title">Security posture</h2>' +
      '<div class="portal-score-main tone-' + b.tone + '">' +
        '<div class="portal-score-number">' + P.esc(d.score) + '<span>/100</span></div>' +
        '<div class="portal-score-band">' + P.esc(b.label) +
          (deltaTxt ? '<span class="portal-score-delta">' + P.esc(deltaTxt) + '</span>' : '') +
        '</div>' +
        '<div class="portal-score-spark tone-' + b.tone + '">' + sparkline(trend) + '</div>' +
      '</div>' +
      '<ul class="portal-score-components">' +
        (d.components || []).map(function (c) {
          var cb = band(c.score);
          return '<li><span class="portal-score-clabel">' + P.esc(c.label) + '</span>' +
            '<span class="portal-score-bar tone-' + cb.tone + '">' +
              '<i style="width:' + Math.max(0, Math.min(100, c.score)) + '%"></i></span>' +
            '<span class="portal-score-cvalue">' + P.esc(c.score) + '</span></li>';
        }).join('') +
      '</ul>' +
      '<p class="portal-card-foot">As at ' + P.esc(P.fmtDate(d.asOf)) + '.</p>' +
      '</section>';
  }

  window.PortalScore = { render: render };
})();
