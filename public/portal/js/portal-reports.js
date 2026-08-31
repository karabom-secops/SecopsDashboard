/* portal-reports.js — the published report archive. */
(function () {
  'use strict';

  var P = window.Portal;

  function render(data) {
    var reports = (data && data.reports) || [];
    var el = document.getElementById('tab-reports');

    var head = P.viewHead('Reports',
      'Board reports prepared and reviewed by our team. Each one is the exact ' +
      'document that was signed off.');

    if (!reports.length) {
      el.innerHTML = head + P.emptyState('No reports have been published yet',
        'Your first board report will appear here once our team has prepared ' +
        'and reviewed it.');
      return;
    }

    el.innerHTML = head + P.table([
      { label: 'Period', raw: function (r) {
          return '<strong>' + P.esc(r.periodLabel || r.period) + '</strong>' +
            '<div class="cell-sub">' +
              (r.title ? '<span>' + P.esc(r.title) + '</span>' : '') +
              // A superseded version is still downloadable — it really was sent
              // — but must not be mistaken for the current one.
              (!r.isLatest ? '<span class="badge badge-amber">Superseded</span>' : '') +
            '</div>';
        } },
      { label: 'Version',   cls: 'col-narrow', raw: function (r) { return 'v' + P.esc(r.version); } },
      { label: 'Published', cls: 'col-narrow', raw: function (r) { return P.esc(P.fmtDate(r.publishedAt)); } },
      { label: 'Size',      cls: 'col-narrow', raw: function (r) { return P.esc(P.fmtBytes(r.pptxBytes)); } },
      { label: '', cls: 'col-actions', raw: function (r) {
          var base = P.BASE + 'api/portal/reports/' + encodeURIComponent(r.id);
          var out = '';
          if (r.canView) {
            out += '<a class="btn btn-secondary btn-sm" target="_blank" rel="noopener" ' +
              'href="' + base + '/view">View</a> ';
          }
          // A real link, not a scripted save: the server sends its own
          // Content-Disposition, so the browser's download handling applies.
          out += r.canDownload
            ? '<a class="btn btn-primary btn-sm" href="' + base + '/download.pptx">Download</a>'
            : '<span class="cell-sub">No longer available</span>';
          return out;
        } },
    ], reports, { emptyTitle: 'No reports published yet' });

    var notes = reports.filter(function (r) { return r.coverNote && r.isLatest; });
    if (notes.length) {
      el.insertAdjacentHTML('beforeend',
        '<div class="portal-card"><h3 class="portal-card-title">From your security team</h3>' +
        notes.map(function (r) {
          return '<blockquote class="portal-quote"><p>' + P.esc(r.coverNote) + '</p>' +
            '<cite>' + P.esc(r.periodLabel || r.period) + '</cite></blockquote>';
        }).join('') + '</div>');
    }

    el.insertAdjacentHTML('beforeend',
      '<p class="portal-note">Reports download as PowerPoint. Use <strong>View</strong> ' +
      'to read one in your browser without PowerPoint installed.</p>');
  }

  window.PortalReports = {
    async load() {
      var el = document.getElementById('tab-reports');
      try {
        render(await P.get('reports'));
      } catch (err) {
        el.innerHTML = P.viewHead('Reports') + P.errorState(err.message);
      }
    },
  };
})();
