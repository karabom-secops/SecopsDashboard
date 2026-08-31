/* portal-reports.js — the published report archive. */
(function () {
  'use strict';

  var P = window.Portal;

  function render(data) {
    var reports = (data && data.reports) || [];
    var el = document.getElementById('view-reports');

    var head =
      '<div class="portal-view-head">' +
        '<h1>Reports</h1>' +
        '<p class="portal-view-intro">Board reports prepared and reviewed by our team. ' +
          'Each one is the exact document that was signed off.</p>' +
      '</div>';

    if (!reports.length) {
      el.innerHTML = head + P.emptyState('📄', 'No reports have been published yet',
        'Your first board report will appear here once our team has prepared and reviewed it.');
      return;
    }

    el.innerHTML = head + P.table([
      { label: 'Period', raw: function (r) {
          return '<strong>' + P.esc(r.periodLabel || r.period) + '</strong>' +
            (r.title ? '<div class="portal-sub"><span>' + P.esc(r.title) + '</span></div>' : '') +
            // A superseded version is still downloadable — it was really sent —
            // but must not be mistaken for the current one.
            (!r.isLatest ? '<div class="portal-sub"><span class="portal-superseded">' +
              'Superseded by a later version</span></div>' : '');
        } },
      { label: 'Version', cls: 'col-narrow', raw: function (r) { return 'v' + P.esc(r.version); } },
      { label: 'Published', cls: 'col-narrow', raw: function (r) {
          return P.esc(P.fmtDate(r.publishedAt)); } },
      { label: 'Size', cls: 'col-narrow', raw: function (r) {
          return P.esc(P.fmtBytes(r.pptxBytes)); } },
      { label: '', cls: 'col-actions', raw: function (r) {
          var base = P.BASE + 'api/portal/reports/' + encodeURIComponent(r.id);
          var out = '';
          if (r.canView) {
            out += '<a class="btn btn-secondary btn-sm" target="_blank" rel="noopener" ' +
              'href="' + base + '/view">View</a> ';
          }
          out += r.canDownload
            // A real link, not a scripted download: the artefact is served by
            // the server with its own Content-Disposition, so the browser's
            // own download handling applies.
            ? '<a class="btn btn-primary btn-sm" href="' + base + '/download.pptx">Download</a>'
            : '<span class="portal-sub">No longer available</span>';
          return out;
        } },
    ], reports, { emptyTitle: 'No reports published yet' });

    var notes = reports.filter(function (r) { return r.coverNote && r.isLatest; });
    if (notes.length) {
      el.insertAdjacentHTML('beforeend',
        '<div class="portal-covernote"><h3>From your security team</h3>' +
        notes.map(function (r) {
          return '<blockquote><p>' + P.esc(r.coverNote) + '</p>' +
            '<cite>' + P.esc(r.periodLabel || r.period) + '</cite></blockquote>';
        }).join('') + '</div>');
    }

    el.insertAdjacentHTML('beforeend',
      '<div class="portal-note">Reports download as PowerPoint. Use <strong>View</strong> ' +
      'to read one in your browser without PowerPoint installed.</div>');
  }

  window.PortalReports = {
    async load() {
      var el = document.getElementById('view-reports');
      try {
        render(await P.get('reports'));
      } catch (err) {
        el.innerHTML = '<div class="portal-view-head"><h1>Reports</h1></div>' +
          P.errorState(err.message);
      }
    },
  };
})();
