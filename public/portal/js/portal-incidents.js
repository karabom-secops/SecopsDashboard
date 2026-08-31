/* portal-incidents.js — the merged incident list and its detail view. */
(function () {
  'use strict';

  var P = window.Portal;
  var _items = [];
  var _filter = { status: 'open', severity: '', q: '' };

  function matches(item) {
    if (_filter.status === 'open'   && item.closed) return false;
    if (_filter.status === 'closed' && !item.closed) return false;
    if (_filter.severity && item.severity !== _filter.severity) return false;
    if (_filter.q) {
      var hay = (item.title + ' ' + (item.reference || '') + ' ' + (item.category || '')).toLowerCase();
      if (hay.indexOf(_filter.q.toLowerCase()) < 0) return false;
    }
    return true;
  }

  function controls(openCount, total) {
    return '<div class="portal-controls">' +
      '<div class="portal-segmented" role="group" aria-label="Filter by state">' +
        ['open', 'closed', 'all'].map(function (v) {
          var label = v === 'open' ? 'Open (' + openCount + ')'
                    : v === 'closed' ? 'Resolved' : 'All (' + total + ')';
          return '<button type="button" class="portal-seg' +
            (_filter.status === v ? ' is-active' : '') + '" data-status="' + v + '">' +
            P.esc(label) + '</button>';
        }).join('') +
      '</div>' +
      '<select id="incSeverity" class="portal-select" aria-label="Filter by severity">' +
        '<option value="">All severities</option>' +
        ['critical', 'high', 'medium', 'low'].map(function (s) {
          return '<option value="' + s + '"' + (_filter.severity === s ? ' selected' : '') + '>' +
            s.charAt(0).toUpperCase() + s.slice(1) + '</option>';
        }).join('') +
      '</select>' +
      '<input id="incSearch" class="portal-input" type="search" placeholder="Search incidents"' +
        ' value="' + P.esc(_filter.q) + '" aria-label="Search incidents" />' +
    '</div>';
  }

  function list() {
    var rows = _items.filter(matches);

    return P.table([
      { label: 'Incident', key: 'title', raw: function (r) {
          return '<button type="button" class="portal-linkbtn" data-key="' + P.esc(r.key) + '">' +
              P.esc(r.title || 'Untitled') + '</button>' +
            '<div class="portal-sub">' +
              (r.reference ? '<span class="portal-ref">' + P.esc(r.reference) + '</span>' : '') +
              (r.category ? '<span>' + P.esc(r.category) + '</span>' : '') +
              // Where an event exists in both systems, say which record this is.
              '<span class="portal-source">' +
                (r.source === 'mdr' ? 'Detected by MDR' : 'Incident response') +
              '</span>' +
            '</div>';
        } },
      { label: 'Severity', cls: 'col-narrow', raw: function (r) { return P.sevPill(r.severity); } },
      { label: 'Status', cls: 'col-narrow', raw: function (r) { return P.statusPill(r.status, r.closed); } },
      { label: 'Raised', cls: 'col-narrow', raw: function (r) { return P.esc(P.fmtDate(r.openedAt)); } },
      { label: 'Resolved', cls: 'col-narrow', raw: function (r) { return P.esc(P.fmtDate(r.closedAt)); } },
    ], rows, {
      emptyIcon: '✓',
      emptyTitle: _filter.status === 'open' && !_filter.severity && !_filter.q
        ? 'No open incidents'
        : 'No incidents match these filters',
    });
  }

  function render(data) {
    _items = (data && data.items) || [];
    var el = document.getElementById('view-incidents');

    el.innerHTML =
      '<div class="portal-view-head">' +
        '<h1>Incidents</h1>' +
        '<p class="portal-view-intro">Security incidents raised by our monitoring, ' +
          'and the ones our team formally opened and worked.</p>' +
      '</div>' +
      controls(data.openCount || 0, data.total || 0) +
      '<div id="incList">' + list() + '</div>' +
      '<div class="portal-note">Detected incidents come from our managed detection ' +
        'service. Where our team opened a formal investigation, that record is shown ' +
        'instead and carries the original reference.</div>';

    el.addEventListener('click', onClick);
    var sev = document.getElementById('incSeverity');
    if (sev) sev.addEventListener('change', function () {
      _filter.severity = sev.value; refresh();
    });
    var q = document.getElementById('incSearch');
    if (q) q.addEventListener('input', function () { _filter.q = q.value; refresh(); });
  }

  function refresh() {
    var wrap = document.getElementById('incList');
    if (wrap) wrap.innerHTML = list();
  }

  function onClick(ev) {
    var seg = ev.target.closest('.portal-seg');
    if (seg) {
      _filter.status = seg.dataset.status;
      Array.prototype.forEach.call(document.querySelectorAll('.portal-seg'), function (b) {
        b.classList.toggle('is-active', b === seg);
      });
      refresh();
      return;
    }
    var link = ev.target.closest('.portal-linkbtn');
    if (link) openDetail(link.dataset.key, link);
  }

  /* ── Detail ─────────────────────────────────────────────────────────────
     A dialog rather than a route: the portal has no router, and a client
     glancing at one incident should not lose their filters to get back. */
  var _lastTrigger = null;

  async function openDetail(key, trigger) {
    _lastTrigger = trigger || null;
    var host = document.getElementById('portalDialog') || createDialog();
    var body = host.querySelector('.portal-dialog-body');
    body.innerHTML = '<p class="portal-loading">Loading…</p>';
    showDialog(host);

    try {
      var d = await P.get('incidents/' + encodeURIComponent(key));
      body.innerHTML = detailHtml(d);
    } catch (err) {
      body.innerHTML = P.errorState(err.message);
    }
  }

  function detailHtml(d) {
    var timeline = (d.timeline || []).length
      ? '<h3 class="portal-dialog-h">History</h3><ol class="portal-timeline">' +
          d.timeline.map(function (t) {
            var what = t.type === 'created'
              ? 'Raised'
              : (t.field === 'status' ? 'Status changed'
                 : t.field === 'severity' ? 'Severity changed'
                 : t.field === 'resolved_at' ? 'Resolution recorded'
                 : 'Updated');
            var detail = (t.from || t.to)
              ? P.esc([t.from, t.to].filter(Boolean).join(' → ')) : '';
            return '<li><span class="portal-timeline-at">' + P.esc(P.fmtDate(t.at)) + '</span>' +
              '<span class="portal-timeline-what">' + P.esc(what) +
              (detail ? ' <em>' + detail + '</em>' : '') + '</span></li>';
          }).join('') + '</ol>'
      : '';

    var progress = (d.progress || []).length
      ? '<h3 class="portal-dialog-h">Response progress</h3><ul class="portal-progress">' +
          d.progress.map(function (p) {
            var pct = p.total ? Math.round((p.done / p.total) * 100) : 0;
            return '<li><span>' + P.esc(p.phase) + '</span>' +
              '<span class="portal-progress-bar"><i style="width:' + pct + '%"></i></span>' +
              '<span class="portal-progress-num">' + p.done + '/' + p.total + '</span></li>';
          }).join('') + '</ul>'
      : '';

    return '<div class="portal-dialog-meta">' +
        P.sevPill(d.severity) + P.statusPill(d.status, d.closed) +
        (d.reference ? '<span class="portal-ref">' + P.esc(d.reference) + '</span>' : '') +
      '</div>' +
      '<h2 class="portal-dialog-title">' + P.esc(d.title || 'Untitled') + '</h2>' +
      (d.summary ? '<p class="portal-dialog-summary">' + P.esc(d.summary) + '</p>' : '') +
      '<dl class="portal-deflist">' +
        '<div><dt>Raised</dt><dd>' + P.esc(P.fmtDate(d.openedAt)) + '</dd></div>' +
        '<div><dt>Resolved</dt><dd>' + P.esc(P.fmtDate(d.closedAt)) + '</dd></div>' +
        (d.category ? '<div><dt>Category</dt><dd>' + P.esc(d.category) + '</dd></div>' : '') +
        (d.phase ? '<div><dt>Current phase</dt><dd>' + P.esc(d.phase) + '</dd></div>' : '') +
      '</dl>' + progress + timeline +
      (!timeline && !progress
        ? '<p class="portal-note">No further detail has been recorded for this incident.</p>'
        : '');
  }

  function createDialog() {
    var host = document.createElement('div');
    host.id = 'portalDialog';
    host.className = 'portal-dialog-overlay';
    host.hidden = true;
    host.setAttribute('role', 'dialog');
    host.setAttribute('aria-modal', 'true');
    host.setAttribute('aria-label', 'Incident detail');
    host.innerHTML =
      '<div class="portal-dialog">' +
        '<button type="button" class="portal-dialog-close" aria-label="Close">×</button>' +
        '<div class="portal-dialog-body"></div>' +
      '</div>';
    document.body.appendChild(host);

    host.addEventListener('click', function (ev) {
      if (ev.target === host || ev.target.closest('.portal-dialog-close')) hideDialog(host);
    });
    document.addEventListener('keydown', function (ev) {
      if (ev.key === 'Escape' && !host.hidden) hideDialog(host);
    });
    return host;
  }

  function showDialog(host) {
    host.hidden = false;
    document.body.classList.add('portal-dialog-open');
    var close = host.querySelector('.portal-dialog-close');
    if (close) close.focus();
  }

  function hideDialog(host) {
    host.hidden = true;
    document.body.classList.remove('portal-dialog-open');
    // Focus goes back where it came from, or a keyboard user is dumped at the
    // top of the document with their place lost.
    if (_lastTrigger && document.contains(_lastTrigger)) _lastTrigger.focus();
  }

  window.PortalIncidents = {
    async load() {
      var el = document.getElementById('view-incidents');
      try {
        render(await P.get('incidents'));
      } catch (err) {
        el.innerHTML = '<div class="portal-view-head"><h1>Incidents</h1></div>' +
          P.errorState(err.message);
      }
    },
  };
})();
