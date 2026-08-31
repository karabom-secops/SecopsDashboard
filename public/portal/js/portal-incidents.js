/* portal-incidents.js — the merged incident list and its detail view.
 *
 * Filters use the dashboard's .chip, the table its .data-table, the badges its
 * .badge — so this reads as the same product as the Vulnerabilities or Risk
 * Register tabs rather than a separate app.
 */
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
      var hay = (item.title + ' ' + (item.reference || '') + ' ' +
                 (item.category || '')).toLowerCase();
      if (hay.indexOf(_filter.q.toLowerCase()) < 0) return false;
    }
    return true;
  }

  function chip(value, label, active) {
    return '<button type="button" class="chip' + (active ? ' active' : '') +
      '" data-status="' + P.esc(value) + '">' + P.esc(label) + '</button>';
  }

  function controls(openCount, total) {
    return '<div class="filter-bar">' +
      '<div class="chip-row" role="group" aria-label="Filter by state">' +
        chip('open',   'Open (' + openCount + ')', _filter.status === 'open') +
        chip('closed', 'Resolved',                 _filter.status === 'closed') +
        chip('all',    'All (' + total + ')',      _filter.status === 'all') +
      '</div>' +
      '<select id="incSeverity" class="form-select" aria-label="Filter by severity">' +
        '<option value="">All severities</option>' +
        ['critical', 'high', 'medium', 'low'].map(function (s) {
          return '<option value="' + s + '"' + (_filter.severity === s ? ' selected' : '') +
            '>' + s.charAt(0).toUpperCase() + s.slice(1) + '</option>';
        }).join('') +
      '</select>' +
      '<input id="incSearch" class="form-input table-search-input" type="search"' +
        ' placeholder="Search incidents" value="' + P.esc(_filter.q) +
        '" aria-label="Search incidents" />' +
    '</div>';
  }

  function list() {
    var rows = _items.filter(matches);

    return P.table([
      { label: 'Incident', raw: function (r) {
          // A real button, so the row is reachable and activatable by keyboard.
          return '<button type="button" class="link-btn" data-key="' + P.esc(r.key) + '">' +
              P.esc(r.title || 'Untitled') + '</button>' +
            '<div class="cell-sub">' +
              (r.reference ? '<code>' + P.esc(r.reference) + '</code>' : '') +
              (r.category ? '<span>' + P.esc(r.category) + '</span>' : '') +
              // Where an event exists in both systems, say which record this is.
              '<span>' + (r.source === 'mdr' ? 'Detected by MDR' : 'Incident response') +
              '</span>' +
            '</div>';
        } },
      { label: 'Severity', cls: 'col-narrow', raw: function (r) { return P.sevPill(r.severity); } },
      { label: 'Status',   cls: 'col-narrow', raw: function (r) { return P.statusPill(r.status, r.closed); } },
      { label: 'Raised',   cls: 'col-narrow', raw: function (r) { return P.esc(P.fmtDate(r.openedAt)); } },
      { label: 'Resolved', cls: 'col-narrow', raw: function (r) { return P.esc(P.fmtDate(r.closedAt)); } },
    ], rows, {
      emptyTitle: _filter.status === 'open' && !_filter.severity && !_filter.q
        ? 'No open incidents'
        : 'No incidents match these filters',
      emptyDetail: _filter.status === 'open' && !_filter.severity && !_filter.q
        ? 'Nothing currently needs your attention.' : '',
    });
  }

  function render(data) {
    _items = (data && data.items) || [];
    var el = document.getElementById('tab-incidents');

    el.innerHTML =
      P.viewHead('Incidents',
        'Security incidents raised by our monitoring, and the ones our team ' +
        'formally opened and worked.') +
      controls(data.openCount || 0, data.total || 0) +
      '<div id="incList">' + list() + '</div>' +
      '<p class="portal-note">Detected incidents come from our managed detection ' +
        'service. Where our team opened a formal investigation, that record is ' +
        'shown instead and carries the original reference.</p>';

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
    var c = ev.target.closest('.chip[data-status]');
    if (c) {
      _filter.status = c.dataset.status;
      Array.prototype.forEach.call(
        document.querySelectorAll('#tab-incidents .chip[data-status]'),
        function (b) { b.classList.toggle('active', b === c); });
      refresh();
      return;
    }
    var link = ev.target.closest('.link-btn[data-key]');
    if (link) openDetail(link.dataset.key, link);
  }

  /* ── Detail ─────────────────────────────────────────────────────────────
     A dialog rather than a route: the portal has no router, and a client
     glancing at one incident should not lose their filters to get back.
     Uses the dashboard's .modal-overlay / .modal-box so it matches the
     modals on the staff side. */
  var _lastTrigger = null;

  async function openDetail(key, trigger) {
    _lastTrigger = trigger || null;
    var host = document.getElementById('portalDialog') || createDialog();
    var body = host.querySelector('.modal-body');
    body.innerHTML = '<div class="loading-overlay"><div class="loading-spinner"></div>' +
      '<span>Loading…</span></div>';
    showDialog(host);

    try {
      var d = await P.get('incidents/' + encodeURIComponent(key));
      var title = host.querySelector('#portalDialogTitle');
      if (title) title.textContent = d.title || 'Incident';
      body.innerHTML = detailHtml(d);
    } catch (err) {
      body.innerHTML = P.errorState(err.message);
    }
  }

  function detailHtml(d) {
    var timeline = (d.timeline || []).length
      ? '<h4 class="portal-detail-h">History</h4><ol class="portal-timeline">' +
          d.timeline.map(function (t) {
            var what = t.type === 'created' ? 'Raised'
              : t.field === 'status'      ? 'Status changed'
              : t.field === 'severity'    ? 'Severity changed'
              : t.field === 'resolved_at' ? 'Resolution recorded'
              : 'Updated';
            var detail = (t.from || t.to)
              ? P.esc([t.from, t.to].filter(Boolean).join(' → ')) : '';
            return '<li><span class="portal-timeline-at">' + P.esc(P.fmtDate(t.at)) + '</span>' +
              '<span>' + P.esc(what) + (detail ? ' <em>' + detail + '</em>' : '') + '</span></li>';
          }).join('') + '</ol>'
      : '';

    /*
     * When the incident moved through each phase.
     *
     * This is the part of an incident record a client actually wants: not that
     * it is "in eradication" but that it was contained within four hours and
     * eradicated the next morning. Shown before the task-completion bars,
     * because the timings are the story and the checklist is the detail.
     *
     * A phase can appear more than once — eradication routinely bounces back to
     * containment — and the list reflects that rather than pretending the
     * response was a tidy five-step march.
     */
    var phases = (d.phases || []).length
      ? '<h4 class="portal-detail-h">Response timeline</h4>' +
          '<ol class="portal-phases">' +
          d.phases.map(function (p) {
            return '<li' + (p.current ? ' class="is-current"' : '') + '>' +
              '<span class="portal-phase-name">' + P.esc(p.phase) +
                (p.current ? ' <span class="badge badge-blue">Current</span>' : '') +
              '</span>' +
              '<span class="portal-phase-at">' + P.esc(P.fmtDateTime(p.enteredAt)) + '</span>' +
              '<span class="portal-phase-dur">' +
                (p.durationHours === null ? '—' : P.fmtDuration(p.durationHours)) +
              '</span></li>';
          }).join('') + '</ol>'
      : '';

    var progress = (d.progress || []).length
      ? '<h4 class="portal-detail-h">Response progress</h4><ul class="portal-progress">' +
          d.progress.map(function (p) {
            var pct = p.total ? Math.round((p.done / p.total) * 100) : 0;
            return '<li><span>' + P.esc(p.phase) + '</span>' +
              '<span class="portal-bar"><i style="width:' + pct + '%"></i></span>' +
              '<span class="portal-bar-num">' + p.done + '/' + p.total + '</span></li>';
          }).join('') + '</ul>'
      : '';

    return '<div class="portal-detail-meta">' +
        P.sevPill(d.severity) + ' ' + P.statusPill(d.status, d.closed) +
        (d.reference ? ' <code>' + P.esc(d.reference) + '</code>' : '') +
      '</div>' +
      (d.summary ? '<p class="portal-card-lead">' + P.esc(d.summary) + '</p>' : '') +
      '<dl class="portal-deflist">' +
        '<div><dt>Raised</dt><dd>' + P.esc(P.fmtDate(d.openedAt)) + '</dd></div>' +
        '<div><dt>Resolved</dt><dd>' + P.esc(P.fmtDate(d.closedAt)) + '</dd></div>' +
        (d.category ? '<div><dt>Category</dt><dd>' + P.esc(d.category) + '</dd></div>' : '') +
        (d.phase ? '<div><dt>Current phase</dt><dd>' + P.esc(d.phase) + '</dd></div>' : '') +
      '</dl>' + phases + progress + timeline +
      (!phases && !timeline && !progress
        ? '<p class="portal-note">No further detail has been recorded for this incident.</p>'
        : '');
  }

  function createDialog() {
    var host = document.createElement('div');
    host.id = 'portalDialog';
    host.className = 'modal-overlay';
    host.hidden = true;
    host.setAttribute('role', 'dialog');
    host.setAttribute('aria-modal', 'true');
    host.setAttribute('aria-labelledby', 'portalDialogTitle');
    host.innerHTML =
      '<div class="modal-box">' +
        '<div class="modal-header">' +
          '<h3 class="modal-title" id="portalDialogTitle">Incident</h3>' +
          '<button type="button" class="modal-close-btn" aria-label="Close">&times;</button>' +
        '</div>' +
        '<div class="modal-body"></div>' +
      '</div>';
    document.body.appendChild(host);

    host.addEventListener('click', function (ev) {
      if (ev.target === host || ev.target.closest('.modal-close-btn')) hideDialog(host);
    });
    document.addEventListener('keydown', function (ev) {
      if (ev.key === 'Escape' && !host.hidden) hideDialog(host);
    });
    return host;
  }

  function showDialog(host) {
    host.hidden = false;
    document.body.classList.add('modal-open');
    var close = host.querySelector('.modal-close-btn');
    if (close) close.focus();
  }

  function hideDialog(host) {
    host.hidden = true;
    document.body.classList.remove('modal-open');
    // Focus goes back where it came from, or a keyboard user is dumped at the
    // top of the document with their place lost.
    if (_lastTrigger && document.contains(_lastTrigger)) _lastTrigger.focus();
  }

  window.PortalIncidents = {
    async load() {
      var el = document.getElementById('tab-incidents');
      try {
        render(await P.get('incidents'));
      } catch (err) {
        el.innerHTML = P.viewHead('Incidents') + P.errorState(err.message);
      }
    },
  };
})();
