/* portal-remediation.js — everything outstanding, from all four sources.
 *
 * Vulnerability rows name the issue but never the affected host, port or CVE:
 * the Vulnerabilities view withholds the finding list deliberately, and this
 * must not undo that decision through a different door. See lib/portal-routes.js.
 */
(function () {
  'use strict';

  var P = window.Portal;
  var _items = [];
  var _filter = { scope: 'open', source: '', q: '' };

  function matches(i) {
    if (_filter.scope === 'overdue' && !i.overdue) return false;
    if (_filter.source && i.source !== _filter.source) return false;
    if (_filter.q) {
      var q = _filter.q.trim().toLowerCase();
      if (q && (i.title || '').toLowerCase().indexOf(q) < 0 &&
               (i.source || '').toLowerCase().indexOf(q) < 0) return false;
    }
    return true;
  }

  function chip(value, label, active) {
    return '<button type="button" class="chip' + (active ? ' active' : '') +
      '" data-scope="' + P.esc(value) + '">' + P.esc(label) + '</button>';
  }

  function controls(data, sources) {
    return '<div class="filter-bar">' +
      '<div class="chip-row" role="group" aria-label="Filter">' +
        chip('open',    'All open (' + (data.total || 0) + ')', _filter.scope === 'open') +
        chip('overdue', 'Overdue (' + (data.overdue || 0) + ')', _filter.scope === 'overdue') +
      '</div>' +
      '<select id="remSource" class="form-select" aria-label="Filter by source">' +
        '<option value="">All sources</option>' +
        sources.map(function (s) {
          return '<option value="' + P.esc(s) + '"' +
            (_filter.source === s ? ' selected' : '') + '>' + P.esc(s) + '</option>';
        }).join('') +
      '</select>' +
      '<input id="remSearch" class="form-input table-search-input" type="search"' +
        ' placeholder="Search remediation items" aria-label="Search remediation items"' +
        ' aria-controls="remList" />' +
      '<span id="remCount" class="portal-count" role="status" aria-live="polite"></span>' +
    '</div>';
  }

  function due(i) {
    if (!i.dueDate) return '<span class="portal-muted">—</span>';
    var txt = P.esc(P.fmtDate(i.dueDate));
    // Late is the only thing on this page anyone needs to spot at a glance.
    return i.overdue
      ? '<span class="badge badge-red">' + txt + '</span>'
      : txt;
  }

  function list() {
    var rows = _items.filter(matches);

    var countEl = document.getElementById('remCount');
    if (countEl) {
      countEl.textContent = rows.length === _items.length
        ? _items.length + ' items'
        : rows.length + ' of ' + _items.length + ' items';
    }

    return P.table([
      { label: 'Item', raw: function (i) {
          return P.esc(i.title || 'Untitled') +
            '<div class="cell-sub"><span>' + P.esc(i.source) + '</span></div>';
        } },
      { label: 'Severity', cls: 'col-narrow', raw: function (i) { return P.sevPill(i.severity); } },
      { label: 'Status',   cls: 'col-narrow', raw: function (i) { return P.esc(i.status || '—'); } },
      { label: 'Raised',   cls: 'col-narrow', raw: function (i) { return P.esc(P.fmtDate(i.raisedAt)); } },
      { label: 'Target',   cls: 'col-narrow', raw: due },
    ], rows, {
      emptyTitle: _filter.scope === 'overdue' && !_filter.source && !_filter.q
        ? 'Nothing is overdue'
        : 'Nothing matches these filters',
      emptyDetail: _filter.scope === 'overdue' && !_filter.source && !_filter.q
        ? 'Every open item is still inside its target date.' : '',
    });
  }

  function render(data) {
    _items = (data && data.items) || [];
    _filter = { scope: 'open', source: '', q: '' };

    var el = document.getElementById('tab-remediation');
    var head = P.viewHead('Remediation',
      'Everything currently open across vulnerabilities, risks, penetration ' +
      'test findings and incidents.');

    if (!_items.length) {
      el.innerHTML = head + P.emptyState('Nothing outstanding',
        'There are no open remediation items for your environment.');
      return;
    }

    var sev = data.bySeverity || {};
    var cards = [
      { label: 'Open items', value: data.total || 0 },
      { label: 'Overdue', value: data.overdue || 0,
        accent: (data.overdue || 0) > 0 ? 'red' : 'green',
        sub: 'Past the agreed target date' },
      { label: 'Critical & high', value: (sev.critical || 0) + (sev.high || 0),
        accent: ((sev.critical || 0) + (sev.high || 0)) > 0 ? 'amber' : 'green' },
    ];

    var sources = _items.map(function (i) { return i.source; })
      .filter(function (v, idx, a) { return a.indexOf(v) === idx; }).sort();

    el.innerHTML = head + P.statCards(cards) +
      controls(data, sources) +
      '<div id="remList">' + list() + '</div>' +
      '<p class="portal-note">' + P.esc(data.note || '') + '</p>';

    // Only #remList is re-rendered, so the search box keeps focus and caret.
    el.addEventListener('click', function (ev) {
      var c = ev.target.closest('.chip[data-scope]');
      if (!c) return;
      _filter.scope = c.dataset.scope;
      Array.prototype.forEach.call(
        el.querySelectorAll('.chip[data-scope]'),
        function (b) { b.classList.toggle('active', b === c); });
      refresh();
    });
    var src = document.getElementById('remSource');
    if (src) src.addEventListener('change', function () {
      _filter.source = src.value; refresh();
    });
    var q = document.getElementById('remSearch');
    if (q) q.addEventListener('input', function () { _filter.q = q.value; refresh(); });

    list();   // populate the count on first paint
  }

  function refresh() {
    var host = document.getElementById('remList');
    if (host) host.innerHTML = list();
  }

  window.PortalRemediation = {
    async load() {
      var el = document.getElementById('tab-remediation');
      try {
        render(await P.get('remediation'));
      } catch (err) {
        el.innerHTML = P.viewHead('Remediation') + P.errorState(err.message);
      }
    },
  };
})();
