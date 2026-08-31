/* portal-awareness.js — security awareness training.
 *
 * Shows named per-employee completion. That is the client's own staff and their
 * own training obligation, and the existing manager report already does exactly
 * this — but it does mean one employee at the client can see another's record,
 * which is worth being deliberate about rather than discovering later.
 */
(function () {
  'use strict';

  var P = window.Portal;

  // Held so filtering never refetches: the whole list is already in memory and
  // a keystroke should not cost a round trip.
  var _people = [];
  var _q = '';

  function bar(pct) {
    var accent = pct >= 90 ? 'green' : pct >= 70 ? 'amber' : 'red';
    return '<span class="portal-bar accent-' + accent + '">' +
      '<i style="width:' + Math.max(0, Math.min(100, pct)) + '%"></i></span>' +
      '<span class="portal-bar-num">' + P.esc(pct) + '%</span>';
  }

  function render(data) {
    var el = document.getElementById('tab-awareness');
    var head = P.viewHead('Security awareness',
      'How your people are progressing through security awareness training.');

    if (!data || !data.available) {
      el.innerHTML = head + P.emptyState('No training records yet',
        (data && data.reason) ||
        'Completion figures appear here once training records are loaded.');
      return;
    }

    var pct = data.completionPct || 0;
    // "78%" of WHAT differs by upload format — sessions on a session-history
    // export, people on a summary. Saying which stops the same number meaning
    // two things in consecutive months.
    var unit = data.unit === 'sessions' ? 'sessions' : 'people';
    var assessed = data.assessed || 0;

    var cards = [
      { label: 'Training completion', value: pct + '%',
        accent: pct >= 90 ? 'green' : pct >= 70 ? 'amber' : 'red',
        sub: assessed ? (data.completed || 0).toLocaleString() + ' of ' +
             assessed.toLocaleString() + ' ' + unit : '' },
      { label: 'Staff covered', value: data.totalStaff || 0 },
      { label: 'Completed',   value: (data.completed || 0).toLocaleString(),
        sub: unit },
      { label: 'Outstanding', value: (data.outstanding || 0).toLocaleString(),
        accent: (data.outstanding || 0) > 0 ? 'amber' : 'green',
        sub: unit },
    ];

    _people = data.people || [];
    _q = '';

    var table = '';
    if (_people.length) {
      // The list is ordered least-covered first. Without saying so, the top of
      // the table is all zeroes and reads as "nobody has done anything" — which
      // is exactly how it was first reported.
      table = '<h3 class="portal-card-title">By person</h3>' +
        '<p class="portal-note">Least complete first, so whoever needs ' +
          'chasing is at the top.</p>' +
        '<div class="filter-bar">' +
          '<input id="awSearch" class="form-input table-search-input" type="search"' +
            ' placeholder="Search by name or email"' +
            ' aria-label="Search people" aria-controls="awPeople" />' +
          '<span id="awCount" class="portal-count" role="status" aria-live="polite"></span>' +
        '</div>' +
        // Only THIS div is re-rendered while typing. Rebuilding the wrapper
        // would destroy and recreate the input, losing focus and caret after
        // the first keystroke.
        '<div id="awPeople"></div>';
    }

    el.innerHTML = head + P.statCards(cards) +
      '<p class="portal-note">As at ' + P.esc(P.fmtDate(data.asOf)) + '.</p>' +
      table +
      // Provenance, where it matters: manual figures came from the client, and
      // presenting them as though we verified them would be dishonest.
      (data.selfReported
        ? '<p class="portal-note">These figures were supplied for an internally ' +
          'run training programme and have not been verified against records ' +
          'held by us.</p>'
        : '');

    if (_people.length) {
      refreshPeople();
      var input = document.getElementById('awSearch');
      if (input) input.addEventListener('input', function () {
        _q = input.value;
        refreshPeople();
      });
    }
  }

  /** Case-insensitive match on the two things anyone would type. */
  function matches(p) {
    if (!_q) return true;
    var q = _q.trim().toLowerCase();
    if (!q) return true;
    return String(p.name || '').toLowerCase().indexOf(q) >= 0 ||
           String(p.email || '').toLowerCase().indexOf(q) >= 0;
  }

  function refreshPeople() {
    var host = document.getElementById('awPeople');
    if (!host) return;

    var rows = _people.filter(matches);
    var hasPct = _people[0] && _people[0].pct !== undefined;

    var countEl = document.getElementById('awCount');
    if (countEl) {
      countEl.textContent = _q.trim()
        ? rows.length + ' of ' + _people.length + ' people'
        : _people.length + ' people';
    }

    host.innerHTML = P.table([
      { label: 'Name', raw: function (r) {
          return P.esc(r.name || '—') +
            (r.email ? '<div class="cell-sub"><span>' + P.esc(r.email) + '</span></div>' : '');
        } },
      hasPct
        ? { label: 'Completed', cls: 'col-narrow', raw: function (r) {
            return P.esc(r.completed + ' of ' + r.assigned); } }
        : { label: 'Outstanding', cls: 'col-num', raw: function (r) {
            return P.esc(r.outstanding); } },
      hasPct
        ? { label: 'Progress', cls: 'col-narrow', raw: function (r) { return bar(r.pct); } }
        : { label: '', cls: 'col-narrow', raw: function () { return ''; } },
    ], rows, {
      emptyTitle: _q.trim() ? 'Nobody matches that search' : 'No individual records',
      emptyDetail: _q.trim() ? 'Try part of a name or an email address.' : '',
    }) +
    // The server caps the list, so a search that finds nothing may simply be
    // looking past the cap rather than at someone who is not enrolled.
    (_people.length >= 500
      ? '<p class="portal-note">Showing the first 500 people, least complete ' +
        'first. Anyone beyond that is not searchable here.</p>'
      : '');
  }

  window.PortalAwareness = {
    async load() {
      var el = document.getElementById('tab-awareness');
      try {
        render(await P.get('awareness'));
      } catch (err) {
        el.innerHTML = P.viewHead('Security awareness') + P.errorState(err.message);
      }
    },
    render: render,
  };
})();
