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
    var cards = [
      { label: 'Completion', value: pct + '%',
        accent: pct >= 90 ? 'green' : pct >= 70 ? 'amber' : 'red' },
      { label: 'Staff covered', value: data.totalStaff || 0 },
      { label: 'Completed',     value: data.completed || 0 },
      { label: 'Outstanding',   value: data.outstanding || 0,
        accent: (data.outstanding || 0) > 0 ? 'amber' : 'green' },
    ];

    var people = data.people || [];
    var table = '';
    if (people.length) {
      var hasPct = people[0].pct !== undefined;
      table = '<h3 class="portal-card-title">By person</h3>' +
        P.table([
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
        ], people, { emptyTitle: 'No individual records' }) +
        (people.length >= 500
          ? '<p class="portal-note">Showing the first 500 people.</p>' : '');
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
