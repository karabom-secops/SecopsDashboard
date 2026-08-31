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

  function render(data) {
    var el = document.getElementById('view-awareness');
    var head = '<div class="portal-view-head"><h1>Security awareness</h1>' +
      '<p class="portal-view-intro">How your people are progressing through ' +
      'security awareness training.</p></div>';

    if (!data || !data.available) {
      el.innerHTML = head + P.emptyState('◔', 'No training records yet',
        (data && data.reason) || 'Completion figures appear here once training records are loaded.');
      return;
    }

    var pct = data.completionPct || 0;
    var cards = [
      { label: 'Completion', value: pct + '%',
        tone: pct >= 90 ? 'good' : pct >= 70 ? 'warn' : 'bad' },
      { label: 'Staff covered', value: data.totalStaff || 0, tone: 'neutral' },
      { label: 'Completed', value: data.completed || 0, tone: 'neutral' },
      { label: 'Outstanding', value: data.outstanding || 0,
        tone: (data.outstanding || 0) > 0 ? 'warn' : 'good' },
    ];

    var people = data.people || [];
    var table = '';
    if (people.length) {
      var hasPct = people[0].pct !== undefined;
      table = '<h2 class="portal-card-title">By person</h2>' +
        P.table([
          { label: 'Name', raw: function (r) {
              return P.esc(r.name || '—') +
                (r.email ? '<div class="portal-sub"><span>' + P.esc(r.email) + '</span></div>' : '');
            } },
          hasPct
            ? { label: 'Completed', cls: 'col-narrow', raw: function (r) {
                return P.esc(r.completed + ' of ' + r.assigned); } }
            : { label: 'Outstanding', cls: 'col-num', raw: function (r) {
                return P.esc(r.outstanding); } },
          hasPct
            ? { label: 'Progress', cls: 'col-narrow', raw: function (r) {
                var tone = r.pct >= 90 ? 'good' : r.pct >= 70 ? 'warn' : 'bad';
                return '<span class="portal-score-bar tone-' + tone + '">' +
                  '<i style="width:' + Math.max(0, Math.min(100, r.pct)) + '%"></i></span>' +
                  '<span class="portal-progress-num">' + P.esc(r.pct) + '%</span>';
              } }
            : { label: '', cls: 'col-narrow', raw: function () { return ''; } },
        ], people, { emptyTitle: 'No individual records' }) +
        (people.length >= 500
          ? '<p class="portal-card-foot">Showing the first 500 people.</p>' : '');
    }

    el.innerHTML = head + P.statCards(cards) +
      '<p class="portal-card-foot">As at ' + P.esc(P.fmtDate(data.asOf)) + '.</p>' +
      table +
      // Provenance, where it matters: manual figures came from the client, and
      // presenting them as though we verified them would be dishonest.
      (data.selfReported
        ? '<div class="portal-note">These figures were supplied for an internally ' +
          'run training programme and have not been verified against records held ' +
          'by us.</div>'
        : '');
  }

  window.PortalAwareness = {
    async load() {
      var el = document.getElementById('view-awareness');
      try {
        render(await P.get('awareness'));
      } catch (err) {
        el.innerHTML = '<div class="portal-view-head"><h1>Security awareness</h1></div>' +
          P.errorState(err.message);
      }
    },
    render: render,
  };
})();
