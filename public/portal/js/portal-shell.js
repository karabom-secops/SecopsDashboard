/* portal-shell.js — the portal's small toolkit.
 *
 * Everything here emits the DASHBOARD'S component classes — .section-header,
 * .stat-grid/.stat-card, .data-table, .table-scroll, .btn — rather than a
 * parallel set. That is what makes the portal look like the same product: the
 * cards, tables and buttons are literally the same components, so a change to
 * the design system reaches both.
 *
 * The staff dashboard carries fifteen private copies of `esc` and ten of the
 * tenant query-param helper. The portal has one of each, on purpose.
 *
 * Read-only: there is no POST helper, and adding one should feel like a
 * decision rather than a convenience.
 */
(function () {
  'use strict';

  var BASE = (function () {
    var b = document.querySelector('base');
    return b ? b.href : '/';
  })();

  /** Full 5-character escape. The 4-character version in tab-admin.js leaves
   *  single quotes live, which is a real hole inside an attribute. */
  function esc(v) {
    return String(v === null || v === undefined ? '' : v)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  /**
   * The only way this app talks to the server.
   *
   * There is no tenant parameter and no way to add one: the server takes the
   * tenant from the session, so a portal page has nothing to pass and nothing
   * to get wrong.
   */
  async function get(pathname) {
    var res = await fetch(BASE + 'api/portal/' + pathname, { credentials: 'same-origin' });
    if (res.status === 401) { location.replace(BASE + 'login.html'); throw new Error('signed out'); }
    var data = null;
    try { data = await res.json(); } catch (e) { data = null; }
    if (!res.ok) throw new Error((data && data.error) || 'Request failed (' + res.status + ').');
    return data;
  }

  /** The dashboard's page heading block. */
  function viewHead(title, intro) {
    return '<div class="section-header">' +
        '<h2 class="section-title">' + esc(title) + '</h2>' +
      '</div>' +
      (intro ? '<p class="portal-view-intro">' + esc(intro) + '</p>' : '');
  }

  /** The dashboard's empty state, so "nothing here" looks the same everywhere. */
  function emptyState(title, detail) {
    return '<div class="empty-state"><div class="empty-state-container">' +
      '<p class="empty-state-title">' + esc(title) + '</p>' +
      (detail ? '<p class="empty-state-description">' + esc(detail) + '</p>' : '') +
      '</div></div>';
  }

  function errorState(message) {
    return '<div class="empty-state"><div class="empty-state-container">' +
      '<p class="empty-state-title">This section could not be loaded</p>' +
      '<p class="empty-state-description">' + esc(message) + '</p>' +
      '</div></div>';
  }

  /**
   * Stat cards, using the dashboard's .stat-card and its accent modifiers.
   *
   * Colour only where it means something: an amber tile beside three neutral
   * ones is a signal; four accented tiles are wallpaper.
   */
  function statCards(cards) {
    return '<div class="stat-grid">' + cards.map(function (c) {
      return '<div class="stat-card' + (c.accent ? ' accent-' + esc(c.accent) : '') + '">' +
        '<div class="stat-label">' + esc(c.label) + '</div>' +
        '<div class="stat-value">' + esc(c.value) + '</div>' +
        (c.sub ? '<div class="stat-delta">' + esc(c.sub) + '</div>' : '') +
        '</div>';
    }).join('') + '</div>';
  }

  /** The band a 0-100 score falls in, as a .stat-card accent. */
  function scoreAccent(score) {
    var n = Number(score) || 0;
    return n >= 70 ? 'green' : n >= 50 ? 'amber' : 'red';
  }

  /**
   * One table renderer, emitting the dashboard's .data-table inside its
   * .table-scroll wrapper so wide content scrolls in its own box rather than
   * pushing the page sideways.
   *
   * cols: [{ label, key, cls, raw(row) }]
   */
  function table(cols, rows, opts) {
    var o = opts || {};
    if (!rows.length) return emptyState(o.emptyTitle || 'Nothing to show', o.emptyDetail);

    return '<div class="table-scroll"><table class="data-table">' +
      '<thead><tr>' + cols.map(function (c) {
        return '<th scope="col"' + (c.cls ? ' class="' + esc(c.cls) + '"' : '') + '>' +
          esc(c.label) + '</th>';
      }).join('') + '</tr></thead><tbody>' +
      rows.map(function (r) {
        return '<tr>' + cols.map(function (c) {
          var val = c.raw ? c.raw(r)
            : esc(r[c.key] === null || r[c.key] === undefined ? '—' : r[c.key]);
          return '<td' + (c.cls ? ' class="' + esc(c.cls) + '"' : '') + '>' + val + '</td>';
        }).join('') + '</tr>';
      }).join('') +
      '</tbody></table></div>';
  }

  /** Severity and status use the dashboard's .badge, not a bespoke pill. */
  var SEVERITY_BADGE = {
    critical: 'badge-red', high: 'badge-red',
    medium: 'badge-amber', low: 'badge-muted',
  };

  function sevPill(severity) {
    var s = String(severity || '').toLowerCase();
    var label = s ? s.charAt(0).toUpperCase() + s.slice(1) : 'Unrated';
    // Critical and high share badge-red deliberately: the dashboard's palette
    // has one red, and inventing a darker one here would make the portal the
    // only place in the product with a fifth severity colour.
    return '<span class="badge ' + (SEVERITY_BADGE[s] || 'badge-muted') + '">' +
      esc(label) + '</span>';
  }

  function statusPill(status, closed) {
    return '<span class="badge ' + (closed ? 'badge-green' : 'badge-blue') + '">' +
      esc(status || (closed ? 'Closed' : 'Open')) + '</span>';
  }

  var DATE_OPTS = { day: 'numeric', month: 'short', year: 'numeric' };
  function fmtDate(v) {
    if (!v) return '—';
    var d = new Date(v);
    return isNaN(d.getTime()) ? '—' : d.toLocaleDateString('en-ZA', DATE_OPTS);
  }

  function fmtBytes(n) {
    var b = Number(n) || 0;
    if (!b) return '—';
    if (b < 1024 * 1024) return Math.round(b / 1024) + ' KB';
    return (b / (1024 * 1024)).toFixed(1) + ' MB';
  }

  window.Portal = {
    BASE: BASE,
    esc: esc,
    get: get,
    viewHead: viewHead,
    emptyState: emptyState,
    errorState: errorState,
    statCards: statCards,
    scoreAccent: scoreAccent,
    table: table,
    sevPill: sevPill,
    statusPill: statusPill,
    fmtDate: fmtDate,
    fmtBytes: fmtBytes,
  };
})();
