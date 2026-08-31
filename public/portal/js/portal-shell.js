/* portal-shell.js — the portal's own small toolkit.
 *
 * The staff dashboard carries fifteen private copies of `esc` and ten of the
 * tenant query-param helper. The portal starts with one of each, on purpose:
 * it is a new surface and there is no reason to inherit that.
 *
 * Everything here is read-only. There is no POST helper, and adding one should
 * feel like a decision rather than a convenience.
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
   * NOTE there is no tenant parameter and no way to add one: the server takes
   * the tenant from the session, so a portal page has nothing to pass and
   * nothing to get wrong.
   */
  async function get(pathname) {
    var res = await fetch(BASE + 'api/portal/' + pathname, { credentials: 'same-origin' });
    if (res.status === 401) { location.replace(BASE + 'login.html'); throw new Error('signed out'); }
    var data = null;
    try { data = await res.json(); } catch (e) { data = null; }
    if (!res.ok) {
      throw new Error((data && data.error) || 'Request failed (' + res.status + ').');
    }
    return data;
  }

  /** A section that has nothing to show says WHY, never renders an empty box. */
  function emptyState(icon, title, detail) {
    return '<div class="portal-empty">' +
      '<div class="portal-empty-icon" aria-hidden="true">' + esc(icon) + '</div>' +
      '<p class="portal-empty-title">' + esc(title) + '</p>' +
      (detail ? '<p class="portal-empty-detail">' + esc(detail) + '</p>' : '') +
      '</div>';
  }

  function errorState(message) {
    return '<div class="portal-empty portal-empty-error">' +
      '<div class="portal-empty-icon" aria-hidden="true">!</div>' +
      '<p class="portal-empty-title">This section could not be loaded</p>' +
      '<p class="portal-empty-detail">' + esc(message) + '</p></div>';
  }

  function statCards(cards) {
    return '<div class="portal-stats">' + cards.map(function (c) {
      return '<div class="portal-stat' + (c.tone ? ' tone-' + esc(c.tone) : '') + '">' +
        '<div class="portal-stat-value">' + esc(c.value) + '</div>' +
        '<div class="portal-stat-label">' + esc(c.label) + '</div>' +
        (c.sub ? '<div class="portal-stat-sub">' + esc(c.sub) + '</div>' : '') +
        '</div>';
    }).join('') + '</div>';
  }

  /**
   * One table renderer for the whole portal.
   * cols: [{ label, key, cls, raw(row) }]
   */
  function table(cols, rows, opts) {
    var o = opts || {};
    if (!rows.length) return emptyState(o.emptyIcon || '—', o.emptyTitle || 'Nothing to show');

    return '<div class="portal-table-wrap"><table class="portal-table">' +
      '<thead><tr>' + cols.map(function (c) {
        return '<th scope="col"' + (c.cls ? ' class="' + esc(c.cls) + '"' : '') + '>' +
          esc(c.label) + '</th>';
      }).join('') + '</tr></thead><tbody>' +
      rows.map(function (r) {
        return '<tr' + (o.rowAttrs ? ' ' + o.rowAttrs(r) : '') + '>' + cols.map(function (c) {
          var val = c.raw ? c.raw(r) : esc(r[c.key] === null || r[c.key] === undefined ? '—' : r[c.key]);
          return '<td' + (c.cls ? ' class="' + esc(c.cls) + '"' : '') + '>' + val + '</td>';
        }).join('') + '</tr>';
      }).join('') +
      '</tbody></table></div>';
  }

  function sevPill(severity) {
    var s = String(severity || '').toLowerCase();
    var label = s ? s.charAt(0).toUpperCase() + s.slice(1) : 'Unrated';
    return '<span class="portal-pill sev-' + esc(s || 'none') + '">' + esc(label) + '</span>';
  }

  function statusPill(status, closed) {
    return '<span class="portal-pill ' + (closed ? 'st-closed' : 'st-open') + '">' +
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

  /** Days between a date and now; negative when in the past. */
  function daysFromNow(v) {
    if (!v) return null;
    var d = new Date(v);
    if (isNaN(d.getTime())) return null;
    return Math.round((d.getTime() - Date.now()) / 86400000);
  }

  window.Portal = {
    BASE: BASE,
    esc: esc,
    get: get,
    emptyState: emptyState,
    errorState: errorState,
    statCards: statCards,
    table: table,
    sevPill: sevPill,
    statusPill: statusPill,
    fmtDate: fmtDate,
    fmtBytes: fmtBytes,
    daysFromNow: daysFromNow,
  };
})();
