/* portal-boot.js — session check, navigation, and first paint.
 *
 * Loaded last. Nothing else in the portal touches the DOM until this has
 * confirmed there is a session, because a client should never see a flash of
 * an empty dashboard before being bounced to the login page.
 */
(function () {
  'use strict';

  var P = window.Portal;

  var VIEWS = {
    overview:  { load: renderOverview },
    incidents: { load: function () { return window.PortalIncidents.load(); } },
    reports:   { load: function () { return window.PortalReports.load(); } },
    vulns:     { load: function () { return window.PortalVulns.load(); } },
    awareness: { load: function () { return window.PortalAwareness.load(); } },
  };

  var _loaded = {};
  var _current = null;

  /* ── Overview ─────────────────────────────────────────────────────────── */

  /**
   * The landing view: posture, then the two things a client came to check.
   *
   * Loads score, incidents and reports together with allSettled rather than
   * await-in-sequence: one section being unavailable (an un-migrated table, a
   * client with no scans yet) must not blank the other two.
   */
  async function renderOverview() {
    var el = document.getElementById('view-overview');
    el.innerHTML = '<div class="portal-loading">Loading…</div>';

    var results = await Promise.allSettled([
      P.get('secure-score'),
      P.get('incidents'),
      P.get('reports'),
    ]);
    var score     = results[0].status === 'fulfilled' ? results[0].value : null;
    var incidents = results[1].status === 'fulfilled' ? results[1].value : null;
    var reports   = results[2].status === 'fulfilled' ? results[2].value : null;

    var openCount = incidents ? incidents.openCount : null;
    var latest = reports && reports.reports && reports.reports.length ? reports.reports[0] : null;

    var cards = [];
    if (openCount !== null) {
      cards.push({
        label: 'Open incidents', value: openCount,
        tone: openCount > 0 ? 'warn' : 'good',
        sub: incidents.total ? incidents.total + ' in total' : '',
      });
    }
    if (latest) {
      cards.push({
        label: 'Latest report', value: latest.periodLabel || latest.period,
        tone: 'neutral', sub: 'Published ' + P.fmtDate(latest.publishedAt),
      });
    }

    el.innerHTML =
      '<div class="portal-view-head">' +
        '<h1>Overview</h1>' +
        '<p class="portal-view-intro">Your security position at a glance.</p>' +
      '</div>' +
      (cards.length ? P.statCards(cards) : '') +
      window.PortalScore.render(score) +
      (latest
        ? '<section class="portal-card">' +
            '<h2 class="portal-card-title">' + P.esc(latest.periodLabel || latest.period) +
              ' board report</h2>' +
            (latest.coverNote ? '<p class="portal-dialog-summary">' +
              P.esc(latest.coverNote) + '</p>' : '') +
            '<p><a class="btn btn-primary btn-sm" href="' + P.BASE +
              'api/portal/reports/' + encodeURIComponent(latest.id) + '/download.pptx">' +
              'Download report</a> ' +
              (latest.canView
                ? '<a class="btn btn-secondary btn-sm" target="_blank" rel="noopener" href="' +
                  P.BASE + 'api/portal/reports/' + encodeURIComponent(latest.id) +
                  '/view">View in browser</a>'
                : '') +
            '</p>' +
          '</section>'
        : '');
  }

  /* ── Navigation ───────────────────────────────────────────────────────── */

  async function show(view) {
    if (!VIEWS[view]) view = 'overview';
    _current = view;

    Object.keys(VIEWS).forEach(function (k) {
      var panel = document.getElementById('view-' + k);
      if (panel) panel.hidden = k !== view;
    });
    Array.prototype.forEach.call(document.querySelectorAll('.portal-tab'), function (b) {
      var on = b.dataset.view === view;
      b.classList.toggle('is-active', on);
      b.setAttribute('aria-current', on ? 'page' : 'false');
    });

    // The hash is the only routing this page has, but it means a client can
    // bookmark "my incidents" and use the back button.
    //
    // Guarded: replaceState throws a SecurityError in restricted contexts
    // (file://, some embedded webviews). Losing the bookmarkable URL there is a
    // small loss; letting it take the whole navigation down is not.
    try {
      if (location.hash !== '#' + view) history.replaceState(null, '', '#' + view);
    } catch (e) { location.hash = view; }

    // Each view loads once; returning to it does not re-fetch.
    if (!_loaded[view]) {
      _loaded[view] = true;
      try {
        await VIEWS[view].load();
      } catch (err) {
        _loaded[view] = false;    // let a retry happen
        var panel = document.getElementById('view-' + view);
        if (panel) panel.innerHTML = P.errorState(err.message);
      }
    }
  }

  function wireNav() {
    document.getElementById('portalNav').addEventListener('click', function (ev) {
      var btn = ev.target.closest('.portal-tab');
      if (btn) show(btn.dataset.view);
    });
    window.addEventListener('hashchange', function () {
      var v = location.hash.replace('#', '');
      if (v && v !== _current) show(v);
    });

    document.getElementById('portalLogout').addEventListener('click', async function () {
      try {
        await fetch(P.BASE + 'api/auth/logout', { method: 'POST', credentials: 'same-origin' });
      } catch (e) { /* sign out locally regardless */ }
      location.replace(P.BASE + 'login.html');
    });

    var themeBtn = document.getElementById('portalThemeToggle');
    if (themeBtn && window.Theme) {
      themeBtn.addEventListener('click', function () { window.Theme.cycle(); });
    }
  }

  /* ── Boot ─────────────────────────────────────────────────────────────── */

  (async function boot() {
    var loading = document.getElementById('portalLoading');
    var me;
    try {
      me = await P.get('me');
    } catch (err) {
      // P.get already redirects on 401. Anything else means the account is
      // authenticated but not usable here — say so rather than showing an
      // empty portal the client cannot interpret.
      if (loading) {
        loading.className = '';
        loading.innerHTML = P.errorState(err.message);
      }
      return;
    }

    document.getElementById('portalClientName').textContent = me.clientName || '';
    document.getElementById('portalUser').textContent = me.username || '';
    document.getElementById('portalFooterNote').textContent =
      me.clientName ? 'Prepared for ' + me.clientName : '';
    if (me.clientName) document.title = me.clientName + ' — Reflex Client Portal';

    // Staff previewing should know they are looking at a client's view.
    if (me.preview) {
      var banner = document.getElementById('portalPreviewBanner');
      if (banner) banner.hidden = false;
    }

    if (loading) loading.remove();
    wireNav();
    await show((location.hash || '#overview').replace('#', ''));
  })();
})();
