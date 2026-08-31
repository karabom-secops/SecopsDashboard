/* portal-boot.js — session check, navigation, and first paint.
 *
 * Loaded last. Nothing touches the DOM until there is a confirmed session, so a
 * client never sees a flash of an empty dashboard before being bounced to login.
 *
 * Navigation is the DASHBOARD'S: sidenav.js owns the drawer, the rail, the
 * flyout and the persisted state, and calls window.switchTab — which this file
 * provides, the same contract app.js fulfils on the staff side. That is why the
 * portal collapses and remembers its nav exactly as the dashboard does, without
 * a second state machine.
 */
(function () {
  'use strict';

  var P = window.Portal;

  var VIEWS = {
    overview:  { label: 'Overview',        load: renderOverview },
    incidents: { label: 'Incidents',       load: function () { return window.PortalIncidents.load(); } },
    reports:   { label: 'Reports',         load: function () { return window.PortalReports.load(); } },
    vulns:     { label: 'Vulnerabilities', load: function () { return window.PortalVulns.load(); } },
    awareness: { label: 'Security Awareness', load: function () { return window.PortalAwareness.load(); } },
  };

  var _loaded = {};
  var _current = null;

  /**
   * The view asked for in the URL, captured AT LOAD.
   *
   * It cannot be read later. sidenav.js's refresh() calls switchTab() with the
   * first visible tab whenever no nav item is active yet — which is the case
   * during boot — and switchTab rewrites the URL to match. So by the time the
   * session check resolves, location.hash says 'overview' no matter what the
   * client actually opened, and every bookmarked view silently lands on the
   * landing page.
   */
  var _requested = (location.hash || '').replace('#', '');

  /* ── Overview ─────────────────────────────────────────────────────────── */

  /**
   * Loads score, incidents and reports together with allSettled rather than
   * awaiting in sequence: one section being unavailable — an un-migrated table,
   * a client with no scans yet — must not blank the other two.
   */
  async function renderOverview() {
    var el = document.getElementById('tab-overview');
    el.innerHTML = P.viewHead('Overview', 'Your security position at a glance.') +
      '<div class="loading-overlay"><div class="loading-spinner"></div><span>Loading…</span></div>';

    var r = await Promise.allSettled([
      P.get('secure-score'), P.get('incidents'), P.get('reports'),
    ]);
    var score     = r[0].status === 'fulfilled' ? r[0].value : null;
    var incidents = r[1].status === 'fulfilled' ? r[1].value : null;
    var reports   = r[2].status === 'fulfilled' ? r[2].value : null;

    var latest = reports && reports.reports && reports.reports.length ? reports.reports[0] : null;
    var cards = [];

    if (incidents) {
      cards.push({
        label: 'Open incidents', value: incidents.openCount,
        accent: incidents.openCount > 0 ? 'amber' : 'green',
        sub: incidents.total ? incidents.total + ' recorded in total' : '',
      });
    }
    if (score && score.available) {
      cards.push({
        label: 'Secure Score', value: score.score,
        accent: P.scoreAccent(score.score), sub: score.rating,
      });
    }
    if (latest) {
      cards.push({
        label: 'Latest report', value: latest.periodLabel || latest.period,
        accent: 'blue', sub: 'Published ' + P.fmtDate(latest.publishedAt),
      });
    }

    el.innerHTML =
      P.viewHead('Overview', 'Your security position at a glance.') +
      (cards.length ? P.statCards(cards) : '') +
      window.PortalScore.render(score) +
      (latest ? reportCard(latest) : '');
  }

  function reportCard(latest) {
    var base = P.BASE + 'api/portal/reports/' + encodeURIComponent(latest.id);
    return '<div class="portal-card">' +
      '<h3 class="portal-card-title">' + P.esc(latest.periodLabel || latest.period) +
        ' board report</h3>' +
      (latest.coverNote
        ? '<p class="portal-card-lead">' + P.esc(latest.coverNote) + '</p>' : '') +
      '<div class="portal-card-actions">' +
        '<a class="btn btn-primary btn-sm" href="' + base + '/download.pptx">Download report</a>' +
        (latest.canView
          ? ' <a class="btn btn-secondary btn-sm" target="_blank" rel="noopener" href="' +
            base + '/view">View in browser</a>'
          : '') +
      '</div></div>';
  }

  /* ── Navigation ───────────────────────────────────────────────────────── */

  /**
   * window.switchTab — the contract sidenav.js calls into.
   *
   * Same name and shape as app.js's, so the shared drawer needs no knowledge of
   * which of the two shells it is running in.
   */
  window.switchTab = async function switchTab(view) {
    if (!VIEWS[view]) view = 'overview';
    _current = view;
    window.currentTab = view;

    Object.keys(VIEWS).forEach(function (k) {
      var panel = document.getElementById('tab-' + k);
      if (panel) panel.hidden = k !== view;
    });

    if (window.SideNav && window.SideNav.syncActive) window.SideNav.syncActive(view);

    var label = document.getElementById('currentTabLabel');
    if (label) label.textContent = VIEWS[view].label;
    document.title = (window.__clientName ? window.__clientName + ' — ' : '') +
      VIEWS[view].label + ' — Reflex Client Portal';

    // The hash is the only routing here, but it makes a view bookmarkable and
    // the back button work. Guarded: replaceState throws a SecurityError in
    // restricted contexts (file://, some embedded webviews), and losing the URL
    // there must not take navigation down with it.
    try {
      if (location.hash !== '#' + view) history.replaceState(null, '', '#' + view);
    } catch (e) {
      // Falling back keeps the view bookmarkable where replaceState is blocked.
      // This fires hashchange, but the handler below ignores a hash that
      // already matches the current view, so there is no loop.
      location.hash = view;
    }

    // Each view loads once; returning to it does not re-fetch.
    if (!_loaded[view]) {
      _loaded[view] = true;
      try {
        await VIEWS[view].load();
      } catch (err) {
        _loaded[view] = false;                   // allow a retry
        var panel = document.getElementById('tab-' + view);
        if (panel) panel.innerHTML = P.viewHead(VIEWS[view].label) + P.errorState(err.message);
      }
    }
  };

  function wireChrome() {
    window.addEventListener('hashchange', function () {
      var v = location.hash.replace('#', '');
      if (v && v !== _current) window.switchTab(v);
    });

    var logout = document.getElementById('logoutBtn');
    if (logout) {
      logout.addEventListener('click', async function () {
        try {
          await fetch(P.BASE + 'api/auth/logout', { method: 'POST', credentials: 'same-origin' });
        } catch (e) { /* sign out locally regardless */ }
        location.replace(P.BASE + 'login.html');
      });
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
      // authenticated but not usable here — say so rather than showing an empty
      // portal the client cannot interpret.
      if (loading) {
        loading.className = '';
        loading.innerHTML = P.errorState(err.message);
      }
      return;
    }

    window.__clientName = me.clientName || '';

    var uname = document.getElementById('headerUsername');
    if (uname) uname.textContent = me.username || '';
    var role = document.getElementById('headerRole');
    if (role) { role.textContent = me.clientName || 'Client'; role.className = 'header-role-badge'; }
    var chip = document.getElementById('portalClientName');
    if (chip && me.clientName) { chip.textContent = me.clientName; chip.hidden = false; }

    if (me.preview) {
      var banner = document.getElementById('portalPreviewBanner');
      if (banner) {
        banner.hidden = false;
        var back = banner.querySelector('a');
        if (back) back.setAttribute('href', P.BASE);
      }
    }

    if (loading) loading.remove();
    wireChrome();

    // sidenav.js resolves visibility from .side-nav-item[hidden]; the portal's
    // items are never hidden, so this simply syncs its internal state.
    if (window.SideNav && window.SideNav.refresh) window.SideNav.refresh();
    document.dispatchEvent(new CustomEvent('nav:permissions-updated'));

    await window.switchTab(_requested || 'overview');
  })();
})();
