(function () {
  'use strict';

  /**
   * public/js/auth.js
   * Loaded as the FIRST script on every protected page (index.html, upload.html).
   *
   * - Calls GET /api/auth/me on page load.
   * - If not authenticated, redirects to login.html.
   * - If authenticated, exposes window.currentUser = { id, username, role }.
   * - Exposes window.canView(pageKey) / window.canWrite(pageKey), which every
   *   other script uses instead of comparing role strings. The access map and
   *   page catalog both come from the server (lib/pages.js) so page keys are
   *   never duplicated here.
   * - Wires the logout button (#logoutBtn).
   * - Hides nav items and edit controls the user has no access to.
   */

  var LEVEL_RANK = { none: 0, read: 1, write: 2 };

  // Defined up front so scripts loaded before init() resolves can call them.
  window.pageAccess = {};
  window.pageCatalog = [];

  function level(pageKey) {
    return (window.pageAccess && window.pageAccess[pageKey]) || 'none';
  }
  window.canView  = function (pageKey) { return LEVEL_RANK[level(pageKey)] >= 1; };
  window.canWrite = function (pageKey) { return LEVEL_RANK[level(pageKey)] >= 2; };

  const BASE = (function () {
    // Derive base URL from <base href> so this works under /secops/ prefix.
    const base = document.querySelector('base');
    return base ? base.href : '/';
  })();

  function apiUrl(path) {
    return BASE + 'api/' + path;
  }

  async function init() {
    let user;
    try {
      const res = await fetch(apiUrl('auth/me'), { credentials: 'same-origin' });
      if (!res.ok) {
        location.replace(BASE + 'login.html');
        return;
      }
      user = await res.json();
    } catch (_) {
      location.replace(BASE + 'login.html');
      return;
    }

    window.pageAccess  = user.pageAccess || {};
    window.pageCatalog = user.pages || [];
    window.roleCatalog = user.roles || [];

    // Users whose only page is the manager dashboard get sent there — unless
    // that is already where we are, which would loop.
    var onManagerPage = /manager\.html$/.test(location.pathname);
    var viewableTabs = window.pageCatalog
      .filter(function (p) { return p.type === 'tab' && window.canView(p.key); });
    if (!onManagerPage && viewableTabs.length === 0 && window.canView('manager')) {
      location.replace(BASE + 'manager.html');
      return;
    }

    // Conversely, someone with no access to the manager dashboard should not
    // be sitting on it.
    if (onManagerPage && !window.canView('manager')) {
      location.replace(BASE + (viewableTabs.length ? '' : 'login.html'));
      return;
    }

    // The upload page only makes sense with write access to it.
    if (/upload\.html$/.test(location.pathname) && !window.canWrite('upload')) {
      location.replace(BASE + (viewableTabs.length ? '' : 'login.html'));
      return;
    }

    // Expose globally so other scripts can read role etc.
    window.currentUser = user;

    // Notify other tab scripts that auth is resolved
    document.dispatchEvent(new CustomEvent('authReady', { detail: user }));

    // ── MFA banner for grace-period superadmins ──────────────────────────
    if (user.role === 'superadmin' && !user.totpEnabled) {
      var banner = document.getElementById('mfaBanner');
      if (banner) {
        banner.hidden = false;
        var bannerLink = document.getElementById('mfaBannerLink');
        if (bannerLink) {
          bannerLink.addEventListener('click', function (e) {
            e.preventDefault();
            // Switch to the Admin tab and scroll to MFA section
            if (typeof window.switchTab === 'function') window.switchTab('admin');
            setTimeout(function () {
              var mfaSection = document.getElementById('mfaSection');
              if (mfaSection) mfaSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }, 100);
          });
        }
      }
    }

    // ── Tenant switcher (shown when user is assigned to 2+ tenants) ──────
    const tenantSwitcher = document.getElementById('tenantSwitcher');
    if (tenantSwitcher && Array.isArray(user.tenantIds) && user.tenantIds.length > 1) {
      try {
        const tRes = await fetch(apiUrl('auth/my-tenants'), { credentials: 'same-origin' });
        if (tRes.ok) {
          const tenants = await tRes.json();
          if (tenants.length > 1) {
            tenants.forEach(function (t) {
              var opt = document.createElement('option');
              opt.value = t.id;
              opt.textContent = t.name;
              if (t.id === user.tenantId) opt.selected = true;
              tenantSwitcher.appendChild(opt);
            });
            tenantSwitcher.hidden = false;
            tenantSwitcher.addEventListener('change', async function () {
              var newId = parseInt(tenantSwitcher.value, 10);
              try {
                await fetch(apiUrl('auth/switch-tenant'), {
                  method: 'POST',
                  credentials: 'same-origin',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ tenantId: newId }),
                });
              } catch (_) { /* ignore */ }
              location.reload();
            });
          }
        }
      } catch (_) { /* non-critical */ }
    }

    // ── Global tenant selector (superadmin only — scopes every tenant-aware tab) ──
    window.globalTenantId = null;
    if (user.role === 'superadmin') {
      const globalWrap = document.getElementById('globalTenantFilterWrap');
      const globalSel  = document.getElementById('globalTenantSelect');
      if (globalWrap && globalSel) {
        try {
          const tRes = await fetch(apiUrl('tenants'), { credentials: 'same-origin' });
          if (tRes.ok) {
            const tenants = await tRes.json();
            tenants.forEach(function (t) {
              var opt = document.createElement('option');
              opt.value = t.id;
              opt.textContent = t.name;
              globalSel.appendChild(opt);
            });
            globalWrap.hidden = false;
            globalSel.addEventListener('change', function () {
              window.globalTenantId = globalSel.value ? parseInt(globalSel.value, 10) : null;
              // app.js re-renders the active tab. Announcing the change rather
              // than naming tabs here is what keeps this correct as tabs are
              // added — the old version listed Vulns and Awareness by hand and
              // left every other tenant-scoped tab showing the previous
              // customer's data.
              document.dispatchEvent(new CustomEvent('tenant:changed', {
                detail: { tenantId: window.globalTenantId },
              }));
            });
          }
        } catch (_) { /* non-critical */ }
      }
    }

    // ── Populate header user info ────────────────────────────────────────
    const usernameEl = document.getElementById('headerUsername');
    if (usernameEl) usernameEl.textContent = user.username;

    const roleEl = document.getElementById('headerRole');
    if (roleEl) {
      if (user.role === 'superadmin') {
        roleEl.textContent = 'Super Admin';
        roleEl.className   = 'header-role-badge role-superadmin';
      } else if (user.role === 'admin') {
        roleEl.textContent = 'Admin';
        roleEl.className   = 'header-role-badge role-admin';
      } else if (user.role === 'manager') {
        roleEl.textContent = 'Manager';
        roleEl.className   = 'header-role-badge role-manager';
      } else if (user.role === 'sales') {
        roleEl.textContent = 'Sales';
        roleEl.className   = 'header-role-badge role-sales';
      } else {
        roleEl.textContent = 'Read-only';
        roleEl.className   = 'header-role-badge role-readonly';
      }
    }

    // ── Hide side-nav items for pages the user cannot view ───────────────
    document.querySelectorAll('.side-nav-item[data-tab]').forEach(el => {
      el.hidden = !window.canView(el.dataset.tab);
    });

    // Roll that up to the category headers — otherwise a readonly or sales
    // user is shown accordions that open onto nothing.
    document.querySelectorAll('.side-nav-group').forEach(group => {
      group.hidden = !group.querySelector('.side-nav-item[data-tab]:not([hidden])');
    });

    // Hand back to sidenav.js: re-run the accordion, repair the active tab if
    // permissions just removed it, and drop the nav chrome if nothing is left.
    // An event rather than a direct call because auth.js resolves
    // asynchronously and must not depend on script order.
    document.dispatchEvent(new CustomEvent('nav:permissions-updated'));

    // Overrides can leave someone with nothing at all — say so rather than
    // showing an empty dashboard shell.
    if (viewableTabs.length === 0 && !onManagerPage) {
      const dash = document.getElementById('dashboard');
      if (dash) {
        dash.hidden = false;
        dash.innerHTML = '<div class="admin-table-empty" style="padding:3rem;text-align:center">' +
          'You do not currently have access to any pages. Please contact your administrator.</div>';
      }
    }

    // Standalone pages have their own entry points rather than a data-tab.
    const managerBtn = document.getElementById('managerDashboardBtn');
    if (managerBtn) managerBtn.hidden = !window.canView('manager');

    document.querySelectorAll('.side-upload-btn').forEach(el => {
      el.hidden = !window.canWrite('upload');
    });

    // ── Hide write controls the user has no permission for ───────────────
    // [data-page-write="<key>"] gates on a specific page; [data-admin-only]
    // is the older global marker, kept working for existing markup.
    document.querySelectorAll('[data-page-write]').forEach(el => {
      el.hidden = !window.canWrite(el.dataset.pageWrite);
    });

    const canWriteAnything = window.pageCatalog.some(p => window.canWrite(p.key));
    if (!canWriteAnything) {
      document.querySelectorAll('[data-admin-only]').forEach(el => {
        el.hidden = true;
      });
    }

    // ── Logout button ────────────────────────────────────────────────────
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', async function () {
        try {
          await fetch(apiUrl('auth/logout'), {
            method:      'POST',
            credentials: 'same-origin',
          });
        } catch (_) { /* ignore network errors on logout */ }
        location.replace(BASE + 'login.html');
      });
    }
  }

  // Run immediately on DOMContentLoaded (or right away if already loaded).
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
