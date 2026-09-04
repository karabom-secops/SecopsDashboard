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

  /* ── Vulnerability remediation SLA ───────────────────────────────────────
     THE ONLY COPY IN THE BROWSER.

     lib/vuln-parser.js owns these numbers: it computes the due_date stored on
     every finding. Four tab modules each kept their own literal, and the board
     report's had drifted to 7/30/90/180 — so a 20-day-old High was "overdue"
     on the Vulnerabilities tab and "within SLA" on the slide the client
     receives, from the same row of the same table.

     Overwritten below from GET /api/auth/me. The literal is only the value
     before that call returns, and tests pin it to the parser so the fallback
     cannot drift either. Every consumer reads it through the accessor AT USE
     TIME — capturing it into a module-level const at load would freeze the
     fallback in place and undo the whole exercise. */
  window.VULN_SLA_DAYS = { Critical: 7, High: 14, Medium: 30, Low: 60 };

  /**
   * Days allowed to remediate a finding of this severity, or null when the
   * severity carries no SLA (Info, or anything unrecognised).
   *
   * Case-insensitive: the tabs hold severities lowercase, the report holds
   * them capitalised, and the parser stores them capitalised.
   */
  window.vulnSlaDays = function (severity) {
    var s = String(severity == null ? '' : severity).trim().toLowerCase();
    var map = window.VULN_SLA_DAYS || {};
    var hit = null;
    Object.keys(map).forEach(function (k) {
      if (k.toLowerCase() === s) hit = map[k];
    });
    return hit;
  };

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

    // Served from lib/vuln-parser.js, the module that writes the stored due
    // dates. Guarded: an older server that does not send it leaves the literal
    // above in place rather than blanking every SLA on the page.
    if (user.vulnSlaDays && typeof user.vulnSlaDays === 'object') {
      window.VULN_SLA_DAYS = user.vulnSlaDays;
    }

    // A portal client has no staff pages at all — that is the point of the
    // role — so landing here they would get "you do not have access to any
    // pages" instead of their own portal. Send them where they belong.
    // Checked before the manager rule so a client never falls through it.
    if (user.role === 'client') {
      location.replace(BASE + 'portal.html');
      return;
    }

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
            // Without an active tenant nothing gets `selected`, so the browser
            // displays the FIRST option as though it were active while the
            // session actually has none. Choosing that same visible option then
            // fires no change event, leaving the user permanently stuck with
            // every tenant-scoped screen empty. An explicit placeholder makes
            // the displayed state match reality and makes any real choice fire.
            var hasActive = tenants.some(function (t) { return t.id === user.tenantId; });
            if (!hasActive) {
              var ph = document.createElement('option');
              ph.value       = '';
              ph.textContent = '— Select organisation —';
              ph.disabled    = true;
              ph.selected    = true;
              tenantSwitcher.appendChild(ph);
            }

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
              if (isNaN(newId)) return;   // placeholder
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
    /*
     * `data-tab-also="a,b"` names other page keys reachable THROUGH this nav
     * item, so the item stays visible for someone who can view one of them but
     * not the item's own page.
     *
     * It exists because the Admin tab now hosts the Client Profile as a
     * sub-tab. Those are still two separate page keys with separate access
     * levels — a per-page override can grant client-profile and not admin — and
     * without this, such a user would hold a page with no route to it. The
     * sub-tab itself is gated on its own key inside tab-admin.js; this only
     * decides whether the door is visible, never what is behind it.
     */
    document.querySelectorAll('.side-nav-item[data-tab]').forEach(el => {
      const keys = [el.dataset.tab].concat(
        (el.dataset.tabAlso || '').split(',').map(k => k.trim()).filter(Boolean));
      el.hidden = !keys.some(k => window.canView(k));
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
        logoutBtn.disabled = true;
        try {
          // Raced against a timeout: an awaited fetch that never settles would
          // skip the redirect and leave the button looking dead. The local
          // sign-out must not depend on the server answering.
          await Promise.race([
            fetch(apiUrl('auth/logout'), {
              method:      'POST',
              credentials: 'same-origin',
            }),
            new Promise(function (r) { setTimeout(r, 3000); }),
          ]);
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
