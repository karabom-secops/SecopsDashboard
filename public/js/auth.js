(function () {
  'use strict';

  /**
   * public/js/auth.js
   * Loaded as the FIRST script on every protected page (index.html, upload.html).
   *
   * - Calls GET /api/auth/me on page load.
   * - If not authenticated, redirects to login.html.
   * - If authenticated, exposes window.currentUser = { id, username, role }.
   * - Wires the logout button (#logoutBtn).
   * - Shows/hides admin-only UI elements based on role.
   */

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

    // Managers have their own minimal page — send them there if they land here
    if (user.role === 'manager') {
      location.replace(BASE + 'manager.html');
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

    // ── Global tenant selector (superadmin only — shared across Vulns & Awareness) ──
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
              // Re-render whichever of the tenant-scoped tabs is currently visible
              var activePanel = document.querySelector('.tab-panel:not([hidden])');
              if (activePanel) {
                if (activePanel.id === 'tab-vulns' && typeof window.renderVulns === 'function') {
                  window.renderVulns();
                } else if (activePanel.id === 'tab-awareness' && typeof window.renderAwareness === 'function') {
                  window.renderAwareness();
                }
              }
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
      } else {
        roleEl.textContent = 'Read-only';
        roleEl.className   = 'header-role-badge role-readonly';
      }
    }

    // ── Show Admin item in side menu for admin or superadmin ────────────
    const sideAdminBtn = document.getElementById('sideAdminBtn');
    if (sideAdminBtn) {
      sideAdminBtn.hidden = (user.role === 'readonly');
    }

    // ── Hide admin-only action elements for readonly users ───────────────
    if (user.role === 'readonly') {
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
