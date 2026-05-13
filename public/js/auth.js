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

    // Expose globally so other scripts can read role etc.
    // Expose globally so other scripts can read role etc.
    window.currentUser = user;

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
      } else {
        roleEl.textContent = 'Read-only';
        roleEl.className   = 'header-role-badge role-readonly';
      }
    }

    // ── Show Admin tab for admin or superadmin ───────────────────────────
    const adminTabBtn = document.getElementById('tab-admin-btn');
    if (adminTabBtn) {
      adminTabBtn.hidden = (user.role === 'readonly');
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
