(function () {
  'use strict';

  /**
   * public/js/tab-admin.js
   * Admin tab — dual-mode:
   *   superadmin : Tenant management section + full user management (all tenants).
   *   admin      : User management within their own tenant only.
   */

  const BASE = (function () {
    const base = document.querySelector('base');
    return base ? base.href : '/';
  })();

  function apiUrl(path) {
    return BASE + 'api/' + path;
  }

  function escapeHtml(str) {
    return String(str ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  function formatDate(iso) {
    if (!iso) return '—';
    try {
      return new Date(iso).toLocaleString(undefined, {
        year: 'numeric', month: 'short', day: '2-digit',
        hour: '2-digit', minute: '2-digit',
      });
    } catch (_) { return iso; }
  }

  function isSuperAdmin() {
    return window.currentUser && window.currentUser.role === 'superadmin';
  }

  function showAdminError(msg) {
    const el = document.getElementById('adminError');
    if (!el) return;
    el.textContent = msg;
    el.hidden = !msg;
  }

  function showAdminSuccess(msg) {
    const el = document.getElementById('adminSuccess');
    if (!el) return;
    el.textContent = msg;
    el.hidden = !msg;
    if (msg) setTimeout(() => { el.hidden = true; }, 4000);
  }

  // ── Tenant list (superadmin only) ─────────────────────────────────────────

  let _tenants = [];

  async function fetchTenants() {
    try {
      const res = await fetch(apiUrl('tenants'), { credentials: 'same-origin' });
      if (res.ok) _tenants = await res.json();
    } catch (_) { _tenants = []; }
    return _tenants;
  }

  async function renderTenants() {
    const tbody = document.getElementById('tenantTableBody');
    if (!tbody) return;

    await fetchTenants();

    if (_tenants.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" class="admin-table-empty">No tenants yet.</td></tr>';
      return;
    }

    tbody.innerHTML = _tenants.map(t => `
      <tr>
        <td>${escapeHtml(t.name)}</td>
        <td><code>${escapeHtml(t.slug)}</code></td>
        <td>${t.user_count}</td>
        <td class="admin-actions">
          <button class="btn btn-danger btn-sm"
                  data-action="delete-tenant"
                  data-id="${t.id}"
                  data-name="${escapeHtml(t.name)}"
                  title="${t.user_count > 0 ? 'Remove all users first' : 'Delete tenant'}"
                  ${t.user_count > 0 ? 'disabled' : ''}>
            Delete
          </button>
        </td>
      </tr>
    `).join('');
  }

  async function handleAddTenant(e) {
    e.preventDefault();
    showAdminError('');
    const name = document.getElementById('newTenantName').value.trim();
    const slug = document.getElementById('newTenantSlug').value.trim().toLowerCase();
    const btn  = document.getElementById('addTenantBtn');
    btn.disabled = true;
    try {
      const res  = await fetch(apiUrl('tenants'), {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, slug }),
      });
      const data = await res.json();
      if (!res.ok) {
        showAdminError(data.error || 'Failed to create tenant.');
      } else {
        document.getElementById('addTenantForm').reset();
        showAdminSuccess(`Tenant "${data.name}" created.`);
        await renderTenants();
        await populateTenantDropdowns();
      }
    } catch (err) {
      showAdminError('Network error: ' + err.message);
    } finally {
      btn.disabled = false;
    }
  }

  async function handleDeleteTenant(tenantId, name) {
    if (!confirm(`Delete tenant "${name}"?\n\nThis will fail if users or scans are still assigned to it.`)) return;
    showAdminError('');
    try {
      const res  = await fetch(apiUrl(`tenants/${tenantId}`), {
        method: 'DELETE', credentials: 'same-origin',
      });
      const data = await res.json();
      if (!res.ok) {
        showAdminError(data.error || 'Delete failed.');
      } else {
        showAdminSuccess(`Tenant "${name}" deleted.`);
        await renderTenants();
        await populateTenantDropdowns();
      }
    } catch (err) {
      showAdminError('Network error: ' + err.message);
    }
  }

  function bindSlugAutoFill() {
    const nameInput = document.getElementById('newTenantName');
    const slugInput = document.getElementById('newTenantSlug');
    if (!nameInput || !slugInput) return;
    nameInput.addEventListener('input', () => {
      slugInput.value = nameInput.value
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 30);
    });
  }

  // ── Tenant dropdowns in user forms ────────────────────────────────────────

  async function populateTenantDropdowns() {
    const selects = document.querySelectorAll('.tenant-dropdown');
    if (selects.length === 0 && !document.getElementById('newUserTenants')) return;
    if (_tenants.length === 0) await fetchTenants();
    const opts = '<option value="">&#8212; Select tenant &#8212;</option>' +
      _tenants.map(t => `<option value="${t.id}">${escapeHtml(t.name)}</option>`).join('');
    selects.forEach(sel => {
      const current = sel.value;
      sel.innerHTML = opts;
      if (current) sel.value = current;
    });
    // Refresh multi-selects too
    populateTenantMultiSelect(document.getElementById('newUserTenants'), []);
  }

  function populateTenantMultiSelect(selectEl, selectedIds) {
    if (!selectEl || _tenants.length === 0) return;
    selectEl.innerHTML = _tenants
      .map(t => {
        const sel = selectedIds && selectedIds.includes(t.id) ? ' selected' : '';
        return `<option value="${t.id}"${sel}>${escapeHtml(t.name)}</option>`;
      })
      .join('');
  }

  // ── User table ────────────────────────────────────────────────────────────

  async function renderUsers() {
    const tbody = document.getElementById('userTableBody');
    if (!tbody) return;

    try {
      const res  = await fetch(apiUrl('users'), { credentials: 'same-origin' });
      const data = await res.json();

      if (!res.ok) {
        tbody.innerHTML = `<tr><td colspan="7" class="admin-table-empty">${escapeHtml(data.error || 'Failed to load users.')}</td></tr>`;
        return;
      }

      if (data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="admin-table-empty">No users found.</td></tr>';
        return;
      }

      const showTenantCol = isSuperAdmin();

      tbody.innerHTML = data.map(u => {
        const isSelf   = window.currentUser && u.id === window.currentUser.id;
        const isSso    = u.auth_type === 'saml';
        const roleTag  = u.role === 'superadmin'
          ? '<span class="role-badge role-superadmin">Super Admin</span>'
          : u.role === 'admin'
            ? '<span class="role-badge role-admin">Admin</span>'
            : u.role === 'manager'
              ? '<span class="role-badge role-manager">Manager</span>'
              : u.role === 'sales'
                ? '<span class="role-badge role-sales">Sales</span>'
                // An external account must never be mistaken for an internal
                // one; the old chain fell through to "Read-only", which is a
                // staff role with read on every tab.
                : u.role === 'client'
                  ? '<span class="role-badge role-client">Client</span>'
                  : '<span class="role-badge role-readonly">Read-only</span>';
        const ssoTag   = isSso ? ' <span class="role-badge">SSO</span>' : '';
        const tenantCell = showTenantCol
          ? `<td>${escapeHtml(u.tenant_name || '—')}</td>`
          : '';
        const delBtn = isSelf
          ? '<span class="admin-self-label">you</span>'
          : `<button class="btn btn-danger btn-sm" data-action="delete-user" data-id="${u.id}" data-username="${escapeHtml(u.username)}">Delete</button>`;

        /* ── Account state ────────────────────────────────────────────────
           Suspended is the one that changes what the account can do, so it
           reads as a warning; the other two are informational. Shown for
           every user, not only clients — the columns apply to everyone. */
        const suspended = u.is_active === false;
        const stateTags = [
          suspended ? '<span class="role-badge state-suspended">Suspended</span>' : '',
          // Only staff are ever asked to change a password at sign-in. A client
          // cannot — resets are admin-only — so the badge would promise a step
          // that never comes.
          (u.must_change_password && u.role !== 'client')
            ? '<span class="role-badge state-pending">Password reset</span>' : '',
          // Only meaningful where MFA is actually required of the role.
          (u.role === 'client' || u.role === 'superadmin')
            ? (u.totp_enabled
                ? '<span class="role-badge state-ok">MFA</span>'
                : '<span class="role-badge state-pending">MFA pending</span>')
            : '',
        ].filter(Boolean).join(' ') || '<span class="admin-muted">—</span>';

        // Suspending, reactivating and resetting MFA are all self-lockout
        // risks, so the server refuses them on your own account and the UI
        // does not offer them.
        const lifecycleBtns = isSelf ? '' : `
            <button class="btn btn-secondary btn-sm" data-action="toggle-active"
              data-id="${u.id}" data-username="${escapeHtml(u.username)}"
              data-active="${suspended ? '0' : '1'}"
              title="${suspended ? 'Restore access for this account' : 'Block sign-in without deleting the account'}">
              ${suspended ? 'Reactivate' : 'Suspend'}
            </button>
            ${isSso ? '' : `<button class="btn btn-secondary btn-sm" data-action="reset-mfa"
              data-id="${u.id}" data-username="${escapeHtml(u.username)}"
              ${u.totp_enabled ? '' : 'disabled title="No authenticator is enrolled"'}>
              Reset MFA
            </button>`}`;

        return `<tr${suspended ? ' class="admin-row-suspended"' : ''}>
          <td>${escapeHtml(u.username)}${isSelf ? ' <span class="admin-self-label">(you)</span>' : ''}</td>
          <td>${roleTag}${ssoTag}</td>
          ${tenantCell}
          <td>${stateTags}</td>
          <td>${formatDate(u.created_at)}</td>
          <td>${formatDate(u.last_login)}</td>
          <td class="admin-actions">
            <button class="btn btn-secondary btn-sm" data-action="edit-user"
              data-id="${u.id}" data-username="${escapeHtml(u.username)}" data-role="${u.role}"
              data-auth-type="${u.auth_type || 'local'}"
              data-tenant-ids="${escapeHtml(JSON.stringify(u.tenantIds || []))}"
              data-page-access="${escapeHtml(JSON.stringify(u.pageAccess || {}))}"
              ${isSelf ? 'disabled title="Cannot change your own role"' : ''}>
              Edit
            </button>
            ${lifecycleBtns}
            ${delBtn}
          </td>
        </tr>`;
      }).join('');
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="7" class="admin-table-empty">Error: ${escapeHtml(err.message)}</td></tr>`;
    }
  }

  // ── Per-page access editor ────────────────────────────────────────────────
  // One row per page, each a 4-way select. "Inherit" (the empty value) means
  // no override row — the user simply gets whatever their role grants. Only
  // pages the acting admin can write are offered, matching the server-side
  // rule that you cannot grant access you do not hold yourself.

  function assignablePages() {
    return (window.pageCatalog || []).filter(p => window.canWrite(p.key));
  }

  function renderPageAccessEditor(containerId, current) {
    const container = document.getElementById(containerId);
    if (!container) return;

    const overrides = current || {};
    container.innerHTML = assignablePages().map(p => {
      const val = overrides[p.key] || '';
      const opt = (v, label) =>
        `<option value="${v}"${val === v ? ' selected' : ''}>${label}</option>`;
      return `<label class="page-access-row">
        <span class="page-access-label">${escapeHtml(p.label)}</span>
        <select class="page-access-select" data-page-key="${p.key}">
          ${opt('',      'Inherit from role')}
          ${opt('none',  'No access')}
          ${opt('read',  'View only')}
          ${opt('write', 'View & edit')}
        </select>
      </label>`;
    }).join('');
  }

  /** Collect the editor's selections into the { pageKey: level } request body. */
  function collectPageAccess(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return {};
    const out = {};
    container.querySelectorAll('.page-access-select').forEach(sel => {
      out[sel.dataset.pageKey] = sel.value; // '' means "clear the override"
    });
    return out;
  }

  // ── Add user form ─────────────────────────────────────────────────────────

  async function handleAddUser(e) {
    e.preventDefault();
    showAdminError('');
    showAdminSuccess('');

    const username = document.getElementById('newUsername').value.trim();
    const password = document.getElementById('newPassword').value;
    const role     = document.getElementById('newRole').value;
    const body     = { username, password, role, pageAccess: collectPageAccess('newUserPageAccess') };

    if (isSuperAdmin()) {
      const multiSel = document.getElementById('newUserTenants');
      if (role !== 'superadmin') {
        const selected = multiSel
          ? Array.from(multiSel.selectedOptions).map(o => parseInt(o.value, 10))
          : [];
        if (selected.length === 0) {
          showAdminError('Please select at least one tenant for this user.');
          btn.disabled = false;
          return;
        }
        body.tenantIds = selected;
      }
    }

    const btn = document.getElementById('addUserBtn');
    btn.disabled = true;

    try {
      const res  = await fetch(apiUrl('users'), {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json();

      if (!res.ok) {
        showAdminError(data.error || 'Failed to create user.');
      } else {
        document.getElementById('addUserForm').reset();
        renderPageAccessEditor('newUserPageAccess', {});
        showAdminSuccess(`User "${data.username}" created successfully.`);
        await renderUsers();
      }
    } catch (err) {
      showAdminError('Network error: ' + err.message);
    } finally {
      btn.disabled = false;
    }
  }

  // ── Edit user modal ───────────────────────────────────────────────────────

  function openEditModal(userId, username, currentRole, currentTenantIds, authType, currentPageAccess) {
    const modal = document.getElementById('editUserModal');
    if (!modal) return;

    document.getElementById('editUserId').value          = userId;
    document.getElementById('editUserTitle').textContent = `Edit: ${username}`;
    document.getElementById('editUserPassword').value    = '';
    document.getElementById('editUserError').hidden      = true;

    // Hide password field for SSO users
    const pwdGroup = document.getElementById('editUserPassword') &&
                     document.getElementById('editUserPassword').closest('.form-group');
    if (pwdGroup) pwdGroup.hidden = (authType === 'saml');

    const roleSelect  = document.getElementById('editUserRole');
    const allowedRoles = (window.roleCatalog || [])
      .filter(r => isSuperAdmin() || r.value !== 'superadmin');
    roleSelect.innerHTML = allowedRoles
      .map(r => `<option value="${r.value}"${currentRole === r.value ? ' selected' : ''}>${escapeHtml(r.label)}</option>`)
      .join('');

    renderPageAccessEditor('editUserPageAccess', currentPageAccess);

    // Tenant assignment (superadmin only)
    const tenantsRow = document.getElementById('editUserTenantsRow');
    const multiSel   = document.getElementById('editUserTenants');
    if (tenantsRow && multiSel) {
      if (isSuperAdmin()) {
        populateTenantMultiSelect(multiSel, currentTenantIds || []);
        tenantsRow.hidden = false;
      } else {
        tenantsRow.hidden = true;
      }
    }

    modal.hidden = false;
    document.body.classList.add('modal-open');
  }

  function closeEditModal() {
    const modal = document.getElementById('editUserModal');
    if (modal) modal.hidden = true;
    document.body.classList.remove('modal-open');
  }

  async function handleSaveEdit() {
    const userId = parseInt(document.getElementById('editUserId').value, 10);
    const role   = document.getElementById('editUserRole').value;
    const pass   = document.getElementById('editUserPassword').value;

    const errEl  = document.getElementById('editUserError');
    errEl.hidden = true;

    const body = { role, pageAccess: collectPageAccess('editUserPageAccess') };
    if (pass) body.password = pass;

    // Include tenant assignments if superadmin
    if (isSuperAdmin()) {
      const multiSel = document.getElementById('editUserTenants');
      if (multiSel) {
        body.tenantIds = Array.from(multiSel.selectedOptions).map(o => parseInt(o.value, 10));
      }
    }

    const btn    = document.getElementById('editUserSaveBtn');
    btn.disabled = true;

    try {
      const res  = await fetch(apiUrl(`users/${userId}`), {
        method: 'PUT', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json();

      if (!res.ok) {
        errEl.textContent = data.error || 'Update failed.';
        errEl.hidden = false;
      } else {
        closeEditModal();
        showAdminSuccess(`User "${data.username}" updated.`);
        await renderUsers();
      }
    } catch (err) {
      errEl.textContent = 'Network error: ' + err.message;
      errEl.hidden = false;
    } finally {
      btn.disabled = false;
    }
  }

  // ── Delete user ───────────────────────────────────────────────────────────

  /** PUT a partial user update and re-render. Shared by the lifecycle actions. */
  async function patchUser(userId, body, successMsg) {
    showAdminError('');
    try {
      const res  = await fetch(apiUrl(`users/${userId}`), {
        method: 'PUT', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) { showAdminError(data.error || 'Update failed.'); return false; }
      showAdminSuccess(successMsg);
      await renderUsers();
      return true;
    } catch (err) {
      showAdminError('Network error: ' + err.message);
      return false;
    }
  }

  /**
   * Suspend or reactivate.
   *
   * Suspension is the answer to "this person has left" that DELETE is not:
   * the account stops working on its next request — is_active is checked per
   * request, not cached on the session — while the record of who had access
   * survives. Deleting destroys that record.
   */
  async function handleToggleActive(userId, username, isCurrentlyActive) {
    const msg = isCurrentlyActive
      ? `Suspend "${username}"?\n\nThey will be signed out on their next request and cannot sign in again until reactivated. Nothing is deleted.`
      : `Reactivate "${username}"?\n\nThey will be able to sign in again immediately.`;
    if (!confirm(msg)) return;

    await patchUser(userId, { isActive: !isCurrentlyActive },
      isCurrentlyActive ? `"${username}" suspended.` : `"${username}" reactivated.`);
  }

  /**
   * Clear the enrolled authenticator.
   *
   * The "they lost their phone" path. It does not disable MFA — for a portal
   * client MFA is required by their role, so the next sign-in walks them
   * through enrolment again with a fresh secret.
   */
  async function handleResetMfa(userId, username) {
    if (!confirm(
      `Reset multi-factor authentication for "${username}"?\n\n` +
      `Their current authenticator will stop working and they will be asked to ` +
      `enrol a new one at their next sign-in.\n\n` +
      `Only do this once you are satisfied you are talking to the right person.`
    )) return;

    await patchUser(userId, { resetMfa: true },
      `MFA reset for "${username}". They will re-enrol at next sign-in.`);
  }

  async function handleDeleteUser(userId, username) {
    if (!confirm(`Delete user "${username}"? This cannot be undone.\n\nTo revoke access without losing the record of who had it, use Suspend instead.`)) return;
    showAdminError('');
    try {
      const res  = await fetch(apiUrl(`users/${userId}`), {
        method: 'DELETE', credentials: 'same-origin',
      });
      const data = await res.json();
      if (!res.ok) {
        showAdminError(data.error || 'Delete failed.');
      } else {
        showAdminSuccess(`User "${username}" deleted.`);
        await renderUsers();
      }
    } catch (err) {
      showAdminError('Network error: ' + err.message);
    }
  }

  // ── Configure DOM for role ────────────────────────────────────────────────

  function configureTableForRole() {
    const tenantTh      = document.getElementById('userTableTenantTh');
    if (tenantTh)      tenantTh.hidden = !isSuperAdmin();

    const tenantSection = document.getElementById('tenantManagementSection');
    if (tenantSection) tenantSection.hidden = !isSuperAdmin();

    const tenantRow     = document.getElementById('newUserTenantRow');
    if (tenantRow)     tenantRow.hidden = !isSuperAdmin();

    // Build the Add User role list from the server's catalog; only a
    // superadmin may create another superadmin.
    const newRoleSelect = document.getElementById('newRole');
    if (newRoleSelect && (window.roleCatalog || []).length) {
      newRoleSelect.innerHTML = window.roleCatalog
        .filter(r => isSuperAdmin() || r.value !== 'superadmin')
        .map(r => `<option value="${r.value}"${r.value === 'readonly' ? ' selected' : ''}>${escapeHtml(r.label)}</option>`)
        .join('');
    }

    renderPageAccessEditor('newUserPageAccess', {});
  }

  function bindNewUserRoleChange() {
    const roleSelect = document.getElementById('newRole');
    const tenantRow  = document.getElementById('newUserTenantRow');
    if (!roleSelect || !tenantRow) return;
    roleSelect.addEventListener('change', () => {
      if (isSuperAdmin()) {
        tenantRow.hidden = roleSelect.value === 'superadmin';
      }
    });
  }

  // ── Event wiring ──────────────────────────────────────────────────────────

  /*
   * The client estate and the service checkboxes USED TO LIVE HERE.
   *
   * They moved to public/js/tab-client-profile.js, behind the client-profile
   * page gate. They were two cards with two save buttons on two different
   * gates answering one question — who is this client — and neither recorded
   * what a change did to the Secure Score it drove.
   */

  async function initAdmin() {
    configureTableForRole();

    if (isSuperAdmin()) {
      await Promise.all([renderTenants(), populateTenantDropdowns()]);
      bindSlugAutoFill();

      const addTenantForm = document.getElementById('addTenantForm');
      if (addTenantForm) addTenantForm.addEventListener('submit', handleAddTenant);

      const tenantTbody = document.getElementById('tenantTableBody');
      if (tenantTbody) {
        tenantTbody.addEventListener('click', function (e) {
          const btn = e.target.closest('[data-action]');
          if (!btn || btn.dataset.action !== 'delete-tenant') return;
          handleDeleteTenant(parseInt(btn.dataset.id, 10), btn.dataset.name || '');
        });
      }
    }

    bindNewUserRoleChange();

    const addForm = document.getElementById('addUserForm');
    if (addForm) addForm.addEventListener('submit', handleAddUser);

    const closeBtn = document.getElementById('editUserCancelBtn');
    if (closeBtn) closeBtn.addEventListener('click', closeEditModal);

    const cancelBtn2 = document.getElementById('editUserCancelBtn2');
    if (cancelBtn2) cancelBtn2.addEventListener('click', closeEditModal);

    const saveBtn = document.getElementById('editUserSaveBtn');
    if (saveBtn) saveBtn.addEventListener('click', handleSaveEdit);

    const modal = document.getElementById('editUserModal');
    if (modal) {
      modal.addEventListener('click', function (e) { if (e.target === modal) closeEditModal(); });
    }
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && modal && !modal.hidden) closeEditModal();
    });

    const tbody = document.getElementById('userTableBody');
    if (tbody) {
      tbody.addEventListener('click', function (e) {
        const btn = e.target.closest('[data-action]');
        if (!btn) return;
        const action     = btn.dataset.action;
        const userId     = parseInt(btn.dataset.id, 10);
        const username   = btn.dataset.username || '';
        const tenantIds  = JSON.parse(btn.dataset.tenantIds || '[]');
        const pageAccess = JSON.parse(btn.dataset.pageAccess || '{}');
        const authType   = btn.dataset.authType || 'local';
        if (action === 'delete-user') handleDeleteUser(userId, username);
        else if (action === 'edit-user') openEditModal(userId, username, btn.dataset.role, tenantIds, authType, pageAccess);
        else if (action === 'toggle-active') handleToggleActive(userId, username, btn.dataset.active === '1');
        else if (action === 'reset-mfa') handleResetMfa(userId, username);
      });
    }

    const adminTabBtn = document.getElementById('tab-admin-btn');
    if (adminTabBtn) {
      adminTabBtn.addEventListener('click', async () => {
        await renderUsers();
        if (isSuperAdmin()) await renderTenants();
      });
    }

    await renderUsers();
    initMfa();
  }

  // ── MFA Management (superadmin only) ──────────────────────────────────────

  function initMfa() {
    if (!isSuperAdmin()) return;

    var section      = document.getElementById('mfaSection');
    var statusText   = document.getElementById('mfaStatusText');
    var enableBtn    = document.getElementById('mfaEnableBtn');
    var disableBtn   = document.getElementById('mfaDisableBtn');
    var actionBtns   = document.getElementById('mfaActionBtns');
    var setupPanel   = document.getElementById('mfaSetupPanel');
    var qrImg        = document.getElementById('mfaQrImg');
    var secretText   = document.getElementById('mfaSecretText');
    var confirmCode  = document.getElementById('mfaConfirmCode');
    var confirmBtn   = document.getElementById('mfaConfirmBtn');
    var setupCancel  = document.getElementById('mfaSetupCancelBtn');
    var setupErr     = document.getElementById('mfaSetupError');
    var disablePanel = document.getElementById('mfaDisablePanel');
    var disablePwd   = document.getElementById('mfaDisablePassword');
    var disableConfirm = document.getElementById('mfaDisableConfirmBtn');
    var disableCancel  = document.getElementById('mfaDisableCancelBtn');
    var disableErr     = document.getElementById('mfaDisableError');

    if (!section) return;
    section.hidden = false;

    var totpEnabled = window.currentUser && window.currentUser.totpEnabled;
    updateMfaUi(totpEnabled);

    function updateMfaUi(enabled) {
      if (statusText) {
        statusText.textContent = enabled
          ? '\u2705 MFA is enabled. Your account requires a one-time code at every login.'
          : '\u26A0\uFE0F MFA is not configured. Enable it to protect your superadmin account.';
      }
      if (enableBtn)  enableBtn.hidden  = enabled;
      if (disableBtn) disableBtn.hidden = !enabled;
      if (setupPanel)   setupPanel.hidden   = true;
      if (disablePanel) disablePanel.hidden = true;
      if (actionBtns)   actionBtns.hidden   = false;
    }

    // \u2500\u2500 Enable flow \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    if (enableBtn) {
      enableBtn.addEventListener('click', async function () {
        if (actionBtns)   actionBtns.hidden   = true;
        if (setupPanel)   setupPanel.hidden   = false;
        if (confirmCode)  confirmCode.value   = '';
        if (setupErr)     setupErr.hidden     = true;
        if (qrImg)        qrImg.src           = '';
        if (secretText)   secretText.textContent = 'Loading\u2026';

        try {
          var r = await fetch(apiUrl('auth/totp-setup'), { credentials: 'same-origin' });
          var d = await r.json();
          if (!r.ok) throw new Error(d.error || 'Failed to load setup.');
          if (qrImg)      qrImg.src              = d.qrCodeUrl;
          if (secretText) secretText.textContent = d.secret;
          if (confirmCode) setTimeout(function () { confirmCode.focus(); }, 50);
        } catch (err) {
          if (setupErr) { setupErr.textContent = err.message; setupErr.hidden = false; }
          if (actionBtns) actionBtns.hidden = false;
          if (setupPanel) setupPanel.hidden = true;
        }
      });
    }

    if (setupCancel) {
      setupCancel.addEventListener('click', function () {
        if (setupPanel)   setupPanel.hidden   = true;
        if (actionBtns)   actionBtns.hidden   = false;
      });
    }

    if (confirmBtn) {
      confirmBtn.addEventListener('click', async function () {
        if (setupErr) setupErr.hidden = true;
        confirmBtn.disabled = true;
        confirmBtn.textContent = 'Confirming\u2026';

        try {
          var r = await fetch(apiUrl('auth/totp-confirm'), {
            method: 'POST', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: confirmCode ? confirmCode.value.trim() : '' }),
          });
          var d = await r.json();
          if (!r.ok) throw new Error(d.error || 'Confirmation failed.');

          // Success: update UI and currentUser state
          if (window.currentUser) window.currentUser.totpEnabled = true;
          var banner = document.getElementById('mfaBanner');
          if (banner) banner.hidden = true;
          showAdminSuccess('MFA enabled successfully. Your account is now protected.');
          updateMfaUi(true);
        } catch (err) {
          if (setupErr) { setupErr.textContent = err.message; setupErr.hidden = false; }
        } finally {
          confirmBtn.disabled = false;
          confirmBtn.textContent = 'Confirm & Enable';
        }
      });
    }

    if (confirmCode) {
      confirmCode.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' && confirmBtn) confirmBtn.click();
      });
    }

    // \u2500\u2500 Disable flow \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    if (disableBtn) {
      disableBtn.addEventListener('click', function () {
        if (actionBtns)   actionBtns.hidden   = true;
        if (disablePanel) disablePanel.hidden = false;
        if (disablePwd)   disablePwd.value    = '';
        if (disableErr)   disableErr.hidden   = true;
        if (disablePwd)   setTimeout(function () { disablePwd.focus(); }, 50);
      });
    }

    if (disableCancel) {
      disableCancel.addEventListener('click', function () {
        if (disablePanel) disablePanel.hidden = true;
        if (actionBtns)   actionBtns.hidden   = false;
      });
    }

    if (disableConfirm) {
      disableConfirm.addEventListener('click', async function () {
        if (disableErr) disableErr.hidden = true;
        disableConfirm.disabled = true;
        disableConfirm.textContent = 'Disabling\u2026';

        try {
          var r = await fetch(apiUrl('auth/totp-disable'), {
            method: 'POST', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: disablePwd ? disablePwd.value : '' }),
          });
          var d = await r.json();
          if (!r.ok) throw new Error(d.error || 'Failed to disable MFA.');

          if (window.currentUser) window.currentUser.totpEnabled = false;
          var banner = document.getElementById('mfaBanner');
          if (banner) banner.hidden = false;
          showAdminSuccess('MFA disabled. You will be required to enrol again on next login.');
          updateMfaUi(false);
        } catch (err) {
          if (disableErr) { disableErr.textContent = err.message; disableErr.hidden = false; }
        } finally {
          disableConfirm.disabled = false;
          disableConfirm.textContent = 'Confirm Disable';
        }
      });
    }

    if (disablePwd) {
      disablePwd.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' && disableConfirm) disableConfirm.click();
      });
    }
  }

  // ── Sub-tabs ──────────────────────────────────────────────────────────────

  /*
   * The Admin tab is three sections behind one nav entry: Integrations, User
   * Management and Client Profile.
   *
   * ══ EACH ONE IS GATED ON ITS OWN PAGE KEY ══
   *
   * Client Profile is NOT part of the admin page. It is a separate page key
   * with its own access level, and it stays that way — `client-profile` still
   * appears in lib/pages.js, still owns the /api/client-profile prefix, and is
   * still refused to sales, readonly and analysts by ROLE_DEFAULTS. Folding it
   * into the Admin tab is a change to where the link lives, not to who may use
   * it. Gating the sub-tab on `admin` would silently widen access to every
   * client's estate and service mix to anyone who could reach this tab.
   *
   * The reverse matters too: an admin with a client-profile override of `none`
   * must not see the sub-tab, even though they own the tab it sits in.
   */
  var SUBTABS = [
    { key: 'integrations',   label: 'Integrations',
      // Integrations are a write surface — there is nothing to read here that
      // is not a credential form, which is why this asks for write and the
      // others ask for view.
      allowed: function () { return window.canWrite('admin'); } },
    { key: 'users',          label: 'User Management',
      allowed: function () { return window.canView('admin'); } },
    { key: 'client-profile', label: 'Client Profile',
      allowed: function () { return window.canView('client-profile'); } },
  ];

  var activeSubtab = null;

  function availableSubtabs() {
    return SUBTABS.filter(function (t) { return t.allowed(); });
  }

  function buildSubtabs() {
    var bar = document.getElementById('adminSubtabs');
    if (!bar) return;

    var available = availableSubtabs();

    // One section and no choice to make is not a tab bar. Hiding it avoids a
    // lone tab that looks like the other two failed to load.
    bar.hidden = available.length < 2;

    bar.innerHTML = available.map(function (t) {
      return '<button type="button" class="admin-subtab" role="tab"' +
        ' id="adminSubtab-' + t.key + '" data-subtab="' + t.key + '"' +
        ' aria-controls="adminPane-' + t.key + '"' +
        ' aria-selected="' + (t.key === activeSubtab) + '">' +
        escapeHtml(t.label) + '</button>';
    }).join('');

    bar.querySelectorAll('.admin-subtab').forEach(function (b) {
      b.addEventListener('click', function () { showSubtab(b.dataset.subtab); });
    });
  }

  /**
   * Show one sub-tab.
   *
   * Re-checks `allowed()` rather than trusting the caller: the key can arrive
   * from a remembered value or a stale button, and a pane is only as closed as
   * the last thing that opened it. The server gates the DATA regardless — this
   * keeps the screen honest, it is not the access control.
   */
  function showSubtab(key) {
    var available = availableSubtabs();
    if (!available.length) return;

    var chosen = available.filter(function (t) { return t.key === key; })[0]
              || available[0];
    activeSubtab = chosen.key;

    SUBTABS.forEach(function (t) {
      var pane = document.getElementById('adminPane-' + t.key);
      if (pane) pane.hidden = t.key !== activeSubtab;
    });

    var bar = document.getElementById('adminSubtabs');
    if (bar) {
      bar.querySelectorAll('.admin-subtab').forEach(function (b) {
        var on = b.dataset.subtab === activeSubtab;
        b.classList.toggle('is-on', on);
        b.setAttribute('aria-selected', String(on));
      });
    }

    renderSubtab(activeSubtab);
  }

  /*
   * Render on open, not on tab entry.
   *
   * Every one of these is tenant-scoped, and rendering all three whenever the
   * Admin tab opens costs three round trips to show one. Re-rendering on each
   * open also means a superadmin who switches client never sees the previous
   * customer's estate sitting in a pane they had already visited.
   */
  function renderSubtab(key) {
    if (key === 'integrations') renderIntegrations();
    else if (key === 'users')   renderUsers();
    else if (key === 'client-profile' && window.ClientProfileTab) {
      window.ClientProfileTab.loadAndRender();
    }
  }

  // ── Init ──────────────────────────────────────────────────────────────────

  /*
   * Called by app.js when the Admin tab opens, and again when a superadmin
   * changes the selected organisation. Re-rendering only the visible pane is
   * what keeps that second case cheap and correct.
   */
  window.renderAdmin = function () {
    buildSubtabs();
    showSubtab(activeSubtab);
  };

  // Wait for auth.js to set window.currentUser before initialising
  if (window.currentUser) {
    initAdmin();
  } else {
    document.addEventListener('authReady', initAdmin, { once: true });
  }

  // ── Integrations ───────────────────────────────────────────────────────────

  const AW_REGIONS = [
    { value: 'https://ticket-api.managedgw.us001-prod.arcticwolf.net', label: 'US001 — United States' },
    { value: 'https://ticket-api.managedgw.us002-prod.arcticwolf.net', label: 'US002 — United States' },
    { value: 'https://ticket-api.managedgw.us003-prod.arcticwolf.net', label: 'US003 — United States' },
    { value: 'https://ticket-api.managedgw.eu001-prod.arcticwolf.net', label: 'EU001 — Europe' },
    { value: 'https://ticket-api.managedgw.au001-prod.arcticwolf.net', label: 'AU001 — Australia' },
    { value: 'https://ticket-api.managedgw.ca001-prod.arcticwolf.net', label: 'CA001 — Canada' },
  ];

  const AW_REPORTS_REGIONS = [
    { value: 'https://msp-reporting.managedgw.us001-prod.arcticwolf.net', label: 'US001 — United States' },
    { value: 'https://msp-reporting.managedgw.us002-prod.arcticwolf.net', label: 'US002 — United States' },
    { value: 'https://msp-reporting.managedgw.us003-prod.arcticwolf.net', label: 'US003 — United States' },
    { value: 'https://msp-reporting.managedgw.eu001-prod.arcticwolf.net', label: 'EU001 — Europe' },
    { value: 'https://msp-reporting.managedgw.au001-prod.arcticwolf.net', label: 'AU001 — Australia' },
    { value: 'https://msp-reporting.managedgw.ca001-prod.arcticwolf.net', label: 'CA001 — Canada' },
  ];

  const PROVIDERS = [
    {
      id:   'arctic_wolf',
      name: 'Arctic Wolf',
      icon: '🐺',
      desc: 'MDR ticketing — automatically syncs incidents and alert tickets.',
      awRegions: true, // renders region dropdown + org UUID instead of a free URL field
    },
    {
      id:       'fortianalyzer',
      name:     'FortiAnalyzer',
      icon:     '🧱',
      desc:     'Managed NDR telemetry read directly from FortiAnalyzer — traffic, IPS threats, source countries, VPN failures and firewall admin activity, collected hourly into daily rollups.',
      urlLabel: 'FortiAnalyzer URL',
      urlHint:  'e.g. https://faz.yourdomain.com',
      fazFields: true,
      // A token, not a password: a REST API admin restricted to this client's
      // ADOM. Labelled so it is not mistaken for a GUI login.
      keyLabel: 'REST API Token',
      keyHint:  'Token of a read-only REST API admin restricted to this client\'s ADOM…',
    },
    {
      id:   'arctic_wolf_reports',
      name: 'Arctic Wolf Reports',
      icon: '📊',
      desc: 'Security-awareness session history — automatically syncs training/phishing session data.',
      awRegions: true,
    },
    {
      id:       'sentinelone',
      name:     'SentinelOne',
      icon:     '🛡️',
      desc:     'Managed EDR — syncs threats, console activity and endpoint fleet health every 6 hours.',
      urlLabel: 'Management Console URL',
      urlHint:  'e.g. https://euce1-101.sentinelone.net',
      scopeFields: true, // optional site / account scoping
    },
    {
      id:       'acronis',
      name:     'Acronis',
      icon:     '✉️',
      desc:     'Managed Email Security — syncs email threat alerts every 6 hours.',
      urlLabel: 'Data Centre URL',
      urlHint:  'e.g. https://eu2-cloud.acronis.com',
      acronisFields: true,
      /*
       * Acronis authenticates with OAuth client credentials, not an API key.
       * The generic field is relabelled rather than reused as-is: a box marked
       * "API Key / Token" is one somebody pastes the client ID into, and the
       * resulting 401 gives no clue which of the two halves is wrong.
       */
      keyLabel: 'Client Secret',
      keyHint:  'Paste the client secret shown once when the API client was created…',
    },
    {
      id:       'ms_graph',
      name:     'Microsoft Graph',
      icon:     '📈',
      desc:     'Microsoft Secure Score — syncs the daily posture snapshot and the per-control remediation backlog every 24 hours.',
      urlLabel: 'Graph Endpoint',
      urlHint:  'https://graph.microsoft.com/v1.0',
      // Prefilled rather than left to a placeholder: this value is the same for
      // every commercial tenant, and a required field nobody can guess is a
      // field everybody gets wrong once.
      urlDefault: 'https://graph.microsoft.com/v1.0',
      msGraphFields: true,
      /*
       * Client credentials again, so the generic key box is relabelled for the
       * same reason it is for Acronis: a field marked "API Key / Token" is one
       * somebody pastes the application ID into, and the resulting 401 names
       * the client rather than the field, which sends people to the wrong half.
       */
      keyLabel: 'Client Secret',
      keyHint:  'Paste the client secret VALUE (not the Secret ID) from the app registration…',
    },
    {
      id:   'dnsfilter',
      name: 'DNSFilter',
      icon: '🧭',
      desc: 'AI Visibility — generative AI lookups, tools, users and policy for this client, collected hourly using the DNSFilter MSP key.',
      // No URL and no key on this card: the MSP key is set once on the
      // DNSFilter (MSP) card. This client's row is its organisation id only.
      dnsFields: true,
    },
  ];

  // The superadmin-only MSP DNSFilter record (no key), for the organisation picker.
  let mspDnsCache = null;

  /** What the last per-client DNSFilter Test verified. */
  function renderDnsFilterVerified(c) {
    const note = html => `<p class="int-optional" style="margin:-.25rem 0 .75rem">${html}</p>`;
    if (!c.verified_at) {
      return note('Not verified yet — Save, then Test Connection. Sync is refused until the organisation has been checked.');
    }
    if (c.organization_id && c.verified_org_id && String(c.organization_id) !== String(c.verified_org_id)) {
      return note('<strong>⚠ The organisation has changed since it was verified.</strong> Test Connection again — sync is refused until then.');
    }
    const when = new Date(c.verified_at).toLocaleString('en-ZA', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
    const reports = c.detected && c.detected.reports
      ? Object.keys(c.detected.reports).map(k => `${k} ${c.detected.reports[k].ok ? '✓' : '✗'}`).join(' · ')
      : '';
    /*
     * What DNSFilter actually returned. When a panel comes back empty, these
     * field names are the difference between guessing and knowing — and the
     * pilot's empty users table was exactly that case.
     */
    const rep = (c.detected && c.detected.reports) || {};
    const proved = c.verified_category_filters || {};
    const filterText = (k) => {
      if (!Object.prototype.hasOwnProperty.call(proved, k)) return 'not proved yet (no AI traffic that day)';
      return proved[k] === null ? 'applied here — DNSFilter ignored every filter form' : `applied by DNSFilter as "${proved[k]}"`;
    };
    const detail = Object.keys(rep).length
      ? '<details class="int-optional" style="margin:.25rem 0 .75rem"><summary>What DNSFilter returned</summary>' +
        Object.keys(rep).map((k) => {
          const r = rep[k] || {};
          const body = r.ok
            ? `fields: ${escHtmlInt((r.fields || []).join(', ') || 'none')}` +
              (/domains/.test(k) ? ` · AI filter ${escHtmlInt(filterText(k))}` : '')
            : `${escHtmlInt(r.reason || 'failed')}${r.detail ? ': ' + escHtmlInt(r.detail) : ''}`;
          return `<div><code>${escHtmlInt(k)}</code> — ${body}</div>`;
        }).join('') +
        '</details>'
      : '';
    return note(`Verified ${escHtmlInt(when)}: <strong>${escHtmlInt(c.verified_org_name || '')}</strong> ` +
        `(<code>${escHtmlInt(c.verified_org_id)}</code>).` +
        (c.verified_ai_category_id ? '' : ' <strong>No Generative AI category found.</strong>')) +
      (reports ? `<div class="integration-sync-meta"><span class="int-sync-status">Reports: ${escHtmlInt(reports)}</span></div>` : '') +
      detail;
  }

  function renderDnsFilterCard(p, cfg) {
    const c = (cfg && cfg.config_json) || {};
    const enabled = cfg ? cfg.is_enabled : false;
    const orgs = (mspDnsCache && mspDnsCache.config_json && mspDnsCache.config_json.organisations) || [];
    const lastSync = cfg && cfg.last_synced_at
      ? new Date(cfg.last_synced_at).toLocaleString('en-ZA', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })
      : null;
    return `
      <div class="integration-card" id="int-card-${p.id}">
        <div class="integration-card-header">
          <span class="integration-icon">${p.icon}</span>
          <div class="integration-info">
            <strong>${escHtmlInt(p.name)}</strong>
            <span class="integration-desc">${escHtmlInt(p.desc)}</span>
          </div>
          <label class="integration-toggle" title="${enabled ? 'Disable' : 'Enable'}">
            <input type="checkbox" class="int-enabled-cb" data-provider="${p.id}" ${enabled ? 'checked' : ''} ${!cfg ? 'disabled' : ''}>
            <span class="int-toggle-slider"></span>
          </label>
        </div>
        <div class="integration-form">
          <div class="form-group">
            <label class="modal-label">DNSFilter Organisation ID</label>
            <input type="text" inputmode="numeric" class="int-dns-org form-input" data-provider="${p.id}"
                   list="int-dns-orgs" placeholder="This client's organisation id in DNSFilter"
                   value="${escHtmlInt(c.organization_id || '')}">
            ${orgs.length ? `<datalist id="int-dns-orgs">${orgs.map(o =>
              `<option value="${escHtmlInt(o.id)}">${escHtmlInt(o.name)}</option>`).join('')}</datalist>` : ''}
          </div>
          <div class="form-group">
            <label class="modal-label">Time Zone</label>
            <input type="text" class="int-timezone form-input" data-provider="${p.id}"
                   placeholder="Africa/Johannesburg" value="${escHtmlInt(c.timeZone || 'Africa/Johannesburg')}">
          </div>
          ${renderDnsFilterVerified(c)}
          ${lastSync ? `
          <div class="integration-sync-meta">
            <span class="int-sync-status int-sync-${cfg.last_sync_status || 'ok'}">
              ${cfg.last_sync_status === 'ok' ? '✓' : '✗'} ${escHtmlInt(cfg.last_sync_message || '')}
            </span>
            <span class="int-sync-date">Last synced: ${lastSync}</span>
          </div>` : ''}
          <div class="integration-actions">
            <button class="btn btn-sm int-test-btn" data-provider="${p.id}" ${!cfg ? 'disabled' : ''}>Test Connection</button>
            <button class="btn btn-sm int-sync-btn" data-provider="${p.id}" ${!cfg ? 'disabled' : ''}>Sync Now</button>
            <button class="btn btn-sm btn-primary int-save-btn" data-provider="${p.id}">Save</button>
            ${cfg ? `<button class="btn btn-sm btn-danger int-remove-btn" data-provider="${p.id}">Remove</button>` : ''}
          </div>
          <p class="int-feedback" id="int-feedback-${p.id}"></p>
        </div>
      </div>`;
  }

  /** The MSP key card. Rendered for superadmins only; the server enforces it too. */
  function renderMspDnsCard(m) {
    const c = m.config_json || {};
    const when = c.verified_at
      ? new Date(c.verified_at).toLocaleString('en-ZA', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })
      : null;
    const status = m.migrationNeeded
      ? 'Run <code>db/migrate-ai-visibility.sql</code> before saving a key.'
      : !m.configured ? 'No key saved yet.'
      : !when ? 'Key saved — Test Connection to verify it.'
      : `Verified ${escHtmlInt(when)}: ${escHtmlInt((c.organisations || []).length)} organisations visible; ` +
        (c.ai_category_id ? `AI category "${escHtmlInt(c.ai_category_name)}".` : '<strong>no Generative AI category found.</strong>');
    return `
      <div class="integration-card" id="int-card-dnsfilter-msp">
        <div class="integration-card-header">
          <span class="integration-icon">🔑</span>
          <div class="integration-info">
            <strong>DNSFilter (MSP)</strong>
            <span class="integration-desc">One MSP API key for every client's AI Visibility. Superadmin only — the key is never shown again after saving.</span>
          </div>
        </div>
        <div class="integration-form">
          <div class="form-group">
            <label class="modal-label">API URL</label>
            <input type="url" class="int-msp-dns-url form-input" value="${escHtmlInt(m.base_url || 'https://api.dnsfilter.com')}">
          </div>
          <div class="form-group">
            <label class="modal-label">MSP API Key</label>
            <input type="password" class="int-msp-dns-key form-input"
                   placeholder="${m.configured ? '••••••••  (saved — enter a new key to replace it)' : 'Paste the DNSFilter MSP API key…'}">
          </div>
          <p class="int-optional" style="margin:-.25rem 0 .75rem">
            Use a key created at the <strong>MSP</strong> level so it can see every client organisation. It is only
            ever used to <strong>read</strong> reports and policies. ${status}
          </p>
          <div class="integration-actions">
            <button class="btn btn-sm" id="int-msp-dns-test" ${!m.configured ? 'disabled' : ''}>Test Connection</button>
            <button class="btn btn-sm btn-primary" id="int-msp-dns-save" ${m.migrationNeeded ? 'disabled' : ''}>Save</button>
            ${m.configured ? '<button class="btn btn-sm btn-danger" id="int-msp-dns-remove">Remove</button>' : ''}
          </div>
          <p class="int-feedback" id="int-feedback-dnsfilter-msp"></p>
        </div>
      </div>`;
  }

  function wireMspDnsCard(container) {
    const save = container.querySelector('#int-msp-dns-save');
    const test = container.querySelector('#int-msp-dns-test');
    const remove = container.querySelector('#int-msp-dns-remove');
    const fb = (msg, err) => setIntFeedback('dnsfilter-msp', msg, err);
    const call = async (method, path, body) => {
      const res = await fetch('api/msp-integrations/dnsfilter' + path, {
        method, credentials: 'same-origin',
        headers: body ? { 'Content-Type': 'application/json' } : undefined,
        body: body ? JSON.stringify(body) : undefined,
      });
      const r = await readIntJson(res);
      const data = r.data || {};
      return { ok: r.ok && data.ok !== false, data: r.error ? Object.assign({ error: r.error }, data) : data };
    };
    if (save) save.addEventListener('click', async () => {
      const url = (container.querySelector('.int-msp-dns-url') || {}).value || '';
      const key = ((container.querySelector('.int-msp-dns-key') || {}).value || '').trim();
      try {
        const r = await call('POST', '', Object.assign({ base_url: url.trim() }, key ? { api_key: key } : {}));
        if (!r.ok) return fb(r.data.error || 'Save failed.', true);
        fb('Saved. Test Connection to verify the key.', false);
        setTimeout(() => renderIntegrations(), 800);
      } catch (err) { fb('Network error: ' + err.message, true); }
    });
    if (test) test.addEventListener('click', async () => {
      fb('Testing connection…', false);
      try {
        const r = await call('POST', '/test');
        if (!r.ok) return fb('✗ ' + (r.data.error || 'Connection failed.'), true);
        fb('✓ ' + r.data.message, false);
        setTimeout(() => renderIntegrations(), 1500);
      } catch (err) { fb('Network error: ' + err.message, true); }
    });
    if (remove) remove.addEventListener('click', async () => {
      if (!confirm('Remove the DNSFilter MSP key? AI Visibility stops collecting for every client.')) return;
      try { await call('DELETE', ''); renderIntegrations(); } catch (_) {}
    });
  }

  // Last-rendered integration rows, keyed by provider.
  let configMapCache = {};

  function tenantQS() {
    const isSA = window.currentUser && window.currentUser.role === 'superadmin';
    if (!isSA || !window.globalTenantId) return '';
    return '?tenantId=' + encodeURIComponent(window.globalTenantId);
  }

  function tenantBody() {
    const isSA = window.currentUser && window.currentUser.role === 'superadmin';
    if (!isSA || !window.globalTenantId) return {};
    return { tenantId: window.globalTenantId };
  }

  function escHtmlInt(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  /** A top-level config_json value, or '' when the integration isn't saved yet. */
  function cfgVal(cfg, key) {
    return (cfg && cfg.config_json && cfg.config_json[key]) || '';
  }

  /**
   * What the last FortiAnalyzer Test verified: the ADOM, its FortiGates, and
   * which log types and FortiView views answered. The device names are the
   * operator's check that this is the right client's ADOM, so they are shown
   * rather than summarised as a count.
   */
  function renderFazVerified(cfg) {
    const c = (cfg && cfg.config_json) || {};
    const note = html => `<p class="int-optional" style="margin:-.25rem 0 .75rem">${html}</p>`;
    if (!c.verified_at) {
      return note('Not verified yet — Save, then Test Connection. Sync is refused until this ' +
        'ADOM and its FortiGates have been checked.');
    }
    const when = new Date(c.verified_at).toLocaleString('en-ZA',
      { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
    const devices = (c.verified_devices || []).map(d => d.name || d.sn).join(', ') || 'none';
    const changed = c.adom && c.verified_adom && c.adom !== c.verified_adom;
    const marks = obj => Object.keys(obj || {}).map(k => `${k} ${obj[k] && obj[k].ok ? '✓' : '✗'}`).join(' · ');
    const d = c.detected || {};
    return (changed ? note('<strong>⚠ The ADOM has changed since it was verified.</strong> ' +
        'Test Connection again — sync is refused until then.') : '') +
      note(`Verified ${escHtmlInt(when)} against ADOM <code>${escHtmlInt(c.verified_adom)}</code>` +
        `${c.faz_version ? ` (FortiAnalyzer ${escHtmlInt(c.faz_version)})` : ''}: ${escHtmlInt(devices)}.`) +
      (d.logtypes ? `<div class="integration-sync-meta"><span class="int-sync-status">Logs: ${escHtmlInt(marks(d.logtypes))}</span></div>` : '') +
      (d.views ? `<div class="integration-sync-meta"><span class="int-sync-status">FortiView: ${escHtmlInt(marks(d.views))}</span></div>` : '');
  }

  /**
   * What the last Test found for Managed Identity: each Graph resource, and the
   * Office 365 audit subscriptions. Shown per resource because a tenant commonly
   * has some (sign-ins on P1) and not others (risky users need P2).
   */
  function renderIdentityProbe(cfg) {
    const c = (cfg && cfg.config_json) || {};
    if (!c.identity_enabled) return '';
    const p = c.identity_probe;
    if (!p) {
      return '<p class="int-optional" style="margin:-.25rem 0 .75rem">Managed Identity not verified yet — ' +
        'Save, then Test Connection. Sync is refused until then.</p>';
    }
    const labels = { signins: 'Sign-ins', admin: 'Admin changes', alerts: 'Alerts',
      riskyUsers: 'Risky users', riskDetections: 'Risk detections' };
    const graph = Object.keys(labels).map((k) => {
      const g = (p.graph || {})[k] || {};
      if (g.ok) return `${labels[k]} ✓`;
      return `${labels[k]} ✗ ${g.reason === 'not_licensed' ? '(licence)' : g.permission ? `(${g.permission})` : ''}`;
    }).join(' · ');
    const a = p.audit || { enabled: [], failed: [] };
    const audit = `Audit: ${(a.enabled || []).join(', ') || 'none enabled'}` +
      ((a.failed || []).length ? ` · failed: ${(a.failed || []).map(f => f.contentType).join(', ')}` : '');
    const changed = c.identity_verified_tenant && c.azure_tenant_id &&
      String(c.identity_verified_tenant).toLowerCase() !== String(c.azure_tenant_id).toLowerCase();
    return (changed ? '<p class="int-optional" style="margin:-.25rem 0 .75rem"><strong>⚠ The directory has ' +
        'changed since Managed Identity was verified.</strong> Test Connection again — sync is refused until then.</p>' : '') +
      `<div class="integration-sync-meta"><span class="int-sync-status">${escHtmlInt(graph)}</span></div>` +
      `<div class="integration-sync-meta"><span class="int-sync-status">${escHtmlInt(audit)}</span></div>`;
  }

  async function renderIntegrations() {
    const container = document.getElementById('integrations-list');
    if (!container) return;

    // Integrations are an Admin-page write surface
    if (!window.canWrite('admin')) {
      document.getElementById('integrationsSection').hidden = true;
      return;
    }

    let configured = [];
    try {
      const res = await fetch('api/integrations' + tenantQS(), { credentials: 'same-origin' });
      if (res.ok) configured = await res.json();
    } catch (_) {}

    const configMap = {};
    configured.forEach(c => { configMap[c.provider] = c; });
    // Kept for saveIntegration, which must merge form fields over the config
    // the server owns (probe results like tsField / detected) rather than
    // clobbering it with a fresh object.
    configMapCache = configMap;

    let mspDns = null;
    if (window.currentUser && window.currentUser.role === 'superadmin') {
      try {
        const r = await fetch('api/msp-integrations/dnsfilter', { credentials: 'same-origin' });
        if (r.ok) mspDns = await r.json();
      } catch (_) {}
    }
    mspDnsCache = mspDns;

    container.innerHTML = (mspDns ? renderMspDnsCard(mspDns) : '') + PROVIDERS.map(p => {
      if (p.dnsFields) return renderDnsFilterCard(p, configMap[p.id]);
      const cfg        = configMap[p.id];
      const enabled    = cfg ? cfg.is_enabled : false;
      const lastSync   = cfg && cfg.last_synced_at
        ? new Date(cfg.last_synced_at).toLocaleString('en-ZA', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })
        : null;
      const syncStatus = cfg ? cfg.last_sync_status : null;
      const syncMsg    = cfg ? (cfg.last_sync_message || '') : '';

      return `
        <div class="integration-card" id="int-card-${p.id}">
          <div class="integration-card-header">
            <span class="integration-icon">${p.icon}</span>
            <div class="integration-info">
              <strong>${escHtmlInt(p.name)}</strong>
              <span class="integration-desc">${escHtmlInt(p.desc)}</span>
            </div>
            <label class="integration-toggle" title="${enabled ? 'Disable' : 'Enable'}">
              <input type="checkbox" class="int-enabled-cb" data-provider="${p.id}" ${enabled ? 'checked' : ''} ${!cfg ? 'disabled' : ''}>
              <span class="int-toggle-slider"></span>
            </label>
          </div>
          <div class="integration-form">
            ${p.awRegions ? `
            <div class="form-group">
              <label class="modal-label">Region</label>
              <select class="int-region-select form-input" data-provider="${p.id}">
                ${(p.id === 'arctic_wolf_reports' ? AW_REPORTS_REGIONS : AW_REGIONS).map(r => `<option value="${escHtmlInt(r.value)}" ${cfg && cfg.base_url === r.value ? 'selected' : ''}>${escHtmlInt(r.label)}</option>`).join('')}
              </select>
            </div>
            <div class="form-group">
              <label class="modal-label">Organization UUID</label>
              <input type="text" class="int-org-uuid form-input" data-provider="${p.id}"
                     placeholder="550e8400-e29b-41d4-a716-446655440000"
                     value="${escHtmlInt(cfg && cfg.config_json && cfg.config_json.organizationUuid ? cfg.config_json.organizationUuid : '')}">
            </div>` : `
            <div class="form-group">
              <label class="modal-label">${escHtmlInt(p.urlLabel || 'Base URL')}</label>
              <input type="url" class="int-url-input form-input" data-provider="${p.id}"
                     placeholder="${escHtmlInt(p.urlHint || '')}" value="${cfg ? escHtmlInt(cfg.base_url) : escHtmlInt(p.urlDefault || '')}">
            </div>
            ${p.fazFields ? `
            <div class="form-group">
              <label class="modal-label">ADOM</label>
              <input type="text" class="int-faz-adom form-input" data-provider="${p.id}"
                     placeholder="This client's ADOM, exactly as named in FortiAnalyzer"
                     value="${escHtmlInt(cfgVal(cfg, 'adom'))}">
            </div>
            <div class="form-group">
              <label class="modal-label">Time Zone</label>
              <input type="text" class="int-timezone form-input" data-provider="${p.id}"
                     placeholder="Africa/Johannesburg"
                     value="${escHtmlInt(cfgVal(cfg, 'timeZone') || 'Africa/Johannesburg')}">
            </div>
            <p class="int-optional" style="margin:-.25rem 0 .75rem">
              Use a <strong>read-only REST API admin restricted to this ADOM</strong>, with trusted
              hosts set to this dashboard's server. The time zone must match the FortiAnalyzer's.
            </p>
            ${renderFazVerified(cfg)}` : ''}
            ${p.scopeFields ? `
            <div class="form-group">
              <label class="modal-label">Site IDs <span class="int-optional">(optional)</span></label>
              <input type="text" class="int-site-ids form-input" data-provider="${p.id}"
                     placeholder="Comma-separated — leave blank for all sites"
                     value="${escHtmlInt(cfg && cfg.config_json && cfg.config_json.siteIds ? cfg.config_json.siteIds : '')}">
            </div>
            <div class="form-group">
              <label class="modal-label">Account IDs <span class="int-optional">(optional)</span></label>
              <input type="text" class="int-account-ids form-input" data-provider="${p.id}"
                     placeholder="Comma-separated — leave blank for all accounts"
                     value="${escHtmlInt(cfg && cfg.config_json && cfg.config_json.accountIds ? cfg.config_json.accountIds : '')}">
            </div>` : ''}
            ${p.acronisFields ? `
            <div class="form-group">
              <label class="modal-label">Client ID</label>
              <input type="text" class="int-client-id form-input" data-provider="${p.id}"
                     placeholder="API client ID from Settings → API clients"
                     value="${escHtmlInt(cfgVal(cfg, 'client_id'))}">
            </div>
            <div class="form-group">
              <label class="modal-label">Acronis Tenant UUID</label>
              <input type="text" class="int-tenant-uuid form-input" data-provider="${p.id}"
                     placeholder="The customer tenant this client's alerts belong to"
                     value="${escHtmlInt(cfgVal(cfg, 'tenant_uuid'))}">
            </div>` : ''}
            ${p.msGraphFields ? `
            <div class="form-group">
              <label class="modal-label">Directory (tenant) ID</label>
              <input type="text" class="int-azure-tenant form-input" data-provider="${p.id}"
                     placeholder="The client's Microsoft 365 directory GUID"
                     value="${escHtmlInt(cfgVal(cfg, 'azure_tenant_id'))}">
            </div>
            <div class="form-group">
              <label class="modal-label">Application (client) ID</label>
              <input type="text" class="int-app-id form-input" data-provider="${p.id}"
                     placeholder="App registration GUID"
                     value="${escHtmlInt(cfgVal(cfg, 'client_id'))}">
            </div>
            <div class="form-group">
              <label class="modal-label">Authority <span class="int-optional">(optional)</span></label>
              <input type="text" class="int-authority form-input" data-provider="${p.id}"
                     placeholder="https://login.microsoftonline.com — change only for US Gov / China clouds"
                     value="${escHtmlInt(cfgVal(cfg, 'authority_url'))}">
            </div>
            <p class="int-optional" style="margin:-.25rem 0 .75rem">
              Requires <strong>SecurityEvents.Read.All</strong> as an
              <strong>application</strong> permission with admin consent.
              A delegated grant authenticates and then fails on every read.
            </p>
            <div class="form-group">
              <label class="int-optional" style="display:flex;gap:.5rem;align-items:flex-start">
                <input type="checkbox" class="int-identity-enabled" data-provider="${p.id}"
                       ${cfg && cfg.config_json && cfg.config_json.identity_enabled ? 'checked' : ''}>
                <span><strong>Collect Managed Identity telemetry</strong> — sign-ins, admin changes,
                alerts, risky users, mailbox rules, external sharing and DLP, read directly from
                Microsoft.</span>
              </label>
            </div>
            <div class="form-group">
              <label class="modal-label">Identity Time Zone</label>
              <input type="text" class="int-identity-tz form-input" data-provider="${p.id}"
                     placeholder="Africa/Johannesburg"
                     value="${escHtmlInt(cfgVal(cfg, 'identity_time_zone') || 'Africa/Johannesburg')}">
            </div>
            <p class="int-optional" style="margin:-.25rem 0 .75rem">
              Managed Identity also needs these <strong>application</strong> permissions with admin consent —
              Microsoft Graph: <strong>AuditLog.Read.All</strong>, <strong>SecurityAlert.Read.All</strong>,
              <strong>IdentityRiskyUser.Read.All</strong>, <strong>IdentityRiskEvent.Read.All</strong>;
              Office 365 Management APIs: <strong>ActivityFeed.Read</strong> and <strong>ActivityFeed.ReadDlp</strong>.
              Sign-ins need Entra ID P1; risky users and risk detections need P2. Test Connection starts
              the Office 365 audit subscriptions and checks each permission.
            </p>
            ${renderIdentityProbe(cfg)}
            ${cfgVal(cfg, 'verified_azure_tenant_id') ? `
            <p class="int-optional" style="margin:-.25rem 0 .75rem">
              Last verified against directory
              <code>${escHtmlInt(cfgVal(cfg, 'verified_azure_tenant_id'))}</code>.
            </p>` : ''}` : ''}`}
            <div class="form-group">
              <label class="modal-label">${escHtmlInt(p.keyLabel || 'API Key / Token')}</label>
              <div class="int-key-row">
                <input type="password" class="int-key-input form-input" data-provider="${p.id}"
                       placeholder="${cfg ? '••••••••  (saved — enter new value to change)' : escHtmlInt(p.keyHint || 'Paste API key…')}">
                ${cfg ? `<button class="btn btn-sm int-clear-key" data-provider="${p.id}" title="Clear key to enter a new one">✕</button>` : ''}
              </div>
            </div>
            ${lastSync ? `
            <div class="integration-sync-meta">
              <span class="int-sync-status int-sync-${syncStatus || 'ok'}">
                ${syncStatus === 'ok' ? '✓' : '✗'} ${syncMsg}
              </span>
              <span class="int-sync-date">Last synced: ${lastSync}</span>
            </div>` : ''}
            <div class="integration-actions">
              <button class="btn btn-sm int-test-btn" data-provider="${p.id}" ${!cfg ? 'disabled' : ''}>Test Connection</button>
              <button class="btn btn-sm int-sync-btn" data-provider="${p.id}" ${!cfg ? 'disabled' : ''}>Sync Now</button>
              <button class="btn btn-sm btn-primary int-save-btn" data-provider="${p.id}">Save</button>
              ${cfg ? `<button class="btn btn-sm btn-danger int-remove-btn" data-provider="${p.id}">Remove</button>` : ''}
            </div>
            <p class="int-feedback" id="int-feedback-${p.id}"></p>
          </div>
        </div>`;
    }).join('');

    // ── Wire events ──
    container.querySelectorAll('.int-clear-key').forEach(btn => {
      btn.addEventListener('click', () => {
        const input = container.querySelector(`.int-key-input[data-provider="${btn.dataset.provider}"]`);
        if (input) { input.value = ''; input.placeholder = 'Paste API key…'; input.focus(); }
      });
    });

    container.querySelectorAll('.int-save-btn').forEach(btn => {
      btn.addEventListener('click', () => saveIntegration(btn.dataset.provider, container));
    });

    container.querySelectorAll('.int-test-btn').forEach(btn => {
      btn.addEventListener('click', () => testIntegration(btn.dataset.provider, container));
    });

    container.querySelectorAll('.int-sync-btn').forEach(btn => {
      btn.addEventListener('click', () => syncIntegration(btn.dataset.provider, container));
    });

    container.querySelectorAll('.int-remove-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        if (!confirm(`Remove ${btn.dataset.provider.replace('_', ' ')} integration?`)) return;
        removeIntegration(btn.dataset.provider);
      });
    });

    if (mspDns) wireMspDnsCard(container);
  }

  /*
   * Integration calls go through PanelUI.readJson: a 502 from a proxy, a
   * restarting server or an expired session answers with HTML, and reporting
   * that as "Unexpected token '<'" sends the operator hunting for the wrong
   * thing. The fallback keeps this working if panel-ui.js ever isn't loaded.
   */
  async function readIntJson(res) {
    if (window.PanelUI && window.PanelUI.readJson) return window.PanelUI.readJson(res);
    try { return { ok: res.ok, data: await res.json(), error: null }; }
    catch (_) { return { ok: false, data: null, error: `HTTP ${res.status} — the server did not return JSON.` }; }
  }

  function setIntFeedback(providerId, msg, isError) {
    const el = document.getElementById(`int-feedback-${providerId}`);
    if (!el) return;
    el.textContent = msg;
    el.style.color = isError ? 'var(--red)' : 'var(--green)';
  }

  async function saveIntegration(providerId, container) {
    /*
     * DNSFilter sends only the organisation id and time zone. The server builds
     * the stored config from exactly those two fields, so verification can
     * never be carried in from the browser.
     */
    if (providerId === 'dnsfilter') {
      const val = sel => ((container.querySelector(`${sel}[data-provider="dnsfilter"]`) || {}).value || '').trim();
      const orgId = val('.int-dns-org');
      if (!/^\d{1,12}$/.test(orgId)) {
        setIntFeedback(providerId, 'DNSFilter organisation id is required — digits only.', true);
        return;
      }
      const cb = container.querySelector('.int-enabled-cb[data-provider="dnsfilter"]');
      const body = Object.assign({}, tenantBody(), {
        base_url: 'https://api.dnsfilter.com',
        is_enabled: (cb && !cb.disabled) ? cb.checked : true,
        configJson: { organization_id: orgId, timeZone: val('.int-timezone') || 'Africa/Johannesburg' },
      });
      try {
        const res = await fetch('api/integrations/dnsfilter', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin', body: JSON.stringify(body),
        });
        const r = await readIntJson(res);
        if (!r.ok) { setIntFeedback(providerId, r.error || (r.data && r.data.error) || 'Save failed.', true); return; }
        setIntFeedback(providerId, 'Saved. Test Connection to verify the organisation.', false);
        setTimeout(() => renderIntegrations(), 800);
      } catch (err) { setIntFeedback(providerId, 'Network error: ' + err.message, true); }
      return;
    }

    const keyInput  = container.querySelector(`.int-key-input[data-provider="${providerId}"]`);
    const enabled   = container.querySelector(`.int-enabled-cb[data-provider="${providerId}"]`);

    // Arctic Wolf: derive base_url from region dropdown + collect org UUID
    const regionSel = container.querySelector(`.int-region-select[data-provider="${providerId}"]`);
    const urlInput  = container.querySelector(`.int-url-input[data-provider="${providerId}"]`);
    const base_url  = regionSel ? regionSel.value.trim() : (urlInput ? urlInput.value.trim() : '');

    const api_key    = (keyInput ? keyInput.value.trim() : '');

    // The toggle is rendered disabled-and-unchecked until a row exists, so on a
    // first save `enabled.checked` is false and the integration would be stored
    // disabled — connecting fine on Test but invisible to every screen that
    // filters on is_enabled. A disabled toggle means "new integration", and
    // nobody configures one intending it to be off.
    const is_enabled = (enabled && !enabled.disabled) ? enabled.checked : true;

    if (!base_url) { setIntFeedback(providerId, 'Server region / Base URL is required.', true); return; }

    const body = { ...tenantBody(), base_url, is_enabled };
    if (api_key) body.api_key = api_key;

    // Provider-specific extra config
    if (providerId === 'arctic_wolf' || providerId === 'arctic_wolf_reports') {
      const orgUuidInput = container.querySelector(`.int-org-uuid[data-provider="${providerId}"]`);
      const orgUuid = orgUuidInput ? orgUuidInput.value.trim() : '';
      if (!orgUuid) { setIntFeedback(providerId, 'Organization UUID is required for Arctic Wolf.', true); return; }
      body.configJson = { organizationUuid: orgUuid };
    }

    if (providerId === 'sentinelone') {
      const siteInput    = container.querySelector(`.int-site-ids[data-provider="${providerId}"]`);
      const accountInput = container.querySelector(`.int-account-ids[data-provider="${providerId}"]`);
      const siteIds      = siteInput ? siteInput.value.trim() : '';
      const accountIds   = accountInput ? accountInput.value.trim() : '';
      // Both are optional — omitted means "everything this API token can see".
      body.configJson = {};
      if (siteIds)    body.configJson.siteIds    = siteIds;
      if (accountIds) body.configJson.accountIds = accountIds;
    }

    if (providerId === 'acronis') {
      const idInput   = container.querySelector(`.int-client-id[data-provider="${providerId}"]`);
      const uuidInput = container.querySelector(`.int-tenant-uuid[data-provider="${providerId}"]`);
      const clientId  = idInput   ? idInput.value.trim()   : '';
      const tenantUuid = uuidInput ? uuidInput.value.trim() : '';

      if (!clientId) {
        setIntFeedback(providerId, 'Client ID is required for Acronis.', true); return;
      }
      /*
       * The tenant UUID is REQUIRED, not optional.
       *
       * Without it the alert query is unscoped and returns whatever the
       * credential can see. On a per-client API client that is usually just
       * that client — but "usually" is not a property to rely on when the
       * failure mode is writing one customer's targeted mailboxes into another
       * customer's dashboard. Make it explicit and the question never arises.
       */
      if (!tenantUuid) {
        setIntFeedback(providerId,
          'Acronis Tenant UUID is required — without it, alerts cannot be scoped to this client.', true);
        return;
      }
      // The client SECRET is not here: it travels in api_key and is encrypted
      // server-side like every other provider's credential. config_json is
      // stored in the clear, so nothing secret may be put in it.
      body.configJson = { client_id: clientId, tenant_uuid: tenantUuid };
    }

    if (providerId === 'ms_graph') {
      const get = sel => {
        const el = container.querySelector(`${sel}[data-provider="${providerId}"]`);
        return el ? el.value.trim() : '';
      };
      const azureTenantId = get('.int-azure-tenant');
      const appId         = get('.int-app-id');
      const authority     = get('.int-authority');

      /*
       * Both are REQUIRED. The directory ID is not merely a scope hint — it is
       * a path segment of the token endpoint, so an absent one cannot be
       * defaulted to "everything this credential can see" the way SentinelOne's
       * site IDs can. There is nothing sensible to fall back to.
       */
      if (!azureTenantId) {
        setIntFeedback(providerId,
          'Directory (tenant) ID is required — it forms part of the Microsoft token endpoint.', true);
        return;
      }
      if (!appId) {
        setIntFeedback(providerId, 'Application (client) ID is required for Microsoft Graph.', true);
        return;
      }

      // Preserve verified_azure_tenant_id, which the server writes on a
      // successful Test. It is a probe result, not a form field, and dropping
      // it here would silently disarm the directory-mismatch check the sync
      // relies on.
      const existing = (configMapCache[providerId] && configMapCache[providerId].config_json) || {};
      body.configJson = Object.assign({}, existing, {
        azure_tenant_id: azureTenantId,
        client_id: appId,
      });
      // Blank means "commercial cloud". Storing an empty string instead of
      // omitting it would defeat the adapter's default.
      if (authority) body.configJson.authority_url = authority;
      else delete body.configJson.authority_url;

      const idCb = container.querySelector(`.int-identity-enabled[data-provider="${providerId}"]`);
      body.configJson.identity_enabled = !!(idCb && idCb.checked);
      body.configJson.identity_time_zone = get('.int-identity-tz') || 'Africa/Johannesburg';

      /*
       * Changing the directory invalidates the earlier verification: the stored
       * "verified" id would then belong to a different client, and the sync's
       * mismatch warning would fire on every run against the new, correct one.
       */
      if (existing.azure_tenant_id &&
          existing.azure_tenant_id.toLowerCase() !== azureTenantId.toLowerCase()) {
        delete body.configJson.verified_azure_tenant_id;
        // Identity was verified against the old directory too.
        delete body.configJson.identity_verified_tenant;
        delete body.configJson.identity_probe;
      }
    }

    if (providerId === 'fortianalyzer') {
      const get = sel => {
        const el = container.querySelector(`${sel}[data-provider="${providerId}"]`);
        return el ? el.value.trim() : '';
      };
      const adom = get('.int-faz-adom');
      // Same rule as the server: the ADOM becomes part of an API path.
      if (!/^[A-Za-z0-9_-]{1,64}$/.test(adom)) {
        setIntFeedback(providerId,
          'ADOM is required — letters, digits, "-" and "_" only, exactly as named in FortiAnalyzer.', true);
        return;
      }
      // Preserve the verification the server wrote on Test (verified_adom,
      // verified_devices, tlsFingerprint, detected). A changed ADOM no longer
      // matches verified_adom, which is what makes the sync refuse until re-tested.
      const existing = (configMapCache[providerId] && configMapCache[providerId].config_json) || {};
      body.configJson = Object.assign({}, existing, {
        adom,
        timeZone: get('.int-timezone') || 'Africa/Johannesburg',
      });
    }

    try {
      const res = await fetch(`api/integrations/${providerId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(body),
      });
      const r = await readIntJson(res);
      if (!r.ok) { setIntFeedback(providerId, r.error || (r.data && r.data.error) || 'Save failed.', true); return; }
      setIntFeedback(providerId, 'Saved successfully.', false);
      setTimeout(() => renderIntegrations(), 800);
    } catch (err) { setIntFeedback(providerId, 'Network error: ' + err.message, true); }
  }

  async function testIntegration(providerId, container) {
    setIntFeedback(providerId, 'Testing connection…', false);
    try {
      const res = await fetch(`api/integrations/${providerId}/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(tenantBody()),
      });
      const r = await readIntJson(res);
      const data = r.data || {};
      if (!r.ok && r.error) { setIntFeedback(providerId, '✗ ' + r.error, true); return; }
      if (data.ok) {
        // A working connection on a disabled integration still shows nothing on
        // its screens, so it gets a warning mark rather than a clean tick.
        const disabled = data.isEnabled === false;
        setIntFeedback(providerId, (disabled ? '⚠ ' : '✓ ') + data.message, disabled);
        // The card shows what was verified; redraw it so the operator sees the organisation name.
        if (providerId === 'dnsfilter') setTimeout(() => renderIntegrations(), 1500);
      } else {
        setIntFeedback(providerId, '✗ ' + (data.error || 'Connection failed.'), true);
      }
    } catch (err) { setIntFeedback(providerId, 'Network error: ' + err.message, true); }
  }

  async function syncIntegration(providerId, container) {
    const isReports = providerId === 'arctic_wolf_reports';
    setIntFeedback(providerId, isReports ? 'Generating report…' : 'Syncing…', false);
    const syncBtn = container.querySelector(`.int-sync-btn[data-provider="${providerId}"]`);
    if (syncBtn) syncBtn.disabled = true;

    try {
      const res = await fetch(`api/integrations/${providerId}/sync`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(tenantBody()),
      });
      const sync = await readIntJson(res);
      const data = sync.data || {};
      if (!sync.ok && sync.error) { setIntFeedback(providerId, '✗ Sync failed: ' + sync.error, true); return; }
      if (res.status === 202 && data.stillGenerating) {
        setIntFeedback(providerId, '⏳ ' + (data.message || 'Report is still generating — click Sync Now again shortly.'), true);
      } else if (data.ok && isReports) {
        setIntFeedback(providerId, `✓ Synced ${data.synced} session rows. Refreshing awareness…`, false);
        if (typeof window.renderAwareness === 'function') {
          window.renderAwareness().catch(() => {});
        }
        setTimeout(() => renderIntegrations(), 1500);
      } else if (data.ok && (providerId === 'fortianalyzer' || providerId === 'dnsfilter')) {
        setIntFeedback(providerId, `✓ ${data.message}`, false);
        setTimeout(() => renderIntegrations(), 1500);
      } else if (data.ok && providerId === 'sentinelone') {
        setIntFeedback(providerId, `✓ Synced ${data.threats} threats, ${data.activities} activities, ${data.agents} agents.`, false);
        setTimeout(() => renderIntegrations(), 1500);
      } else if (data.ok) {
        setIntFeedback(providerId, `✓ Synced ${data.synced} tickets. Refreshing incidents…`, false);
        // Refresh incidents tab if it's currently visible
        if (typeof window.renderIncidents === 'function') {
          window.renderIncidents('operations').catch(() => {});
        }
        setTimeout(() => renderIntegrations(), 1500);
      } else {
        setIntFeedback(providerId, '✗ Sync failed: ' + (data.error || 'Unknown error'), true);
      }
    } catch (err) {
      setIntFeedback(providerId, 'Network error: ' + err.message, true);
    } finally {
      if (syncBtn) syncBtn.disabled = false;
    }
  }

  async function removeIntegration(providerId) {
    try {
      const res = await fetch(`api/integrations/${providerId}` + tenantQS(), {
        method: 'DELETE',
        credentials: 'same-origin',
      });
      if (res.ok) renderIntegrations();
    } catch (_) {}
  }
})();
