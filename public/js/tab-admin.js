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
    if (selects.length === 0) return;
    if (_tenants.length === 0) await fetchTenants();
    const opts = '<option value="">— Select tenant —</option>' +
      _tenants.map(t => `<option value="${t.id}">${escapeHtml(t.name)}</option>`).join('');
    selects.forEach(sel => {
      const current = sel.value;
      sel.innerHTML = opts;
      if (current) sel.value = current;
    });
  }

  // ── User table ────────────────────────────────────────────────────────────

  async function renderUsers() {
    const tbody = document.getElementById('userTableBody');
    if (!tbody) return;

    try {
      const res  = await fetch(apiUrl('users'), { credentials: 'same-origin' });
      const data = await res.json();

      if (!res.ok) {
        tbody.innerHTML = `<tr><td colspan="6" class="admin-table-empty">${escapeHtml(data.error || 'Failed to load users.')}</td></tr>`;
        return;
      }

      if (data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="admin-table-empty">No users found.</td></tr>';
        return;
      }

      const showTenantCol = isSuperAdmin();

      tbody.innerHTML = data.map(u => {
        const isSelf   = window.currentUser && u.id === window.currentUser.id;
        const roleTag  = u.role === 'superadmin'
          ? '<span class="role-badge role-superadmin">Super Admin</span>'
          : u.role === 'admin'
            ? '<span class="role-badge role-admin">Admin</span>'
            : '<span class="role-badge role-readonly">Read-only</span>';
        const tenantCell = showTenantCol
          ? `<td>${escapeHtml(u.tenant_name || '—')}</td>`
          : '';
        const delBtn = isSelf
          ? '<span class="admin-self-label">you</span>'
          : `<button class="btn btn-danger btn-sm" data-action="delete-user" data-id="${u.id}" data-username="${escapeHtml(u.username)}">Delete</button>`;

        return `<tr>
          <td>${escapeHtml(u.username)}${isSelf ? ' <span class="admin-self-label">(you)</span>' : ''}</td>
          <td>${roleTag}</td>
          ${tenantCell}
          <td>${formatDate(u.created_at)}</td>
          <td>${formatDate(u.last_login)}</td>
          <td class="admin-actions">
            <button class="btn btn-secondary btn-sm" data-action="edit-user"
              data-id="${u.id}" data-username="${escapeHtml(u.username)}" data-role="${u.role}"
              ${isSelf ? 'disabled title="Cannot change your own role"' : ''}>
              Edit
            </button>
            ${delBtn}
          </td>
        </tr>`;
      }).join('');
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="6" class="admin-table-empty">Error: ${escapeHtml(err.message)}</td></tr>`;
    }
  }

  // ── Add user form ─────────────────────────────────────────────────────────

  async function handleAddUser(e) {
    e.preventDefault();
    showAdminError('');
    showAdminSuccess('');

    const username = document.getElementById('newUsername').value.trim();
    const password = document.getElementById('newPassword').value;
    const role     = document.getElementById('newRole').value;
    const body     = { username, password, role };

    if (isSuperAdmin()) {
      const tenantSel = document.getElementById('newUserTenant');
      if (role !== 'superadmin') {
        if (!tenantSel || !tenantSel.value) {
          showAdminError('Please select a tenant for this user.');
          return;
        }
        body.tenantId = parseInt(tenantSel.value, 10);
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

  function openEditModal(userId, username, currentRole) {
    const modal = document.getElementById('editUserModal');
    if (!modal) return;

    document.getElementById('editUserId').value          = userId;
    document.getElementById('editUserTitle').textContent = `Edit: ${username}`;
    document.getElementById('editUserPassword').value    = '';
    document.getElementById('editUserError').hidden      = true;

    const roleSelect  = document.getElementById('editUserRole');
    const allowedRoles = isSuperAdmin()
      ? [['superadmin', 'Super Admin'], ['admin', 'Admin'], ['readonly', 'Read-only']]
      : [['admin', 'Admin'], ['readonly', 'Read-only']];
    roleSelect.innerHTML = allowedRoles
      .map(([val, label]) => `<option value="${val}"${currentRole === val ? ' selected' : ''}>${label}</option>`)
      .join('');

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

    const body = { role };
    if (pass) body.password = pass;

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

  async function handleDeleteUser(userId, username) {
    if (!confirm(`Delete user "${username}"? This cannot be undone.`)) return;
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

    // Remove superadmin role option from Add User form if not superadmin
    if (!isSuperAdmin()) {
      const newRoleSelect = document.getElementById('newRole');
      if (newRoleSelect) {
        Array.from(newRoleSelect.options).forEach(opt => {
          if (opt.value === 'superadmin') opt.remove();
        });
      }
    }
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
        const action   = btn.dataset.action;
        const userId   = parseInt(btn.dataset.id, 10);
        const username = btn.dataset.username || '';
        if (action === 'delete-user') handleDeleteUser(userId, username);
        else if (action === 'edit-user') openEditModal(userId, username, btn.dataset.role);
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
  }

  // ── Init ──────────────────────────────────────────────────────────────────

  window.renderAdmin = renderUsers;

  // Wait for auth.js to set window.currentUser before initialising
  if (window.currentUser) {
    initAdmin();
  } else {
    document.addEventListener('authReady', initAdmin, { once: true });
  }
})();
