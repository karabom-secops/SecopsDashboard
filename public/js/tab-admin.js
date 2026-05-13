(function () {
  'use strict';

  /**
   * public/js/tab-admin.js
   * User management tab — visible to admin users only.
   */

  const BASE = (function () {
    const base = document.querySelector('base');
    return base ? base.href : '/';
  })();

  function apiUrl(path) {
    return BASE + 'api/' + path;
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

  // ── Render user table ─────────────────────────────────────────────────────

  async function renderUsers() {
    const tbody = document.getElementById('userTableBody');
    if (!tbody) return;

    try {
      const res  = await fetch(apiUrl('users'), { credentials: 'same-origin' });
      const data = await res.json();

      if (!res.ok) {
        tbody.innerHTML = `<tr><td colspan="5" class="admin-table-empty">${data.error || 'Failed to load users.'}</td></tr>`;
        return;
      }

      if (data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="admin-table-empty">No users found.</td></tr>';
        return;
      }

      tbody.innerHTML = data.map(u => {
        const isSelf  = window.currentUser && u.id === window.currentUser.id;
        const roleTag = u.role === 'admin'
          ? '<span class="role-badge role-admin">Admin</span>'
          : '<span class="role-badge role-readonly">Read-only</span>';
        const delBtn = isSelf
          ? '<span class="admin-self-label">you</span>'
          : `<button class="btn btn-danger btn-sm" data-action="delete-user" data-id="${u.id}" data-username="${escapeHtml(u.username)}">Delete</button>`;

        return `<tr>
          <td>${escapeHtml(u.username)}${isSelf ? ' <span class="admin-self-label">(you)</span>' : ''}</td>
          <td>${roleTag}</td>
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
      tbody.innerHTML = `<tr><td colspan="5" class="admin-table-empty">Error: ${escapeHtml(err.message)}</td></tr>`;
    }
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // ── Add user form ─────────────────────────────────────────────────────────

  async function handleAddUser(e) {
    e.preventDefault();
    showAdminError('');
    showAdminSuccess('');

    const username = document.getElementById('newUsername').value.trim();
    const password = document.getElementById('newPassword').value;
    const role     = document.getElementById('newRole').value;

    const btn = document.getElementById('addUserBtn');
    btn.disabled = true;

    try {
      const res  = await fetch(apiUrl('users'), {
        method:      'POST',
        credentials: 'same-origin',
        headers:     { 'Content-Type': 'application/json' },
        body:        JSON.stringify({ username, password, role }),
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

    document.getElementById('editUserId').value       = userId;
    document.getElementById('editUserTitle').textContent = `Edit: ${username}`;
    document.getElementById('editUserRole').value     = currentRole;
    document.getElementById('editUserPassword').value = '';
    document.getElementById('editUserError').hidden   = true;

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

    const errEl = document.getElementById('editUserError');
    errEl.hidden = true;

    const body = { role };
    if (pass) body.password = pass;

    const btn = document.getElementById('editUserSaveBtn');
    btn.disabled = true;

    try {
      const res  = await fetch(apiUrl(`users/${userId}`), {
        method:      'PUT',
        credentials: 'same-origin',
        headers:     { 'Content-Type': 'application/json' },
        body:        JSON.stringify(body),
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
        method:      'DELETE',
        credentials: 'same-origin',
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

  // ── Event wiring ──────────────────────────────────────────────────────────

  function initAdmin() {
    // Add-user form
    const addForm = document.getElementById('addUserForm');
    if (addForm) addForm.addEventListener('submit', handleAddUser);

    // Edit modal buttons
    const closeBtn = document.getElementById('editUserCancelBtn');
    if (closeBtn) closeBtn.addEventListener('click', closeEditModal);

    const saveBtn = document.getElementById('editUserSaveBtn');
    if (saveBtn) saveBtn.addEventListener('click', handleSaveEdit);

    // Overlay click to close edit modal
    const modal = document.getElementById('editUserModal');
    if (modal) {
      modal.addEventListener('click', function (e) {
        if (e.target === modal) closeEditModal();
      });
    }

    // Escape key closes modal
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && modal && !modal.hidden) closeEditModal();
    });

    // Table action delegation
    const tbody = document.getElementById('userTableBody');
    if (tbody) {
      tbody.addEventListener('click', function (e) {
        const btn = e.target.closest('[data-action]');
        if (!btn) return;
        const action   = btn.dataset.action;
        const userId   = parseInt(btn.dataset.id, 10);
        const username = btn.dataset.username || '';

        if (action === 'delete-user') {
          handleDeleteUser(userId, username);
        } else if (action === 'edit-user') {
          openEditModal(userId, username, btn.dataset.role);
        }
      });
    }

    // Tab activation triggers a user list refresh
    const adminTabBtn = document.getElementById('tab-admin-btn');
    if (adminTabBtn) {
      adminTabBtn.addEventListener('click', renderUsers);
    }
  }

  // ── Init ──────────────────────────────────────────────────────────────────

  window.renderAdmin = renderUsers;

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAdmin);
  } else {
    initAdmin();
  }
})();
