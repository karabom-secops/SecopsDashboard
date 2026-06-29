/* tab-incident-response.js — Per-tenant Incident Response tracking */

const IrTab = (() => {
  'use strict';

  let _incidents   = [];
  let _selectedId  = null;
  let _activities  = [];

  function esc(s) {
    return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function fmt(dateStr) {
    if (!dateStr) return '—';
    return new Date(dateStr).toLocaleString('en-ZA', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
  }

  function isAdmin() {
    const r = window.currentUser && window.currentUser.role;
    return r === 'admin' || r === 'superadmin';
  }

  function tenantParam(sep) {
    const isSA = window.currentUser && window.currentUser.role === 'superadmin';
    if (!isSA || !window.globalTenantId) return '';
    return sep + 'tenantId=' + encodeURIComponent(window.globalTenantId);
  }

  const SEVERITY_BADGE = {
    low: 'badge-muted', medium: 'badge-blue', high: 'badge-amber', critical: 'badge-red',
  };

  const STATUS_BADGE = {
    open: 'badge-red', contained: 'badge-amber', remediating: 'badge-blue',
    resolved: 'badge-green', closed: 'badge-muted',
  };

  const ACTIVITY_STATUS_BADGE = {
    pending: 'badge-muted', 'in-progress': 'badge-blue', done: 'badge-green',
  };

  // ── Stats ──────────────────────────────────────────────────────────────────

  async function renderStats() {
    const el = document.getElementById('ir-stats');
    if (!el) return;
    try {
      const res  = await fetch('api/ir/stats' + tenantParam('?'), { credentials: 'same-origin' });
      const data = await res.json();
      el.innerHTML = `
        <div class="stat-card accent-red">
          <div class="stat-label">Open Incidents</div>
          <div class="stat-value">${data.open}</div>
        </div>
        <div class="stat-card accent-blue">
          <div class="stat-label">In Progress</div>
          <div class="stat-value">${data.inProgress}</div>
        </div>
        <div class="stat-card accent-green">
          <div class="stat-label">Resolved This Month</div>
          <div class="stat-value">${data.resolvedThisMonth}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Avg. Time to Close</div>
          <div class="stat-value">${data.avgCloseHours !== null ? data.avgCloseHours + 'h' : '—'}</div>
        </div>`;
    } catch (_) {
      el.innerHTML = '<p class="empty-state">Failed to load stats.</p>';
    }
  }

  // ── Incidents table ────────────────────────────────────────────────────────

  function renderIncidentsTable() {
    const tbody = document.getElementById('ir-incidents-tbody');
    if (!tbody) return;

    if (_incidents.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No incidents logged.</td></tr>';
      return;
    }

    tbody.innerHTML = _incidents.map(inc => `
      <tr class="${_selectedId === inc.id ? 'row-selected' : ''}" data-id="${inc.id}">
        <td>${esc(inc.title)}</td>
        <td><span class="badge ${SEVERITY_BADGE[inc.severity] || ''}">${esc(inc.severity)}</span></td>
        <td><span class="badge ${STATUS_BADGE[inc.status] || ''}">${esc(inc.status)}</span></td>
        <td>${esc(inc.assigned_to || '—')}</td>
        <td>${fmt(inc.opened_at)}</td>
        <td>${inc.activity_count || 0}</td>
        <td>
          <button class="btn btn-sm btn-secondary ir-view-btn" data-id="${inc.id}">View</button>
          ${isAdmin() ? `<button class="btn btn-sm btn-secondary ir-edit-btn" data-id="${inc.id}">Edit</button>
          <button class="btn btn-sm btn-danger ir-delete-btn" data-id="${inc.id}">Delete</button>` : ''}
        </td>
      </tr>
    `).join('');

    tbody.querySelectorAll('.ir-view-btn').forEach(btn => {
      btn.addEventListener('click', () => selectIncident(parseInt(btn.dataset.id, 10)));
    });
    tbody.querySelectorAll('.ir-edit-btn').forEach(btn => {
      btn.addEventListener('click', () => openIncidentModal(parseInt(btn.dataset.id, 10)));
    });
    tbody.querySelectorAll('.ir-delete-btn').forEach(btn => {
      btn.addEventListener('click', () => deleteIncident(parseInt(btn.dataset.id, 10)));
    });
  }

  async function loadIncidents() {
    const res = await fetch('api/ir/incidents' + tenantParam('?'), { credentials: 'same-origin' });
    const data = await res.json();
    _incidents = data.incidents || [];
  }

  async function deleteIncident(id) {
    if (!confirm('Delete this incident and its activity log?')) return;
    await fetch(`api/ir/incidents/${id}` + tenantParam('?'), { method: 'DELETE', credentials: 'same-origin' });
    if (_selectedId === id) _selectedId = null;
    await loadIncidents();
    renderIncidentsTable();
    renderStats();
  }

  // ── Activity log ───────────────────────────────────────────────────────────

  async function selectIncident(id) {
    _selectedId = id;
    renderIncidentsTable();
    const heading = document.getElementById('ir-activities-heading');
    const incident = _incidents.find(i => i.id === id);
    if (heading) heading.textContent = incident ? `Activity Log — ${incident.title}` : 'Activity Log';
    document.getElementById('ir-btn-new-activity').hidden = false;

    const res = await fetch(`api/ir/incidents/${id}/activities` + tenantParam('?'), { credentials: 'same-origin' });
    const data = await res.json();
    _activities = data.activities || [];
    renderActivitiesTable();
  }

  function renderActivitiesTable() {
    const tbody = document.getElementById('ir-activities-tbody');
    if (!tbody) return;

    if (!_selectedId) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-state">Select an incident to view its activity log.</td></tr>';
      return;
    }
    if (_activities.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No activity logged yet.</td></tr>';
      return;
    }

    tbody.innerHTML = _activities.map(a => `
      <tr data-id="${a.id}">
        <td>${esc(a.entry)}</td>
        <td>${esc(a.assignee || '—')}</td>
        <td><span class="badge ${ACTIVITY_STATUS_BADGE[a.status] || ''}">${esc(a.status)}</span></td>
        <td>${fmt(a.logged_at)}</td>
        <td>
          ${isAdmin() ? `<button class="btn btn-sm btn-danger ir-activity-delete-btn" data-id="${a.id}">Delete</button>` : ''}
        </td>
      </tr>
    `).join('');

    tbody.querySelectorAll('.ir-activity-delete-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        if (!confirm('Delete this activity entry?')) return;
        await fetch(`api/ir/activities/${btn.dataset.id}` + tenantParam('?'), { method: 'DELETE', credentials: 'same-origin' });
        await selectIncident(_selectedId);
      });
    });
  }

  // ── Incident modal ─────────────────────────────────────────────────────────

  function openIncidentModal(id) {
    const modal = document.getElementById('ir-incident-modal');
    const incident = id ? _incidents.find(i => i.id === id) : null;

    document.getElementById('ir-inc-modal-title').textContent = incident ? 'Edit Incident' : 'New Incident';
    document.getElementById('ir-inc-id').value = incident ? incident.id : '';
    document.getElementById('ir-inc-title').value = incident ? incident.title : '';
    document.getElementById('ir-inc-description').value = incident ? incident.description : '';
    document.getElementById('ir-inc-severity').value = incident ? incident.severity : 'medium';
    document.getElementById('ir-inc-status').value = incident ? incident.status : 'open';
    document.getElementById('ir-inc-assigned').value = incident ? incident.assigned_to : '';

    modal.hidden = false;
  }

  async function saveIncident() {
    const id = document.getElementById('ir-inc-id').value;
    const body = {
      title: document.getElementById('ir-inc-title').value.trim(),
      description: document.getElementById('ir-inc-description').value.trim(),
      severity: document.getElementById('ir-inc-severity').value,
      status: document.getElementById('ir-inc-status').value,
      assigned_to: document.getElementById('ir-inc-assigned').value.trim(),
    };
    if (!body.title) { alert('Title is required.'); return; }

    const isSA = window.currentUser && window.currentUser.role === 'superadmin';
    if (isSA && window.globalTenantId) body.tenantId = window.globalTenantId;

    const url = id ? `api/ir/incidents/${id}` : 'api/ir/incidents';
    const method = id ? 'PUT' : 'POST';
    await fetch(url, {
      method, headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
      body: JSON.stringify(body),
    });

    document.getElementById('ir-incident-modal').hidden = true;
    await loadIncidents();
    renderIncidentsTable();
    renderStats();
  }

  // ── Activity modal ─────────────────────────────────────────────────────────

  function openActivityModal() {
    if (!_selectedId) return;
    document.getElementById('ir-act-entry').value = '';
    document.getElementById('ir-act-assignee').value = '';
    document.getElementById('ir-act-status').value = 'pending';
    document.getElementById('ir-activity-modal').hidden = false;
  }

  async function saveActivity() {
    const body = {
      incidentId: _selectedId,
      entry: document.getElementById('ir-act-entry').value.trim(),
      assignee: document.getElementById('ir-act-assignee').value.trim(),
      status: document.getElementById('ir-act-status').value,
    };
    if (!body.entry) { alert('Entry text is required.'); return; }

    const isSA = window.currentUser && window.currentUser.role === 'superadmin';
    if (isSA && window.globalTenantId) body.tenantId = window.globalTenantId;

    await fetch('api/ir/activities', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
      body: JSON.stringify(body),
    });

    document.getElementById('ir-activity-modal').hidden = true;
    await selectIncident(_selectedId);
    await loadIncidents();
    renderIncidentsTable();
  }

  // ── Wiring ─────────────────────────────────────────────────────────────────

  function wireOnce() {
    if (IrTab._wired) return;
    IrTab._wired = true;

    document.getElementById('ir-btn-new-incident').addEventListener('click', () => openIncidentModal(null));
    document.getElementById('ir-inc-modal-close').addEventListener('click', () => document.getElementById('ir-incident-modal').hidden = true);
    document.getElementById('ir-inc-modal-save').addEventListener('click', saveIncident);

    document.getElementById('ir-btn-new-activity').addEventListener('click', openActivityModal);
    document.getElementById('ir-act-modal-close').addEventListener('click', () => document.getElementById('ir-activity-modal').hidden = true);
    document.getElementById('ir-act-modal-save').addEventListener('click', saveActivity);
  }

  // ── Main entry ─────────────────────────────────────────────────────────────

  async function loadAndRender() {
    wireOnce();
    await renderStats();
    await loadIncidents();
    renderIncidentsTable();
    renderActivitiesTable();
  }

  return { loadAndRender };
})();

window.IrTab = IrTab;
