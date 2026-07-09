/* tab-incident-response.js — Per-tenant Incident Response tracking */

const IrTab = (() => {
  'use strict';

  let _incidents   = [];
  let _selectedId  = null;
  let _activities  = [];

  function canWrite() { return isAdmin(); }

  function esc(s) {
    return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function fmt(dateStr) {
    if (!dateStr) return '—';
    return new Date(dateStr).toLocaleString('en-ZA', {
      day: 'numeric', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
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

  const PHASES = [
    { value: 'identification',          label: 'Identification' },
    { value: 'containment',             label: 'Containment' },
    { value: 'eradication',             label: 'Eradication' },
    { value: 'recovery',                label: 'Recovery' },
    { value: 'post-incident-analysis',  label: 'Post Incident Analysis' },
  ];
  const PHASE_LABEL = Object.fromEntries(PHASES.map(p => [p.value, p.label]));

  const INCIDENT_TYPES = (window.IrPlaybooks && window.IrPlaybooks.INCIDENT_TYPES) || [{ value: 'other', label: 'Other' }];
  const INCIDENT_TYPE_LABEL = Object.fromEntries(INCIDENT_TYPES.map(t => [t.value, t.label]));

  // ── Playbook track (the selected incident's playbook tasks, progressed in order) ─
  // Tiles are the playbook tasks (ir_activities) seeded for the selected incident,
  // ordered by phase then sort_order. The first non-done task is the "current" step;
  // completing it reveals the next step and, if its phase differs, advances the
  // incident's own phase to match.

  const PHASE_INDEX = Object.fromEntries(PHASES.map((p, i) => [p.value, i]));

  function orderedPlaybookTasks() {
    return _activities
      .filter(a => a.phase)
      .slice()
      .sort((a, b) => (PHASE_INDEX[a.phase] - PHASE_INDEX[b.phase]) || (a.sort_order - b.sort_order));
  }

  function renderPlaybookTrack() {
    const heading = document.getElementById('ir-phase-board-heading');
    const track = document.getElementById('ir-playbook-track');
    const progressLabel = document.getElementById('ir-playbook-progress-label');
    const progressFill = document.getElementById('ir-playbook-progress-fill');
    const incident = _incidents.find(i => i.id === _selectedId);

    if (heading) {
      heading.textContent = incident ? `Playbook — ${incident.title}` : 'Playbook — select an incident';
    }
    if (!track) return;

    if (!incident) {
      track.innerHTML = '<p class="empty-state">Select an incident to view its playbook.</p>';
      if (progressLabel) progressLabel.textContent = '';
      if (progressFill) progressFill.style.width = '0%';
      return;
    }

    const tasks = orderedPlaybookTasks();
    if (tasks.length === 0) {
      track.innerHTML = '<p class="empty-state">No playbook steps for this incident.</p>';
      if (progressLabel) progressLabel.textContent = '';
      if (progressFill) progressFill.style.width = '0%';
      return;
    }

    const doneCount = tasks.filter(t => t.status === 'done').length;
    const currentIndex = tasks.findIndex(t => t.status !== 'done');

    if (progressLabel) {
      progressLabel.textContent = currentIndex === -1
        ? `Playbook complete — ${doneCount}/${tasks.length} steps`
        : `Step ${currentIndex + 1} of ${tasks.length} · ${PHASE_LABEL[tasks[currentIndex].phase] || tasks[currentIndex].phase}`;
    }
    if (progressFill) progressFill.style.width = `${Math.round((doneCount / tasks.length) * 100)}%`;

    let prevPhase = null;
    track.innerHTML = tasks.map((t, i) => {
      const state = t.status === 'done' ? 'is-done' : (i === currentIndex ? 'is-current' : 'is-upcoming');
      const phaseTag = t.phase !== prevPhase ? `<div class="ir-playbook-tile-phase-tag">${esc(PHASE_LABEL[t.phase] || t.phase)}</div>` : '';
      prevPhase = t.phase;
      const actionBtn = (state === 'is-current' && canWrite())
        ? `<button class="btn btn-sm btn-primary ir-playbook-complete-btn" data-id="${t.id}">Mark Complete</button>` : '';
      return `
        <div class="ir-playbook-tile ${state}" data-id="${t.id}">
          ${phaseTag}
          <div class="ir-playbook-tile-step">Step ${i + 1}</div>
          <div class="ir-playbook-tile-entry">${esc(t.entry)}</div>
          <div class="ir-playbook-tile-meta">
            <span class="badge ${ACTIVITY_STATUS_BADGE[t.status] || ''}">${esc(t.status)}</span>
            ${t.assignee ? `<span>${esc(t.assignee)}</span>` : ''}
            ${t.completed_at ? `<span>${fmt(t.completed_at)}</span>` : ''}
          </div>
          ${actionBtn}
        </div>
      `;
    }).join('');

    track.querySelectorAll('.ir-playbook-complete-btn').forEach(btn => {
      btn.addEventListener('click', () => completeStep(parseInt(btn.dataset.id, 10)));
    });
  }

  async function completeStep(activityId) {
    const task = _activities.find(a => a.id === activityId);
    const incident = _incidents.find(i => i.id === _selectedId);
    if (!task || !incident) return;

    const prevStatus = task.status;
    const prevCompletedAt = task.completed_at;
    const prevIncidentPhase = incident.phase;
    const prevIncidentStatus = incident.status;

    task.status = 'done';
    task.completed_at = new Date().toISOString();
    renderPlaybookTrack();
    renderIncidentsTable();

    const isSA = window.currentUser && window.currentUser.role === 'superadmin';
    try {
      const actBody = { entry: task.entry, assignee: task.assignee || '', status: 'done' };
      if (isSA && window.globalTenantId) actBody.tenantId = window.globalTenantId;
      const actRes = await fetch(`api/ir/activities/${activityId}`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
        body: JSON.stringify(actBody),
      });
      if (!actRes.ok) throw new Error('activity update failed');
      const actData = await actRes.json();
      if (actData.activity && actData.activity.completed_at) task.completed_at = actData.activity.completed_at;

      const nextTasks = orderedPlaybookTasks();
      const nextCurrent = nextTasks.find(t => t.status !== 'done');
      const newPhase = nextCurrent ? nextCurrent.phase : incident.phase;
      const newStatus = !nextCurrent ? 'resolved' : (incident.status === 'open' ? 'remediating' : incident.status);

      if (newPhase !== incident.phase || newStatus !== incident.status) {
        const incBody = {
          title: incident.title, incident_type: incident.incident_type, description: incident.description,
          severity: incident.severity, status: newStatus, phase: newPhase, assigned_to: incident.assigned_to,
        };
        if (isSA && window.globalTenantId) incBody.tenantId = window.globalTenantId;
        const incRes = await fetch(`api/ir/incidents/${_selectedId}`, {
          method: 'PUT', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
          body: JSON.stringify(incBody),
        });
        if (!incRes.ok) throw new Error('incident update failed');
        const incData = await incRes.json();
        Object.assign(incident, incData.incident);
        renderIncidentsTable();
        renderStats();
      }
    } catch (_) {
      task.status = prevStatus;
      task.completed_at = prevCompletedAt;
      incident.phase = prevIncidentPhase;
      incident.status = prevIncidentStatus;
      renderPlaybookTrack();
      renderIncidentsTable();
    }
  }

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
      tbody.innerHTML = '<tr><td colspan="10" class="empty-state">No incidents logged.</td></tr>';
      return;
    }

    tbody.innerHTML = _incidents.map(inc => `
      <tr class="${_selectedId === inc.id ? 'row-selected' : ''}" data-id="${inc.id}">
        <td>${esc(inc.title)}</td>
        <td>${esc(INCIDENT_TYPE_LABEL[inc.incident_type] || inc.incident_type)}</td>
        <td><span class="badge ${SEVERITY_BADGE[inc.severity] || ''}">${esc(inc.severity)}</span></td>
        <td><span class="badge ${STATUS_BADGE[inc.status] || ''}">${esc(inc.status)}</span></td>
        <td>${esc(PHASE_LABEL[inc.phase] || inc.phase)}</td>
        <td>${esc(inc.assigned_to || '—')}</td>
        <td>${fmt(inc.opened_at)}</td>
        <td>${fmt(inc.closed_at)}</td>
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
    if (_selectedId === id) { _selectedId = null; _activities = []; }
    await loadIncidents();
    renderIncidentsTable();
    renderPlaybookTrack();
    renderStats();
  }

  // ── Incident selection ─────────────────────────────────────────────────────

  async function selectIncident(id) {
    _selectedId = id;
    renderIncidentsTable();

    const res = await fetch(`api/ir/incidents/${id}/activities` + tenantParam('?'), { credentials: 'same-origin' });
    const data = await res.json();
    _activities = data.activities || [];
    renderPlaybookTrack();
  }

  // ── Incident modal ─────────────────────────────────────────────────────────

  function openIncidentModal(id) {
    const modal = document.getElementById('ir-incident-modal');
    const incident = id ? _incidents.find(i => i.id === id) : null;

    document.getElementById('ir-inc-modal-title').textContent = incident ? 'Edit Incident' : 'New Incident';
    document.getElementById('ir-inc-id').value = incident ? incident.id : '';
    document.getElementById('ir-inc-title').value = incident ? incident.title : '';
    const typeSelect = document.getElementById('ir-inc-type');
    typeSelect.value = incident ? incident.incident_type : 'other';
    typeSelect.disabled = !!incident; // playbook is seeded once, at creation
    document.getElementById('ir-inc-description').value = incident ? incident.description : '';
    document.getElementById('ir-inc-severity').value = incident ? incident.severity : 'medium';
    document.getElementById('ir-inc-status').value = incident ? incident.status : 'open';
    document.getElementById('ir-inc-phase').value = incident ? incident.phase : 'identification';
    document.getElementById('ir-inc-assigned').value = incident ? incident.assigned_to : '';

    modal.hidden = false;
  }

  async function saveIncident() {
    const id = document.getElementById('ir-inc-id').value;
    const body = {
      title: document.getElementById('ir-inc-title').value.trim(),
      incident_type: document.getElementById('ir-inc-type').value,
      description: document.getElementById('ir-inc-description').value.trim(),
      severity: document.getElementById('ir-inc-severity').value,
      status: document.getElementById('ir-inc-status').value,
      phase: document.getElementById('ir-inc-phase').value,
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
    renderPlaybookTrack();
    renderStats();
  }

  // ── Wiring ─────────────────────────────────────────────────────────────────

  function wireOnce() {
    if (IrTab._wired) return;
    IrTab._wired = true;

    document.getElementById('ir-btn-new-incident').addEventListener('click', () => openIncidentModal(null));
    document.getElementById('ir-inc-modal-close').addEventListener('click', () => document.getElementById('ir-incident-modal').hidden = true);
    document.getElementById('ir-inc-modal-save').addEventListener('click', saveIncident);
  }

  // ── Main entry ─────────────────────────────────────────────────────────────

  async function loadAndRender() {
    wireOnce();
    await renderStats();
    await loadIncidents();
    renderIncidentsTable();
    renderPlaybookTrack();
  }

  return { loadAndRender };
})();

window.IrTab = IrTab;
