/* tab-redteam.js — Red Team Operations tab */

const RedteamTab = (() => {
  'use strict';

  let _projects      = [];
  let _selectedId    = null;
  let _calDate       = new Date();
  let _calView       = 'month';
  let _initialized   = false;
  let _tenants       = [];
  const STATUS_OPTIONS_FINDING = [['open', 'Open'], ['in-progress', 'In Progress'], ['fixed', 'Fixed'], ['accepted', 'Accepted'], ['risk-accepted', 'Risk Accepted']];

  // ── Helpers ────────────────────────────────────────────────────────────────

  function isAdmin() {
    return window.canWrite('redteam');
  }

  function esc(s) {
    return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function fmt(dateStr) {
    if (!dateStr) return '—';
    return dateStr.slice(0, 10);
  }

  function isOverdue(task) {
    if (!task.due_date || task.status === 'done') return false;
    return task.due_date.slice(0, 10) < new Date().toISOString().slice(0, 10);
  }

  const STATUS_COLORS = {
    planned:   '#06b6d4',
    active:    '#22c55e',
    paused:    '#f59e0b',
    completed: '#94a3b8',
    cancelled: '#ef4444',
  };

  const STATUS_BADGE = {
    planned:   'badge-blue',
    active:    'badge-green',
    paused:    'badge-amber',
    completed: 'badge-muted',
    cancelled: 'badge-red',
  };

  const TASK_STATUS_BADGE = {
    'todo':        'badge-muted',
    'in-progress': 'badge-blue',
    'done':        'badge-green',
    'blocked':     'badge-red',
  };

  // ── Stats ──────────────────────────────────────────────────────────────────

  async function renderStats() {
    const el = document.getElementById('redteam-stats');
    if (!el) return;
    try {
      const res  = await fetch('api/redteam/stats', { credentials: 'same-origin' });
      const data = await res.json();
      el.innerHTML = `
        <div class="stat-card accent-blue">
          <div class="stat-label">Active Engagements</div>
          <div class="stat-value">${data.activeEngagements}</div>
        </div>
        <div class="stat-card accent-green">
          <div class="stat-label">Upcoming Pentests</div>
          <div class="stat-value">${data.upcomingPentests}</div>
        </div>
        <div class="stat-card accent-amber">
          <div class="stat-label">Tasks Due This Week</div>
          <div class="stat-value">${data.tasksDueThisWeek}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Task Completion Rate</div>
          <div class="stat-value">${data.completionRate}%</div>
        </div>`;
    } catch (_) {
      el.innerHTML = '<p class="empty-state">Failed to load stats.</p>';
    }
  }

  // ── Calendar ───────────────────────────────────────────────────────────────

  function projectsForDay(dateStr) {
    return _projects.filter(p => {
      const s = p.start_date ? p.start_date.slice(0, 10) : null;
      const e = p.end_date   ? p.end_date.slice(0, 10)   : null;
      return s && e && dateStr >= s && dateStr <= e;
    });
  }

  function renderCalendar() {
    const wrap = document.getElementById('redteam-cal');
    if (!wrap) return;
    const today = new Date().toISOString().slice(0, 10);

    const navHtml = `
      <div class="cal-header">
        <div style="display:flex;align-items:center;gap:8px;">
          <button class="btn btn-sm btn-secondary" id="rt-cal-prev">&#8592;</button>
          <span class="cal-title" id="rt-cal-title"></span>
          <button class="btn btn-sm btn-secondary" id="rt-cal-next">&#8594;</button>
        </div>
        <div class="cal-view-toggle">
          <button class="btn btn-sm ${_calView==='month'?'btn-primary':'btn-secondary'}" id="rt-cal-month">Month</button>
          <button class="btn btn-sm ${_calView==='week'?'btn-primary':'btn-secondary'}"  id="rt-cal-week">Week</button>
        </div>
      </div>`;

    let gridHtml = '';
    const DAY_HEADERS = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];

    if (_calView === 'month') {
      const y = _calDate.getFullYear(), m = _calDate.getMonth();
      const firstDay = new Date(y, m, 1).getDay();
      const daysInMonth = new Date(y, m + 1, 0).getDate();
      const monthName = _calDate.toLocaleString('default', { month: 'long', year: 'numeric' });
      document.getElementById('rt-cal-title') && (document.getElementById('rt-cal-title').textContent = monthName);

      const headerRow = DAY_HEADERS.map(d => `<div class="cal-day-header">${d}</div>`).join('');
      let cells = '';
      for (let i = 0; i < firstDay; i++) cells += '<div class="cal-day cal-day--empty"></div>';
      for (let d = 1; d <= daysInMonth; d++) {
        const ds = `${y}-${String(m+1).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
        const projs = projectsForDay(ds);
        const isToday = ds === today;
        const bars = projs.slice(0, 3).map(p =>
          `<div class="cal-event-bar" style="background:${STATUS_COLORS[p.status]||'#64748b'}"
                data-pid="${p.id}" title="${esc(p.title)}">${esc(p.title)}</div>`
        ).join('');
        const more = projs.length > 3 ? `<div class="cal-event-more">+${projs.length-3} more</div>` : '';
        cells += `<div class="cal-day${isToday?' cal-day--today':''}">
          <span class="cal-day-num">${d}</span>
          ${bars}${more}
        </div>`;
      }
      gridHtml = `<div class="cal-grid">${headerRow}${cells}</div>`;
    } else {
      // Week view
      const dow = _calDate.getDay();
      const weekStart = new Date(_calDate);
      weekStart.setDate(_calDate.getDate() - dow);
      const days = Array.from({length:7}, (_, i) => {
        const d = new Date(weekStart);
        d.setDate(weekStart.getDate() + i);
        return d;
      });
      const rangeLabel = `${days[0].toLocaleDateString('default',{month:'short',day:'numeric'})} – ${days[6].toLocaleDateString('default',{month:'short',day:'numeric',year:'numeric'})}`;
      document.getElementById('rt-cal-title') && (document.getElementById('rt-cal-title').textContent = rangeLabel);

      const cols = days.map((d, i) => {
        const ds = d.toISOString().slice(0, 10);
        const isToday = ds === today;
        const projs = projectsForDay(ds);
        const bars = projs.map(p =>
          `<div class="cal-event-bar" style="background:${STATUS_COLORS[p.status]||'#64748b'}"
                data-pid="${p.id}" title="${esc(p.title)}">${esc(p.title)}</div>`
        ).join('');
        return `<div class="cal-week-col${isToday?' cal-day--today':''}">
          <div class="cal-day-header">${DAY_HEADERS[i]} ${d.getDate()}</div>
          ${bars || '<div style="color:#94a3b8;font-size:.75rem;padding:4px">—</div>'}
        </div>`;
      }).join('');
      gridHtml = `<div class="cal-week-grid">${cols}</div>`;
    }

    wrap.innerHTML = `<div class="redteam-cal-wrap">${navHtml}${gridHtml}</div>`;

    // Bind nav buttons
    document.getElementById('rt-cal-prev').addEventListener('click', () => {
      if (_calView === 'month') _calDate.setMonth(_calDate.getMonth() - 1);
      else _calDate.setDate(_calDate.getDate() - 7);
      renderCalendar();
    });
    document.getElementById('rt-cal-next').addEventListener('click', () => {
      if (_calView === 'month') _calDate.setMonth(_calDate.getMonth() + 1);
      else _calDate.setDate(_calDate.getDate() + 7);
      renderCalendar();
    });
    document.getElementById('rt-cal-month').addEventListener('click', () => { _calView = 'month'; renderCalendar(); });
    document.getElementById('rt-cal-week').addEventListener('click',  () => { _calView = 'week';  renderCalendar(); });

    // Event bar clicks
    wrap.querySelectorAll('.cal-event-bar').forEach(bar => {
      bar.addEventListener('click', () => selectProject(parseInt(bar.dataset.pid, 10)));
    });

    // Update title text now that elements exist
    const titleEl = document.getElementById('rt-cal-title');
    if (titleEl) {
      if (_calView === 'month') {
        titleEl.textContent = _calDate.toLocaleString('default', { month: 'long', year: 'numeric' });
      }
    }
  }

  // ── Projects table ─────────────────────────────────────────────────────────

  function renderProjects() {
    const tbody = document.getElementById('redteam-projects-tbody');
    if (!tbody) return;
    if (_projects.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No engagements yet.</td></tr>';
      return;
    }
    tbody.innerHTML = _projects.map(p => {
      const sel = p.id === _selectedId ? ' row-selected' : '';
      const done = parseInt(p.tasks_done, 10) || 0;
      const total = parseInt(p.task_count, 10) || 0;
      const pct = total > 0 ? Math.round((done/total)*100) : 0;
      const adminBtns = isAdmin() ? `
        <button class="btn btn-sm btn-secondary rt-edit-proj" data-id="${p.id}">Edit</button>
        <button class="btn btn-sm btn-danger rt-del-proj"  data-id="${p.id}">Delete</button>` : '';
      return `<tr class="${sel}" data-id="${p.id}" style="cursor:pointer">
        <td>${esc(p.title)}</td>
        <td>${esc(p.client)}</td>
        <td>${p.tenant_name ? `<span class="badge badge-blue">${esc(p.tenant_name)}</span>` : '<span class="empty-state">Not linked</span>'}</td>
        <td><span class="role-badge ${STATUS_BADGE[p.status]||''}">${esc(p.status)}</span></td>
        <td>${fmt(p.start_date)}</td>
        <td>${fmt(p.end_date)}</td>
        <td>${done}/${total} (${pct}%)</td>
        <td>${adminBtns}</td>
      </tr>`;
    }).join('');

    tbody.querySelectorAll('tr[data-id]').forEach(row => {
      row.addEventListener('click', e => {
        if (e.target.closest('button')) return;
        selectProject(parseInt(row.dataset.id, 10));
      });
    });
    tbody.querySelectorAll('.rt-edit-proj').forEach(btn => {
      btn.addEventListener('click', e => { e.stopPropagation(); openProjectModal(parseInt(btn.dataset.id, 10)); });
    });
    tbody.querySelectorAll('.rt-del-proj').forEach(btn => {
      btn.addEventListener('click', e => { e.stopPropagation(); deleteProject(parseInt(btn.dataset.id, 10)); });
    });
  }

  async function deleteProject(id) {
    if (!confirm('Delete this engagement and all its tasks?')) return;
    try {
      const res = await fetch(`api/redteam/projects/${id}`, { method: 'DELETE', credentials: 'same-origin' });
      if (!res.ok) throw new Error((await res.json()).error);
      if (_selectedId === id) _selectedId = null;
      await loadAndRender();
    } catch (err) { alert('Delete failed: ' + err.message); }
  }

  // ── Tasks table ────────────────────────────────────────────────────────────

  async function selectProject(id) {
    _selectedId = id;
    renderProjects();
    updateReportControls();
    await loadTasks(id);
    await loadFindings(id);
  }

  async function loadTasks(projectId) {
    const tbody  = document.getElementById('redteam-tasks-tbody');
    const heading = document.getElementById('redteam-tasks-heading');
    if (!tbody) return;

    const proj = _projects.find(p => p.id === projectId);
    if (heading) heading.textContent = proj ? `Tasks — ${proj.title}` : 'Tasks';

    try {
      const res  = await fetch(`api/redteam/projects/${projectId}/tasks`, { credentials: 'same-origin' });
      const data = await res.json();
      renderTasks(data.tasks || []);
    } catch (_) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Failed to load tasks.</td></tr>';
    }
  }

  function renderTasks(tasks) {
    const tbody = document.getElementById('redteam-tasks-tbody');
    if (!tbody) return;
    if (tasks.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No tasks for this engagement.</td></tr>';
      return;
    }
    const today = new Date().toISOString().slice(0, 10);
    tbody.innerHTML = tasks.map(t => {
      const over = isOverdue(t);
      const dueCls = over ? ' class="overdue-date"' : '';
      const adminBtns = isAdmin() ? `
        <button class="btn btn-sm btn-secondary rt-edit-task" data-id="${t.id}">Edit</button>
        <button class="btn btn-sm btn-danger rt-del-task"  data-id="${t.id}">Delete</button>` : '';
      return `<tr>
        <td>${esc(t.title)}</td>
        <td>${esc(t.assignee) || '—'}</td>
        <td${dueCls}>${fmt(t.due_date)}</td>
        <td><span class="role-badge ${TASK_STATUS_BADGE[t.status]||''}">${esc(t.status)}</span></td>
        <td>${esc(t.notes) || '—'}</td>
        <td>${adminBtns}</td>
      </tr>`;
    }).join('');

    tbody.querySelectorAll('.rt-edit-task').forEach(btn => {
      btn.addEventListener('click', () => openTaskModal(parseInt(btn.dataset.id, 10)));
    });
    tbody.querySelectorAll('.rt-del-task').forEach(btn => {
      btn.addEventListener('click', () => deleteTask(parseInt(btn.dataset.id, 10)));
    });
  }

  async function deleteTask(id) {
    if (!confirm('Delete this task?')) return;
    try {
      const res = await fetch(`api/redteam/tasks/${id}`, { method: 'DELETE', credentials: 'same-origin' });
      if (!res.ok) throw new Error((await res.json()).error);
      await loadTasks(_selectedId);
    } catch (err) { alert('Delete failed: ' + err.message); }
  }

  // ── Findings table ─────────────────────────────────────────────────────────

  let _findings = [];

  const FINDING_STATUS_BADGE = {
    'open':          'badge-muted',
    'in-progress':   'badge-blue',
    'fixed':         'badge-green',
    'accepted':      'badge-amber',
    'risk-accepted': 'badge-amber',
  };

  async function loadFindings(projectId) {
    const tbody   = document.getElementById('redteam-findings-tbody');
    const heading = document.getElementById('redteam-findings-heading');
    const hint    = document.getElementById('redteam-findings-hint');
    if (!tbody) return;

    const proj = _projects.find(p => p.id === projectId);
    if (heading) heading.textContent = proj ? `Findings — ${proj.title}` : 'Findings';
    if (hint) hint.hidden = !proj || !!proj.tenant_id;

    try {
      const res  = await fetch(`api/redteam/projects/${projectId}/findings`, { credentials: 'same-origin' });
      const data = await res.json();
      // Sorted the same way the report numbers them, so the Ref column matches.
      _findings = (data.findings || []).sort(compareForReport);
      renderFindings();
    } catch (_) {
      _findings = [];
      tbody.innerHTML = '<tr><td colspan="8" class="empty-state">Failed to load findings.</td></tr>';
    }
  }

  /** Mirrors the ORDER BY on GET /api/redteam/projects/:id/report.docx. */
  function compareForReport(a, b) {
    const ao = parseInt(a.sort_order, 10) || 0;
    const bo = parseInt(b.sort_order, 10) || 0;
    if (ao !== bo) return ao - bo;
    const as = a.cvss_score == null ? -1 : Number(a.cvss_score);
    const bs = b.cvss_score == null ? -1 : Number(b.cvss_score);
    if (as !== bs) return bs - as;
    return a.id - b.id;
  }

  function renderFindings() {
    const tbody = document.getElementById('redteam-findings-tbody');
    if (!tbody) return;
    if (_findings.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No findings for this engagement.</td></tr>';
      return;
    }
    tbody.innerHTML = _findings.map((f, i) => {
      const adminBtns = isAdmin() ? `
        <button class="btn btn-sm btn-secondary rt-edit-finding" data-id="${f.id}">Edit</button>
        <button class="btn btn-sm btn-danger rt-del-finding"  data-id="${f.id}">Delete</button>` : '';
      const score = f.cvss_score == null || f.cvss_score === '' ? '—' : Number(f.cvss_score).toFixed(1);
      return `<tr>
        <td>${String(i + 1).padStart(3, '0')}</td>
        <td>${esc(f.title)}</td>
        <td>${esc(f.severity)}</td>
        <td>${score}</td>
        <td>${esc(f.owner) || '—'}</td>
        <td>${fmt(f.due_date)}</td>
        <td><span class="role-badge ${FINDING_STATUS_BADGE[f.status]||''}">${esc(f.status)}</span></td>
        <td>${adminBtns}</td>
      </tr>`;
    }).join('');

    tbody.querySelectorAll('.rt-edit-finding').forEach(btn => {
      btn.addEventListener('click', () => openFindingModal(parseInt(btn.dataset.id, 10)));
    });
    tbody.querySelectorAll('.rt-del-finding').forEach(btn => {
      btn.addEventListener('click', () => deleteFinding(parseInt(btn.dataset.id, 10)));
    });
  }

  function findingTenantQuery(id) {
    const isSA = window.currentUser && window.currentUser.role === 'superadmin';
    if (!isSA) return '';
    const finding = _findings.find(f => f.id === id);
    return finding && finding.tenant_id ? `?tenantId=${encodeURIComponent(finding.tenant_id)}` : '';
  }

  async function deleteFinding(id) {
    if (!confirm('Delete this finding?')) return;
    try {
      const res = await fetch(`api/pentest-findings/${id}${findingTenantQuery(id)}`, { method: 'DELETE', credentials: 'same-origin' });
      if (!res.ok) throw new Error((await res.json()).error);
      await loadFindings(_selectedId);
    } catch (err) { alert('Delete failed: ' + err.message); }
  }

  function openFindingModal(editId) {
    const modal = document.getElementById('redteam-finding-modal');
    const form  = document.getElementById('rt-finding-form');
    if (!modal || !form) return;

    const proj = _projects.find(p => p.id === _selectedId);
    if (!proj || !proj.tenant_id) {
      alert('Link this engagement to a tenant before adding findings.');
      return;
    }

    const finding = editId ? _findings.find(f => f.id === editId) : null;

    form.querySelector('#rt-finding-id').value             = editId || '';
    form.querySelector('#rt-finding-title').value          = finding ? finding.title : '';
    form.querySelector('#rt-finding-severity').value       = finding ? finding.severity : 'medium';
    form.querySelector('#rt-finding-description').value    = finding ? finding.description : '';
    form.querySelector('#rt-finding-recommendation').value = finding ? finding.recommendation : '';
    form.querySelector('#rt-finding-owner').value           = finding ? finding.owner : '';
    form.querySelector('#rt-finding-due').value             = finding && finding.due_date ? finding.due_date.slice(0,10) : '';
    form.querySelector('#rt-finding-status').value          = finding ? finding.status : 'open';
    form.querySelector('#rt-finding-notes').value           = finding ? finding.notes : '';

    form.querySelector('#rt-finding-classification').value  = finding ? (finding.classification || '') : '';
    form.querySelector('#rt-finding-cvss-vector').value     = finding ? (finding.cvss_vector || '') : '';
    form.querySelector('#rt-finding-cvss-score').value      = finding && finding.cvss_score != null ? finding.cvss_score : '';
    form.querySelector('#rt-finding-endpoints').value       = finding ? (finding.affected_endpoints || '') : '';
    form.querySelector('#rt-finding-business-impact').value = finding ? (finding.business_impact || '') : '';
    form.querySelector('#rt-finding-sort').value            = finding ? (finding.sort_order || 0) : _findings.length;

    // Evidence needs a finding row to hang off, so it only appears when editing.
    document.getElementById('rt-finding-evidence-new').hidden  = !!editId;
    document.getElementById('rt-finding-evidence-wrap').hidden = !editId;
    document.getElementById('rt-finding-evidence-file').value  = '';
    if (editId) loadEvidence(editId);

    document.getElementById('rt-finding-modal-title').textContent = editId ? 'Edit Finding' : 'New Finding';
    document.getElementById('rt-finding-modal-delete').hidden = !editId;
    modal.hidden = false;
  }

  // ── Finding evidence ───────────────────────────────────────────────────────

  async function loadEvidence(findingId) {
    const list = document.getElementById('rt-finding-evidence-list');
    if (!list) return;
    list.innerHTML = '<p class="section-subtitle">Loading…</p>';
    try {
      const res  = await fetch(`api/redteam/findings/${findingId}/evidence`, { credentials: 'same-origin' });
      const data = await res.json();
      renderEvidence(data.evidence || []);
    } catch (_) {
      list.innerHTML = '<p class="section-subtitle">Failed to load evidence.</p>';
    }
  }

  function renderEvidence(items) {
    const list = document.getElementById('rt-finding-evidence-list');
    if (!list) return;
    if (items.length === 0) {
      list.innerHTML = '<p class="section-subtitle">No evidence attached.</p>';
      return;
    }
    list.innerHTML = items.map(ev => `
      <div style="display:flex;gap:.75rem;align-items:flex-start;margin-bottom:.75rem">
        <img src="api/redteam/evidence/${ev.id}" alt="${esc(ev.filename)}"
             style="width:120px;border:1px solid var(--border);border-radius:6px">
        <div style="flex:1;min-width:0">
          <div class="section-subtitle" style="margin:0 0 .25rem;word-break:break-all">${esc(ev.filename)}</div>
          <input class="form-input rt-ev-caption" data-id="${ev.id}" type="text"
                 placeholder="Caption" value="${esc(ev.caption)}">
        </div>
        <button class="btn btn-sm btn-danger rt-ev-del" type="button" data-id="${ev.id}">Remove</button>
      </div>`).join('');

    list.querySelectorAll('.rt-ev-del').forEach(btn => {
      btn.addEventListener('click', () => deleteEvidence(parseInt(btn.dataset.id, 10)));
    });
    // Captions save on blur so they survive closing the modal via Cancel.
    list.querySelectorAll('.rt-ev-caption').forEach(input => {
      input.addEventListener('blur', () => saveEvidenceCaption(parseInt(input.dataset.id, 10), input.value.trim()));
    });
  }

  async function saveEvidenceCaption(id, caption) {
    try {
      await fetch(`api/redteam/evidence/${id}`, {
        method: 'PUT', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ caption }),
      });
    } catch (_) { /* non-fatal — the image is still attached */ }
  }

  async function uploadEvidence(file) {
    const findingId = document.getElementById('rt-finding-id').value;
    if (!findingId || !file) return;
    const fd = new FormData();
    fd.append('file', file);
    try {
      const res = await fetch(`api/redteam/findings/${findingId}/evidence`, {
        method: 'POST', credentials: 'same-origin', body: fd,
      });
      if (!res.ok) throw new Error((await res.json()).error);
      document.getElementById('rt-finding-evidence-file').value = '';
      await loadEvidence(findingId);
    } catch (err) { alert('Upload failed: ' + err.message); }
  }

  async function deleteEvidence(id) {
    if (!confirm('Remove this evidence image?')) return;
    try {
      const res = await fetch(`api/redteam/evidence/${id}`, { method: 'DELETE', credentials: 'same-origin' });
      if (!res.ok) throw new Error((await res.json()).error);
      await loadEvidence(document.getElementById('rt-finding-id').value);
    } catch (err) { alert('Delete failed: ' + err.message); }
  }

  async function saveFinding() {
    const form = document.getElementById('rt-finding-form');
    const id   = form.querySelector('#rt-finding-id').value;
    const body = {
      title:          form.querySelector('#rt-finding-title').value.trim(),
      severity:       form.querySelector('#rt-finding-severity').value,
      description:    form.querySelector('#rt-finding-description').value.trim(),
      recommendation: form.querySelector('#rt-finding-recommendation').value.trim(),
      owner:          form.querySelector('#rt-finding-owner').value.trim(),
      due_date:       form.querySelector('#rt-finding-due').value || null,
      status:         form.querySelector('#rt-finding-status').value,
      notes:          form.querySelector('#rt-finding-notes').value.trim(),

      classification:     form.querySelector('#rt-finding-classification').value.trim(),
      cvss_vector:        form.querySelector('#rt-finding-cvss-vector').value.trim(),
      cvss_score:         form.querySelector('#rt-finding-cvss-score').value,
      affected_endpoints: form.querySelector('#rt-finding-endpoints').value.trim(),
      business_impact:    form.querySelector('#rt-finding-business-impact').value.trim(),
      sort_order:         form.querySelector('#rt-finding-sort').value,
    };
    if (!body.title) { alert('Title is required.'); return; }

    if (id) {
      const isSA = window.currentUser && window.currentUser.role === 'superadmin';
      const finding = _findings.find(f => f.id === parseInt(id, 10));
      if (finding) body.project_id = finding.project_id;
      if (isSA && finding) body.tenantId = finding.tenant_id;
    }

    try {
      const url    = id ? `api/pentest-findings/${id}` : `api/redteam/projects/${_selectedId}/findings`;
      const method = id ? 'PUT' : 'POST';
      const res    = await fetch(url, { method, credentials: 'same-origin', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
      if (!res.ok) throw new Error((await res.json()).error);
      document.getElementById('redteam-finding-modal').hidden = true;
      await loadFindings(_selectedId);
    } catch (err) { alert('Save failed: ' + err.message); }
  }

  // ── Client report ──────────────────────────────────────────────────────────

  // Maps a report_meta text column to its input in #redteam-report-modal.
  const REPORT_FIELDS = [
    ['report_title',           'rt-report-title'],
    ['report_subtitle',        'rt-report-subtitle'],
    ['report_version',         'rt-report-version'],
    ['exec_summary',           'rt-report-exec-summary'],
    ['key_risk_themes',        'rt-report-key-risk-themes'],
    ['approach',               'rt-report-approach'],
    ['scope_objectives',       'rt-report-scope-objectives'],
    ['findings_summary',       'rt-report-findings-summary'],
    ['mitigating_factors',     'rt-report-mitigating-factors'],
    ['attack_paths_intro',     'rt-report-attack-paths-intro'],
    ['attack_paths_narrative', 'rt-report-attack-paths-narrative'],
    ['next_steps',             'rt-report-next-steps'],
    ['scope_endpoints',        'rt-report-scope-endpoints'],
    ['methodology',            'rt-report-methodology'],
    ['timeline_note',          'rt-report-timeline'],
  ];

  function updateReportControls() {
    const proj    = _projects.find(p => p.id === _selectedId);
    const heading = document.getElementById('redteam-report-heading');
    const hint    = document.getElementById('redteam-report-hint');
    const btnGen  = document.getElementById('rt-btn-generate-report');
    const btnMeta = document.getElementById('rt-btn-report-details');

    if (heading) heading.textContent = proj ? `Client Report — ${proj.title}` : 'Client Report';
    if (hint) {
      hint.hidden = !!proj;
      hint.textContent = 'Select an engagement to generate its penetration test report.';
    }
    if (btnGen)  btnGen.disabled  = !proj;
    if (btnMeta) btnMeta.disabled = !proj;
  }

  async function openReportModal() {
    if (!_selectedId) { alert('Select an engagement first.'); return; }
    const modal = document.getElementById('redteam-report-modal');
    if (!modal) return;

    let meta = {};
    try {
      const res  = await fetch(`api/redteam/projects/${_selectedId}/report-meta`, { credentials: 'same-origin' });
      if (!res.ok) throw new Error((await res.json()).error);
      meta = (await res.json()).meta || {};
    } catch (err) { alert('Failed to load report details: ' + err.message); return; }

    REPORT_FIELDS.forEach(([key, id]) => {
      const el = document.getElementById(id);
      if (el) el.value = meta[key] || '';
    });
    const dateEl = document.getElementById('rt-report-date');
    if (dateEl) dateEl.value = meta.report_date ? String(meta.report_date).slice(0, 10) : '';

    renderOwaspRows(meta.owasp_results || []);
    renderTeamRows(meta.delivery_team || []);
    modal.hidden = false;
  }

  function renderOwaspRows(results) {
    const wrap = document.getElementById('rt-report-owasp');
    if (!wrap) return;
    wrap.innerHTML = results.map((r, i) => `
      <div style="display:flex;gap:.5rem;align-items:center;margin-bottom:.4rem">
        <span style="flex:1;font-size:.85rem">${esc(r.id)} – ${esc(r.title)}</span>
        <select class="form-select rt-owasp-result" data-i="${i}" style="width:170px">
          <option value="Pass"${r.result === 'Pass' ? ' selected' : ''}>Pass</option>
          <option value="Issues Identified"${r.result !== 'Pass' ? ' selected' : ''}>Issues Identified</option>
        </select>
      </div>`).join('');
    // Ids/titles are fixed by the framework — stash them for the save payload.
    wrap.dataset.rows = JSON.stringify(results.map(r => ({ id: r.id, title: r.title })));
  }

  function renderTeamRows(team) {
    const wrap = document.getElementById('rt-report-team');
    if (!wrap) return;
    const rows = team.length ? team : [{ name: '', role: '' }];
    wrap.innerHTML = rows.map(t => `
      <div class="rt-team-row" style="display:flex;gap:.5rem;margin-bottom:.4rem">
        <input class="form-input rt-team-name" type="text" placeholder="Name" value="${esc(t.name)}">
        <input class="form-input rt-team-role" type="text" placeholder="Role" value="${esc(t.role)}">
        <button class="btn btn-sm btn-danger rt-team-del" type="button">&times;</button>
      </div>`).join('');
    wrap.querySelectorAll('.rt-team-del').forEach(btn => {
      btn.addEventListener('click', () => btn.closest('.rt-team-row').remove());
    });
  }

  async function saveReportMeta() {
    const body = {};
    REPORT_FIELDS.forEach(([key, id]) => {
      const el = document.getElementById(id);
      body[key] = el ? el.value : '';
    });
    body.report_date = document.getElementById('rt-report-date').value || null;

    const owaspWrap = document.getElementById('rt-report-owasp');
    const base = JSON.parse(owaspWrap.dataset.rows || '[]');
    body.owasp_results = Array.from(owaspWrap.querySelectorAll('.rt-owasp-result')).map((sel, i) => ({
      id:     base[i] ? base[i].id : '',
      title:  base[i] ? base[i].title : '',
      result: sel.value,
    }));

    body.delivery_team = Array.from(document.querySelectorAll('.rt-team-row')).map(row => ({
      name: row.querySelector('.rt-team-name').value.trim(),
      role: row.querySelector('.rt-team-role').value.trim(),
    })).filter(t => t.name || t.role);

    try {
      const res = await fetch(`api/redteam/projects/${_selectedId}/report-meta`, {
        method: 'PUT', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error((await res.json()).error);
      document.getElementById('redteam-report-modal').hidden = true;
    } catch (err) { alert('Save failed: ' + err.message); }
  }

  function generateReport() {
    if (!_selectedId) { alert('Select an engagement first.'); return; }
    // A plain navigation lets the browser honour Content-Disposition and carries
    // the session cookie, same as the CSV exports elsewhere in the dashboard.
    window.location.href = `api/redteam/projects/${_selectedId}/report.docx`;
  }

  // ── Tenants (for project → tenant linking) ─────────────────────────────────

  async function loadTenants() {
    try {
      const res = await fetch('api/tenants', { credentials: 'same-origin' });
      _tenants = await res.json();
    } catch (_) {
      _tenants = [];
    }
  }

  function populateTenantSelect(selectedTenantId) {
    const sel = document.getElementById('rt-proj-tenant');
    if (!sel) return;
    sel.innerHTML = '<option value="">Not linked</option>' +
      _tenants.map(t => `<option value="${t.id}" ${t.id === selectedTenantId ? 'selected' : ''}>${esc(t.name)}</option>`).join('');
  }

  function autoMatchTenantByClient(clientName) {
    const sel = document.getElementById('rt-proj-tenant');
    if (!sel || sel.value) return; // don't override an explicit choice
    const name = clientName.trim().toLowerCase();
    if (!name) return;
    const match = _tenants.find(t => t.name.trim().toLowerCase() === name);
    if (match) sel.value = String(match.id);
  }

  // ── Project Modal ──────────────────────────────────────────────────────────

  function openProjectModal(editId) {
    const modal  = document.getElementById('redteam-project-modal');
    const form   = document.getElementById('rt-proj-form');
    if (!modal || !form) return;

    const proj = editId ? _projects.find(p => p.id === editId) : null;

    form.querySelector('#rt-proj-id').value         = editId || '';
    form.querySelector('#rt-proj-title').value      = proj ? proj.title      : '';
    form.querySelector('#rt-proj-client').value     = proj ? proj.client     : '';
    form.querySelector('#rt-proj-scope').value      = proj ? proj.scope      : '';
    form.querySelector('#rt-proj-status').value     = proj ? proj.status     : 'planned';
    form.querySelector('#rt-proj-start').value      = proj ? proj.start_date.slice(0,10) : '';
    form.querySelector('#rt-proj-end').value        = proj ? proj.end_date.slice(0,10)   : '';
    populateTenantSelect(proj ? proj.tenant_id : null);

    document.getElementById('rt-proj-modal-title').textContent = editId ? 'Edit Engagement' : 'New Engagement';
    modal.hidden = false;
  }

  async function saveProject() {
    const form = document.getElementById('rt-proj-form');
    const id   = form.querySelector('#rt-proj-id').value;
    const tenantVal = form.querySelector('#rt-proj-tenant').value;
    const body = {
      title:      form.querySelector('#rt-proj-title').value.trim(),
      client:     form.querySelector('#rt-proj-client').value.trim(),
      scope:      form.querySelector('#rt-proj-scope').value.trim(),
      status:     form.querySelector('#rt-proj-status').value,
      start_date: form.querySelector('#rt-proj-start').value,
      end_date:   form.querySelector('#rt-proj-end').value,
      tenant_id:  tenantVal ? parseInt(tenantVal, 10) : null,
    };
    try {
      const url    = id ? `api/redteam/projects/${id}` : 'api/redteam/projects';
      const method = id ? 'PUT' : 'POST';
      const res    = await fetch(url, { method, credentials: 'same-origin', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
      if (!res.ok) throw new Error((await res.json()).error);
      document.getElementById('redteam-project-modal').hidden = true;
      await loadAndRender();
    } catch (err) { alert('Save failed: ' + err.message); }
  }

  // ── Task Modal ─────────────────────────────────────────────────────────────

  async function openTaskModal(editId) {
    const modal = document.getElementById('redteam-task-modal');
    const form  = document.getElementById('rt-task-form');
    if (!modal || !form) return;

    let task = null;
    if (editId) {
      try {
        const res  = await fetch(`api/redteam/projects/${_selectedId}/tasks`, { credentials: 'same-origin' });
        const data = await res.json();
        task = (data.tasks || []).find(t => t.id === editId);
      } catch (_) {}
    }

    form.querySelector('#rt-task-id').value       = editId || '';
    form.querySelector('#rt-task-title').value    = task ? task.title    : '';
    form.querySelector('#rt-task-assignee').value = task ? task.assignee : '';
    form.querySelector('#rt-task-due').value      = task && task.due_date ? task.due_date.slice(0,10) : '';
    form.querySelector('#rt-task-status').value   = task ? task.status   : 'todo';
    form.querySelector('#rt-task-notes').value    = task ? task.notes    : '';

    document.getElementById('rt-task-modal-title').textContent = editId ? 'Edit Task' : 'New Task';
    modal.hidden = false;
  }

  async function saveTask() {
    const form = document.getElementById('rt-task-form');
    const id   = form.querySelector('#rt-task-id').value;
    const body = {
      project_id: _selectedId,
      title:      form.querySelector('#rt-task-title').value.trim(),
      assignee:   form.querySelector('#rt-task-assignee').value.trim(),
      due_date:   form.querySelector('#rt-task-due').value || null,
      status:     form.querySelector('#rt-task-status').value,
      notes:      form.querySelector('#rt-task-notes').value.trim(),
    };
    try {
      const url    = id ? `api/redteam/tasks/${id}` : 'api/redteam/tasks';
      const method = id ? 'PUT' : 'POST';
      const res    = await fetch(url, { method, credentials: 'same-origin', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
      if (!res.ok) throw new Error((await res.json()).error);
      document.getElementById('redteam-task-modal').hidden = true;
      await loadTasks(_selectedId);
    } catch (err) { alert('Save failed: ' + err.message); }
  }

  // ── Init button listeners (once) ───────────────────────────────────────────

  function initListeners() {
    if (_initialized) return;
    _initialized = true;

    const btnNewProj = document.getElementById('rt-btn-new-project');
    if (btnNewProj) {
      if (!isAdmin()) { btnNewProj.hidden = true; }
      else btnNewProj.addEventListener('click', () => openProjectModal());
    }

    const btnNewTask = document.getElementById('rt-btn-new-task');
    if (btnNewTask) {
      if (!isAdmin()) { btnNewTask.hidden = true; }
      else btnNewTask.addEventListener('click', () => {
        if (!_selectedId) { alert('Select an engagement first.'); return; }
        openTaskModal();
      });
    }

    // Modal close buttons
    document.getElementById('rt-proj-modal-close')?.addEventListener('click', () => {
      document.getElementById('redteam-project-modal').hidden = true;
    });
    document.getElementById('rt-proj-modal-save')?.addEventListener('click', saveProject);

    document.getElementById('rt-task-modal-close')?.addEventListener('click', () => {
      document.getElementById('redteam-task-modal').hidden = true;
    });
    document.getElementById('rt-task-modal-save')?.addEventListener('click', saveTask);

    const btnNewFinding = document.getElementById('rt-btn-new-finding');
    if (btnNewFinding) {
      if (!isAdmin()) { btnNewFinding.hidden = true; }
      else btnNewFinding.addEventListener('click', () => {
        if (!_selectedId) { alert('Select an engagement first.'); return; }
        openFindingModal();
      });
    }

    document.getElementById('rt-finding-modal-close')?.addEventListener('click', () => {
      document.getElementById('redteam-finding-modal').hidden = true;
    });
    document.getElementById('rt-finding-modal-close-2')?.addEventListener('click', () => {
      document.getElementById('redteam-finding-modal').hidden = true;
    });
    document.getElementById('rt-finding-modal-save')?.addEventListener('click', saveFinding);
    document.getElementById('rt-finding-modal-delete')?.addEventListener('click', () => {
      const id = parseInt(document.getElementById('rt-finding-id').value, 10);
      if (id) deleteFinding(id);
      document.getElementById('redteam-finding-modal').hidden = true;
    });

    document.getElementById('rt-finding-evidence-file')?.addEventListener('change', (e) => {
      if (e.target.files && e.target.files[0]) uploadEvidence(e.target.files[0]);
    });

    // Report controls — generating is a read action, editing the narrative is not.
    document.getElementById('rt-btn-generate-report')?.addEventListener('click', generateReport);

    const btnReportMeta = document.getElementById('rt-btn-report-details');
    if (btnReportMeta) {
      if (!isAdmin()) btnReportMeta.hidden = true;
      else btnReportMeta.addEventListener('click', openReportModal);
    }

    document.getElementById('rt-report-modal-close')?.addEventListener('click', () => {
      document.getElementById('redteam-report-modal').hidden = true;
    });
    document.getElementById('rt-report-modal-close-2')?.addEventListener('click', () => {
      document.getElementById('redteam-report-modal').hidden = true;
    });
    document.getElementById('rt-report-modal-save')?.addEventListener('click', saveReportMeta);
    document.getElementById('rt-report-team-add')?.addEventListener('click', () => {
      const wrap = document.getElementById('rt-report-team');
      const rows = Array.from(wrap.querySelectorAll('.rt-team-row')).map(r => ({
        name: r.querySelector('.rt-team-name').value,
        role: r.querySelector('.rt-team-role').value,
      }));
      rows.push({ name: '', role: '' });
      renderTeamRows(rows);
    });

    document.getElementById('rt-proj-client')?.addEventListener('blur', (e) => {
      autoMatchTenantByClient(e.target.value);
    });
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  async function loadAndRender() {
    initListeners();

    try {
      const [projRes] = await Promise.all([
        fetch('api/redteam/projects', { credentials: 'same-origin' }),
        loadTenants(),
      ]);
      const data = await projRes.json();
      _projects  = data.projects || [];
    } catch (_) {
      _projects = [];
    }

    await renderStats();
    renderCalendar();
    renderProjects();
    updateReportControls();

    if (_selectedId) {
      await loadTasks(_selectedId);
      await loadFindings(_selectedId);
    } else {
      const tbody   = document.getElementById('redteam-tasks-tbody');
      const heading = document.getElementById('redteam-tasks-heading');
      if (heading) heading.textContent = 'Tasks';
      if (tbody)   tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Select an engagement to view tasks.</td></tr>';

      const fTbody   = document.getElementById('redteam-findings-tbody');
      const fHeading = document.getElementById('redteam-findings-heading');
      if (fHeading) fHeading.textContent = 'Findings';
      if (fTbody)   fTbody.innerHTML = '<tr><td colspan="8" class="empty-state">Select an engagement to view findings.</td></tr>';
    }
  }

  return { loadAndRender };
})();

window.RedteamTab = RedteamTab;
