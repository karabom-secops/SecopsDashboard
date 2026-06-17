/* tab-redteam.js — Red Team Operations tab */

const RedteamTab = (() => {
  'use strict';

  let _projects      = [];
  let _selectedId    = null;
  let _calDate       = new Date();
  let _calView       = 'month';
  let _initialized   = false;

  // ── Helpers ────────────────────────────────────────────────────────────────

  function tenantParam(sep) {
    if (window.currentUser && window.currentUser.role === 'superadmin' && window._selectedTenantId) {
      return `${sep}tenantId=${window._selectedTenantId}`;
    }
    return '';
  }

  function isAdmin() {
    const r = window.currentUser && window.currentUser.role;
    return r === 'admin' || r === 'superadmin';
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
      const res  = await fetch(`api/redteam/stats${tenantParam('?')}`, { credentials: 'same-origin' });
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
      tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No engagements yet.</td></tr>';
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
      const res = await fetch(`api/redteam/projects/${id}${tenantParam('?')}`, { method: 'DELETE', credentials: 'same-origin' });
      if (!res.ok) throw new Error((await res.json()).error);
      if (_selectedId === id) _selectedId = null;
      await loadAndRender();
    } catch (err) { alert('Delete failed: ' + err.message); }
  }

  // ── Tasks table ────────────────────────────────────────────────────────────

  async function selectProject(id) {
    _selectedId = id;
    renderProjects();
    await loadTasks(id);
  }

  async function loadTasks(projectId) {
    const tbody  = document.getElementById('redteam-tasks-tbody');
    const heading = document.getElementById('redteam-tasks-heading');
    if (!tbody) return;

    const proj = _projects.find(p => p.id === projectId);
    if (heading) heading.textContent = proj ? `Tasks — ${proj.title}` : 'Tasks';

    try {
      const res  = await fetch(`api/redteam/projects/${projectId}/tasks${tenantParam('?')}`, { credentials: 'same-origin' });
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
      const res = await fetch(`api/redteam/tasks/${id}${tenantParam('?')}`, { method: 'DELETE', credentials: 'same-origin' });
      if (!res.ok) throw new Error((await res.json()).error);
      await loadTasks(_selectedId);
    } catch (err) { alert('Delete failed: ' + err.message); }
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

    document.getElementById('rt-proj-modal-title').textContent = editId ? 'Edit Engagement' : 'New Engagement';
    modal.hidden = false;
  }

  async function saveProject() {
    const form = document.getElementById('rt-proj-form');
    const id   = form.querySelector('#rt-proj-id').value;
    const body = {
      title:      form.querySelector('#rt-proj-title').value.trim(),
      client:     form.querySelector('#rt-proj-client').value.trim(),
      scope:      form.querySelector('#rt-proj-scope').value.trim(),
      status:     form.querySelector('#rt-proj-status').value,
      start_date: form.querySelector('#rt-proj-start').value,
      end_date:   form.querySelector('#rt-proj-end').value,
    };
    if (window.currentUser && window.currentUser.role === 'superadmin' && window._selectedTenantId) {
      body.tenantId = window._selectedTenantId;
    }
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
        const res  = await fetch(`api/redteam/projects/${_selectedId}/tasks${tenantParam('?')}`);
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
    if (window.currentUser && window.currentUser.role === 'superadmin' && window._selectedTenantId) {
      body.tenantId = window._selectedTenantId;
    }
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
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  async function loadAndRender() {
    initListeners();

    try {
      const res  = await fetch(`api/redteam/projects${tenantParam('?')}`, { credentials: 'same-origin' });
      const data = await res.json();
      _projects  = data.projects || [];
    } catch (_) {
      _projects = [];
    }

    await renderStats();
    renderCalendar();
    renderProjects();

    if (_selectedId) {
      await loadTasks(_selectedId);
    } else {
      const tbody   = document.getElementById('redteam-tasks-tbody');
      const heading = document.getElementById('redteam-tasks-heading');
      if (heading) heading.textContent = 'Tasks';
      if (tbody)   tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Select an engagement to view tasks.</td></tr>';
    }
  }

  return { loadAndRender };
})();

window.RedteamTab = RedteamTab;
