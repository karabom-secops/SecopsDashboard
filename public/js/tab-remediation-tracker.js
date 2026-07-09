/* tab-remediation-tracker.js — Unified remediation view across Vulnerabilities, Pentest Findings, and Risk Register */

const RemediationTrackerTab = (() => {
  'use strict';

  let _items = [];
  let _vulnMonthKey = null;
  let _sourceFilter = 'all';
  let _statusFilter = 'all';
  let _searchTerm = '';
  let _view = 'table';

  const DEFAULT_DURATION_DAYS = 14;

  const STATUS_OPTIONS = {
    vuln:    [['open', 'Open'], ['in-progress', 'In Progress'], ['fixed', 'Fixed'], ['accepted', 'Accepted']],
    risk:    [['identified', 'Identified'], ['assessing', 'Assessing'], ['mitigating', 'Mitigating'], ['monitoring', 'Monitoring'], ['closed', 'Closed']],
    pentest: [['open', 'Open'], ['in-progress', 'In Progress'], ['fixed', 'Fixed'], ['accepted', 'Accepted'], ['risk-accepted', 'Risk Accepted']],
  };

  const CLOSED_STATUSES = new Set(['fixed', 'accepted', 'closed', 'risk-accepted']);

  const SOURCE_LABELS = { vuln: 'Vulnerability', risk: 'Risk', pentest: 'Pentest' };

  function esc(s) {
    return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function fmt(dateStr) {
    if (!dateStr) return '—';
    return String(dateStr).slice(0, 10);
  }

  function toDateOnly(v) {
    if (!v) return null;
    return String(v).slice(0, 10);
  }

  function addDays(dateStr, days) {
    const d = new Date(dateStr + 'T00:00:00Z');
    d.setUTCDate(d.getUTCDate() + days);
    return d.toISOString().slice(0, 10);
  }

  function isOverdue(item) {
    if (!item.dueDate || CLOSED_STATUSES.has(item.status)) return false;
    return item.dueDate < new Date().toISOString().slice(0, 10);
  }

  function canWrite() {
    const r = window.currentUser && window.currentUser.role;
    return r === 'sales' || r === 'admin' || r === 'superadmin';
  }

  function tenantParam(sep) {
    const isSA = window.currentUser && window.currentUser.role === 'superadmin';
    if (!isSA || !window.globalTenantId) return '';
    return sep + 'tenantId=' + encodeURIComponent(window.globalTenantId);
  }

  function statusPillClass(source, status) {
    if (source === 'risk') {
      if (status === 'closed') return 'fixed';
      if (status === 'monitoring') return 'accepted';
      return 'in-progress';
    }
    if (status === 'risk-accepted') return 'accepted';
    return status; // open | in-progress | fixed | accepted
  }

  // ── Normalization ──────────────────────────────────────────────────────────

  function normalize(data) {
    const today = new Date().toISOString().slice(0, 10);

    const vulns = (data.vulns || []).map(v => {
      const start = toDateOnly(v.firstSeenAt) || today;
      return {
        source: 'vuln',
        id: v.idx,
        title: v.name || v.cve || 'Unnamed finding',
        severity: (v.risk || '').toLowerCase() || 'informational',
        owner: '',
        dueDate: null,
        status: v.status || 'open',
        startDate: start,
        endDate: addDays(start, DEFAULT_DURATION_DAYS),
        raw: v,
      };
    });

    const risks = (data.risks || []).map(r => {
      const start = toDateOnly(r.created_at) || toDateOnly(r.start_date) || today;
      const due = toDateOnly(r.due_date);
      return {
        source: 'risk',
        id: r.id,
        title: r.title,
        severity: r.risk_score >= 15 ? 'high' : r.risk_score >= 8 ? 'medium' : 'low',
        owner: r.owner || '',
        dueDate: due,
        status: r.stage,
        startDate: start,
        endDate: due || addDays(start, DEFAULT_DURATION_DAYS),
        raw: r,
      };
    });

    const pentest = (data.pentestFindings || []).map(p => {
      const start = toDateOnly(p.created_at) || today;
      const due = toDateOnly(p.due_date);
      return {
        source: 'pentest',
        id: p.id,
        title: p.title,
        severity: p.severity,
        owner: p.owner || '',
        dueDate: due,
        status: p.status,
        startDate: start,
        endDate: due || addDays(start, DEFAULT_DURATION_DAYS),
        raw: p,
      };
    });

    return [...vulns, ...pentest, ...risks];
  }

  // ── Stats ──────────────────────────────────────────────────────────────────

  function renderStats() {
    const el = document.getElementById('rt-stats');
    if (!el) return;

    const open = _items.filter(i => !CLOSED_STATUSES.has(i.status)).length;
    const overdue = _items.filter(isOverdue).length;
    const closed = _items.filter(i => CLOSED_STATUSES.has(i.status)).length;
    const bySource = { vuln: 0, risk: 0, pentest: 0 };
    _items.forEach(i => { if (!CLOSED_STATUSES.has(i.status)) bySource[i.source]++; });

    el.innerHTML = `
      <div class="stat-card accent-blue">
        <div class="stat-label">Open Items</div>
        <div class="stat-value">${open}</div>
      </div>
      <div class="stat-card accent-red">
        <div class="stat-label">Overdue</div>
        <div class="stat-value">${overdue}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Open Vulnerabilities</div>
        <div class="stat-value">${bySource.vuln}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Open Pentest Findings</div>
        <div class="stat-value">${bySource.pentest}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Open Risks</div>
        <div class="stat-value">${bySource.risk}</div>
      </div>
      <div class="stat-card accent-green">
        <div class="stat-label">Closed</div>
        <div class="stat-value">${closed}</div>
      </div>`;
  }

  // ── Filters ────────────────────────────────────────────────────────────────

  function renderFilters() {
    const el = document.getElementById('rt-filters');
    if (!el) return;

    const sourceChips = [
      ['all', 'All Sources'],
      ['vuln', 'Vulnerabilities'],
      ['pentest', 'Pentest Findings'],
      ['risk', 'Risk Register'],
    ].map(([key, label]) => `
      <button class="chip ${_sourceFilter === key ? 'active' : ''}" data-source="${key}">${label}</button>
    `).join('');

    el.innerHTML = `
      <div style="display:flex; flex-wrap:wrap; gap:0.5rem; align-items:center;">
        ${sourceChips}
        <input type="text" id="rt-search" class="form-input" placeholder="Search title..." value="${esc(_searchTerm)}" style="max-width:220px; margin-left:0.5rem;">
      </div>`;

    el.querySelectorAll('[data-source]').forEach(btn => {
      btn.addEventListener('click', () => {
        _sourceFilter = btn.dataset.source;
        renderFilters();
        renderActiveView();
      });
    });

    const searchInput = document.getElementById('rt-search');
    if (searchInput) {
      searchInput.addEventListener('input', () => {
        _searchTerm = searchInput.value;
        renderActiveView();
      });
    }
  }

  function filteredItems() {
    let rows = _items;
    if (_sourceFilter !== 'all') rows = rows.filter(i => i.source === _sourceFilter);
    if (_searchTerm.trim()) {
      const q = _searchTerm.trim().toLowerCase();
      rows = rows.filter(i => i.title.toLowerCase().includes(q));
    }
    return rows;
  }

  function renderActiveView() {
    if (_view === 'gantt') renderGantt();
    else renderTable();
  }

  // ── Table ──────────────────────────────────────────────────────────────────

  function renderTable() {
    const tbody = document.getElementById('rt-table-body');
    if (!tbody) return;

    const rows = filteredItems();

    if (rows.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No remediation items match this view.</td></tr>';
      return;
    }

    const writable = canWrite();

    tbody.innerHTML = rows.map((item, i) => {
      const options = STATUS_OPTIONS[item.source]
        .map(([v, label]) => `<option value="${v}" ${v === item.status ? 'selected' : ''}>${label}</option>`)
        .join('');
      return `
        <tr>
          <td><span class="badge badge-source-${item.source}">${SOURCE_LABELS[item.source]}</span></td>
          <td>${esc(item.title)}${isOverdue(item) ? ' <span class="badge badge-red">Overdue</span>' : ''}</td>
          <td>${esc(item.severity)}</td>
          <td>${esc(item.owner) || '—'}</td>
          <td>${fmt(item.dueDate)}</td>
          <td>
            <select class="status-pill ${statusPillClass(item.source, item.status)} rt-status-select" data-index="${i}" ${writable ? '' : 'disabled'}>
              ${options}
            </select>
          </td>
        </tr>`;
    }).join('');

    tbody.querySelectorAll('.rt-status-select').forEach(sel => {
      sel.addEventListener('change', () => updateStatus(rows[parseInt(sel.dataset.index, 10)], sel));
    });
  }

  async function updateStatus(item, selectEl) {
    const newStatus = selectEl.value;
    const prevStatus = item.status;
    if (newStatus === prevStatus) return;

    try {
      if (item.source === 'vuln') {
        if (!_vulnMonthKey) throw new Error('no scan loaded');
        const body = { status: newStatus };
        const isSA = window.currentUser && window.currentUser.role === 'superadmin';
        if (isSA && window.globalTenantId) body.tenantId = window.globalTenantId;
        const res = await fetch(`api/vulns/${encodeURIComponent(_vulnMonthKey)}/finding/${item.id}`, {
          method: 'PATCH', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
          body: JSON.stringify(body),
        });
        if (!res.ok) throw new Error('update failed');
      } else if (item.source === 'risk') {
        const body = { stage: newStatus };
        const isSA = window.currentUser && window.currentUser.role === 'superadmin';
        if (isSA && window.globalTenantId) body.tenantId = window.globalTenantId;
        const res = await fetch(`api/risks/${item.id}/stage`, {
          method: 'PATCH', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
          body: JSON.stringify(body),
        });
        if (!res.ok) throw new Error('update failed');
      } else if (item.source === 'pentest') {
        const body = { status: newStatus };
        const isSA = window.currentUser && window.currentUser.role === 'superadmin';
        if (isSA && window.globalTenantId) body.tenantId = window.globalTenantId;
        const res = await fetch(`api/pentest-findings/${item.id}/status`, {
          method: 'PATCH', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
          body: JSON.stringify(body),
        });
        if (!res.ok) throw new Error('update failed');
      }
      item.status = newStatus;
      renderStats();
      renderActiveView();
    } catch (_) {
      selectEl.value = prevStatus;
      alert('Failed to update status.');
    }
  }

  // ── Gantt view ─────────────────────────────────────────────────────────────

  function renderGantt() {
    const container = document.getElementById('rt-gantt');
    if (!container) return;

    const rows = filteredItems();
    if (rows.length === 0) {
      container.innerHTML = '<div class="rt-gantt-empty">No remediation items match this view.</div>';
      return;
    }

    const sorted = [...rows].sort((a, b) => a.startDate.localeCompare(b.startDate));
    const rawMin = sorted.reduce((min, i) => i.startDate < min ? i.startDate : min, sorted[0].startDate);
    const rawMax = sorted.reduce((max, i) => i.endDate > max ? i.endDate : max, sorted[0].endDate);

    // Snap the visible range to Monday-start week boundaries so the header aligns with the gridlines.
    const minDate = startOfWeek(rawMin);
    const maxDate = addDays(startOfWeek(rawMax), 6);

    const totalDays = Math.max(1, dayDiff(minDate, maxDate));
    const today = new Date().toISOString().slice(0, 10);
    const todayPct = clampPct(dayDiff(minDate, today) / totalDays * 100);

    const weekTicks = buildWeekTicks(minDate, maxDate, totalDays);
    const trackWidth = Math.max(600, weekTicks.length * 110);
    container.style.setProperty('--rt-gantt-track-width', trackWidth + 'px');

    const header = `
      <div class="rt-gantt-header">
        <div></div>
        <div class="rt-gantt-header-weeks">
          ${weekTicks.map(t => `<span class="rt-gantt-week-tick" style="left:${t.pct}%">${t.label}</span>`).join('')}
        </div>
      </div>`;

    const gridlines = weekTicks.map(t => `<div class="rt-gantt-week-line" style="left:${t.pct}%"></div>`).join('');

    const rowsHtml = sorted.map(item => {
      const leftPct = clampPct(dayDiff(minDate, item.startDate) / totalDays * 100);
      const widthPct = Math.max(1, clampPct(dayDiff(item.startDate, item.endDate) / totalDays * 100));
      const title = `${item.title} — ${fmt(item.startDate)} to ${fmt(item.endDate)} (${item.status})`;
      return `
        <div class="rt-gantt-row">
          <div class="rt-gantt-row-label" title="${esc(item.title)}">${esc(item.title)}</div>
          <div class="rt-gantt-track">
            ${gridlines}
            ${todayPct >= 0 && todayPct <= 100 ? `<div class="rt-gantt-today-line" style="left:${todayPct}%"></div>` : ''}
            <div class="rt-gantt-bar source-${item.source} ${isOverdue(item) ? 'overdue' : ''}"
                 style="left:${leftPct}%; width:${widthPct}%;" title="${esc(title)}">
              ${esc(item.title)}
            </div>
          </div>
        </div>`;
    }).join('');

    container.innerHTML = header + rowsHtml;
  }

  function dayDiff(fromStr, toStr) {
    const from = new Date(fromStr + 'T00:00:00Z');
    const to = new Date(toStr + 'T00:00:00Z');
    return (to - from) / 86400000;
  }

  function clampPct(v) {
    return Math.min(100, Math.max(0, v));
  }

  // Monday-start week boundary for a given date string.
  function startOfWeek(dateStr) {
    const d = new Date(dateStr + 'T00:00:00Z');
    const dow = d.getUTCDay(); // 0=Sun..6=Sat
    const offset = dow === 0 ? 6 : dow - 1; // days since Monday
    d.setUTCDate(d.getUTCDate() - offset);
    return d.toISOString().slice(0, 10);
  }

  function buildWeekTicks(minDate, maxDate, totalDays) {
    const ticks = [];
    let cursor = minDate;
    while (cursor <= maxDate) {
      const pct = clampPct(dayDiff(minDate, cursor) / totalDays * 100);
      const d = new Date(cursor + 'T00:00:00Z');
      ticks.push({ pct, label: `Wk of ${d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}` });
      cursor = addDays(cursor, 7);
    }
    return ticks;
  }

  function wireViewToggle() {
    document.getElementById('rt-view-table-btn').addEventListener('click', () => switchView('table'));
    document.getElementById('rt-view-gantt-btn').addEventListener('click', () => switchView('gantt'));
  }

  function switchView(view) {
    _view = view;
    document.getElementById('rt-view-table-btn').classList.toggle('active', view === 'table');
    document.getElementById('rt-view-gantt-btn').classList.toggle('active', view === 'gantt');
    document.getElementById('rt-table-view').hidden = view !== 'table';
    document.getElementById('rt-gantt-view').hidden = view !== 'gantt';
    renderActiveView();
  }

  // ── New Pentest Finding modal ────────────────────────────────────────────

  function openNewModal() {
    document.getElementById('rt-modal-title').textContent = 'New Pentest Finding';
    document.getElementById('rt-id').value = '';
    document.getElementById('rt-title').value = '';
    document.getElementById('rt-severity').value = 'medium';
    document.getElementById('rt-description').value = '';
    document.getElementById('rt-recommendation').value = '';
    document.getElementById('rt-owner').value = '';
    document.getElementById('rt-due').value = '';
    document.getElementById('rt-status').value = 'open';
    document.getElementById('rt-notes').value = '';
    document.getElementById('rt-modal-delete').hidden = true;

    const modalEl = document.getElementById('rt-modal');
    if (modalEl.parentElement !== document.body) document.body.appendChild(modalEl);
    modalEl.hidden = false;
    document.body.classList.add('modal-open');
  }

  function closeModal() {
    document.getElementById('rt-modal').hidden = true;
    document.body.classList.remove('modal-open');
  }

  async function saveFinding() {
    const body = {
      title: document.getElementById('rt-title').value.trim(),
      severity: document.getElementById('rt-severity').value,
      description: document.getElementById('rt-description').value.trim(),
      recommendation: document.getElementById('rt-recommendation').value.trim(),
      owner: document.getElementById('rt-owner').value.trim(),
      due_date: document.getElementById('rt-due').value || null,
      status: document.getElementById('rt-status').value,
      notes: document.getElementById('rt-notes').value.trim(),
    };
    if (!body.title) { alert('Title is required.'); return; }

    const isSA = window.currentUser && window.currentUser.role === 'superadmin';
    if (isSA && window.globalTenantId) body.tenantId = window.globalTenantId;

    await fetch('api/pentest-findings', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
      body: JSON.stringify(body),
    });

    closeModal();
    await load();
    renderStats();
    renderTable();
  }

  // ── CSV export ─────────────────────────────────────────────────────────────

  function exportCsv() {
    const header = ['Source', 'Title', 'Severity', 'Owner', 'Due Date', 'Status'];
    const rows = _items.map(i => [SOURCE_LABELS[i.source], i.title, i.severity, i.owner, fmt(i.dueDate), i.status]);
    const csv = [header, ...rows]
      .map(r => r.map(v => `"${String(v ?? '').replace(/"/g, '""')}"`).join(','))
      .join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'remediation-tracker.csv';
    a.click();
    URL.revokeObjectURL(a.href);
  }

  // ── Data loading ───────────────────────────────────────────────────────────

  async function load() {
    const res = await fetch('api/remediation-tracker' + tenantParam('?'), { credentials: 'same-origin' });
    const data = await res.json();
    _vulnMonthKey = data.vulnMonthKey || null;
    _items = normalize(data);
  }

  // ── Wiring ─────────────────────────────────────────────────────────────────

  function wireOnce() {
    if (RemediationTrackerTab._wired) return;
    RemediationTrackerTab._wired = true;

    const newBtn = document.getElementById('rt-new-btn');
    newBtn.addEventListener('click', openNewModal);
    newBtn.hidden = !canWrite();

    document.getElementById('rt-export-btn').addEventListener('click', exportCsv);
    document.getElementById('rt-modal-close').addEventListener('click', closeModal);
    document.getElementById('rt-modal-close-2').addEventListener('click', closeModal);
    document.getElementById('rt-modal-save').addEventListener('click', saveFinding);
    wireViewToggle();
  }

  // ── Main entry ─────────────────────────────────────────────────────────────

  async function loadAndRender() {
    wireOnce();
    await load();
    renderStats();
    renderFilters();
    renderActiveView();
  }

  return { loadAndRender };
})();

window.RemediationTrackerTab = RemediationTrackerTab;
