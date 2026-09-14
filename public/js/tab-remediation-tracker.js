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

  // Vulnerability remediation SLA, in days from first detection.
  //
  // Served from lib/vuln-parser.js via GET /api/auth/me rather than restated
  // here: that module computes the due_date stored on each finding, and the
  // four private copies this file used to be one of had drifted apart — the
  // board report was allowing a High thirty days while this tab allowed
  // fourteen. Read at call time; a module-level capture would freeze the
  // fallback before the session response arrives.
  //
  // Only a fallback for scans uploaded before due dates were persisted; a
  // stored due_date always wins.
  function vulnSlaDays(severity) {
    return window.vulnSlaDays ? window.vulnSlaDays(severity) : null;
  }

  const STATUS_OPTIONS = {
    vuln:     [['open', 'Open'], ['in-progress', 'In Progress'], ['fixed', 'Fixed'], ['accepted', 'Accepted'], ['false-positive', 'False Positive']],
    risk:     [['identified', 'Identified'], ['assessing', 'Assessing'], ['mitigating', 'Mitigating'], ['monitoring', 'Monitoring'], ['closed', 'Closed']],
    pentest:  [['open', 'Open'], ['in-progress', 'In Progress'], ['fixed', 'Fixed'], ['accepted', 'Accepted'], ['risk-accepted', 'Risk Accepted']],
    incident: [['open', 'Open'], ['contained', 'Contained'], ['remediating', 'Remediating'], ['resolved', 'Resolved'], ['closed', 'Closed']],
  };

  const CLOSED_STATUSES = new Set(['fixed', 'accepted', 'closed', 'risk-accepted', 'resolved']);

  const SOURCE_LABELS = { vuln: 'Vulnerability', risk: 'Risk', pentest: 'Pentest', incident: 'Incident' };

  // Shared ranking across all four sources. Vulns/pentest/incidents use the
  // critical…informational vocabulary; risks are bucketed into high/medium/low
  // from their score in normalize(). Anything unrecognised sorts last.
  const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, informational: 4, info: 4 };

  function severityRank(item) {
    const r = SEVERITY_RANK[(item.severity || '').toLowerCase()];
    return r === undefined ? 5 : r;
  }

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
    return window.canWrite('remediation-tracker');
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
    if (source === 'incident') {
      if (status === 'resolved' || status === 'closed') return 'fixed';
      if (status === 'open') return 'open';
      return 'in-progress'; // contained | remediating
    }
    if (status === 'risk-accepted') return 'accepted';
    return status; // open | in-progress | fixed | accepted
  }

  // ── Normalization ──────────────────────────────────────────────────────────

  function normalize(data) {
    const today = new Date().toISOString().slice(0, 10);

    const vulns = (data.vulns || []).map(v => {
      const start = toDateOnly(v.firstSeenAt) || today;
      const severity = (v.risk || '').toLowerCase() || 'informational';
      // Prefer the stored due date; fall back to the severity SLA off first detection.
      const sla = vulnSlaDays(severity);
      const due = toDateOnly(v.dueDate) || (sla ? addDays(start, sla) : null);
      return {
        source: 'vuln',
        id: v.idx,
        title: v.name || v.cve || 'Unnamed finding',
        severity,
        owner: '',
        dueDate: due,
        status: v.status || 'open',
        startDate: start,
        endDate: due || addDays(start, DEFAULT_DURATION_DAYS),
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

    const incidents = (data.incidents || []).map(inc => {
      const start = toDateOnly(inc.opened_at) || today;
      const closed = toDateOnly(inc.closed_at);
      return {
        source: 'incident',
        id: inc.id,
        title: inc.title,
        severity: inc.severity,
        owner: inc.assigned_to || '',
        dueDate: null,
        status: inc.status,
        startDate: start,
        endDate: closed || addDays(start, DEFAULT_DURATION_DAYS),
        raw: inc,
      };
    });

    return [...vulns, ...pentest, ...risks, ...incidents];
  }

  // ── Stats ──────────────────────────────────────────────────────────────────

  function renderStats() {
    const el = document.getElementById('rt-stats');
    if (!el) return;

    const open = _items.filter(i => !CLOSED_STATUSES.has(i.status)).length;
    const overdue = _items.filter(isOverdue).length;
    const closed = _items.filter(i => CLOSED_STATUSES.has(i.status)).length;
    const bySource = { vuln: 0, risk: 0, pentest: 0, incident: 0 };
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
      <div class="stat-card">
        <div class="stat-label">Open Incidents</div>
        <div class="stat-value">${bySource.incident}</div>
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
      ['incident', 'Incidents'],
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
    // Most severe first, then soonest deadline (undated last), then title.
    return rows.slice().sort((a, b) =>
      severityRank(a) - severityRank(b) ||
      (a.dueDate || '9999-12-31').localeCompare(b.dueDate || '9999-12-31') ||
      a.title.localeCompare(b.title)
    );
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
      } else if (item.source === 'incident') {
        const body = { status: newStatus };
        const isSA = window.currentUser && window.currentUser.role === 'superadmin';
        if (isSA && window.globalTenantId) body.tenantId = window.globalTenantId;
        const res = await fetch(`api/ir/incidents/${item.id}/status`, {
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
    const rows = _items.slice()
      .sort((a, b) => severityRank(a) - severityRank(b) ||
                      (a.dueDate || '9999-12-31').localeCompare(b.dueDate || '9999-12-31'))
      .map(i => [SOURCE_LABELS[i.source], i.title, i.severity, i.owner, fmt(i.dueDate), i.status]);
    const csv = [header, ...rows]
      .map(r => r.map(v => `"${String(v ?? '').replace(/"/g, '""')}"`).join(','))
      .join('\n');
    window.ReportShell.downloadFile(
      'remediation-tracker.csv', csv, 'text/csv;charset=utf-8');
  }

  // ── Client risk acceptances ────────────────────────────────────────────────
  //
  // Requests clients raised from the portal. Nothing about the finding or the
  // Secure Score changes until one is approved here — approval sets the finding
  // accepted, which takes it out of the vulnerability counts. That is why this
  // is behind write access and the client cannot do it themselves.

  let _acceptances = [];
  const _reviewDrafts = {};

  async function loadAcceptances() {
    try {
      const res = await fetch('api/risk-acceptances?status=pending' + tenantParam('&'),
        { credentials: 'same-origin' });
      if (!res.ok) { _acceptances = []; return; }
      const data = await res.json();
      _acceptances = (data && data.acceptances) || [];
    } catch (_) {
      // A missing table or a failed request must not take the tracker with it.
      _acceptances = [];
    }
  }

  function renderAcceptances() {
    const el = document.getElementById('rt-acceptances');
    if (!el) return;
    if (!_acceptances.length) { el.innerHTML = ''; return; }

    const writable = canWrite();
    el.innerHTML = `
      <div class="rt-accept-panel">
        <div class="rt-accept-head">
          <h3 class="rt-accept-title">Client risk acceptances awaiting review
            <span class="badge badge-amber">${_acceptances.length}</span></h3>
          <p class="rt-accept-lead">Approving marks the finding accepted and removes it from the
            Secure Score until the review date. Your note is shown to the client.</p>
        </div>
        ${_acceptances.map(a => `
          <div class="rt-accept-item" data-id="${Number(a.id)}">
            <div class="rt-accept-main">
              <div class="rt-accept-finding">
                <span class="badge badge-source-${a.source === 'pentest' ? 'pentest' : 'vuln'}">${a.source === 'pentest' ? 'Pentest' : 'Vulnerability'}</span>
                <strong>${esc(a.finding_title)}</strong>
                ${a.finding_severity ? `<span class="rt-accept-sev">${esc(a.finding_severity)}</span>` : ''}
                ${a.host ? `<span class="rt-accept-host">${esc(a.host)}${a.port ? ':' + esc(a.port) : ''}</span>` : ''}
              </div>
              <div class="rt-accept-meta">
                Accepted by <strong>${esc(a.approver_name)}</strong> (${esc(a.approver_role)})
                until <strong>${esc(a.expires_on)}</strong>
                &middot; requested ${fmt(a.requested_at)}${a.requested_by_name ? ' by ' + esc(a.requested_by_name) : ''}
              </div>
              <blockquote class="rt-accept-why">${esc(a.justification)}</blockquote>
            </div>
            ${writable ? `
              <div class="rt-accept-actions">
                <label class="form-label" for="rt-accept-note-${Number(a.id)}">Note to the client</label>
                <textarea id="rt-accept-note-${Number(a.id)}" class="form-input rt-accept-note" rows="2"
                  maxlength="1000" placeholder="Optional to approve, required to reject">${esc(_reviewDrafts[a.id] || '')}</textarea>
                <div class="rt-accept-buttons">
                  <button type="button" class="btn btn-primary btn-sm" data-accept-action="approve">Approve</button>
                  <button type="button" class="btn btn-secondary btn-sm" data-accept-action="reject">Reject</button>
                </div>
                <div class="rt-accept-error" role="alert" hidden></div>
              </div>` : ''}
          </div>`).join('')}
      </div>`;

    el.querySelectorAll('.rt-accept-note').forEach(t => {
      t.addEventListener('input', () => {
        const id = t.closest('.rt-accept-item').dataset.id;
        _reviewDrafts[id] = t.value;
      });
    });
    el.querySelectorAll('[data-accept-action]').forEach(btn => {
      btn.addEventListener('click', () => reviewAcceptance(btn));
    });
  }

  async function reviewAcceptance(btn) {
    const item = btn.closest('.rt-accept-item');
    const id = item.dataset.id;
    const action = btn.dataset.acceptAction;
    const note = (item.querySelector('.rt-accept-note') || {}).value || '';
    const errEl = item.querySelector('.rt-accept-error');

    if (action === 'reject' && !note.trim()) {
      errEl.textContent = 'Give the client a reason before rejecting.';
      errEl.hidden = false;
      return;
    }

    item.querySelectorAll('button').forEach(b => { b.disabled = true; });
    errEl.hidden = true;

    const body = { note };
    const isSA = window.currentUser && window.currentUser.role === 'superadmin';
    if (isSA && window.globalTenantId) body.tenantId = window.globalTenantId;

    try {
      const res = await fetch(`api/risk-acceptances/${encodeURIComponent(id)}/${action}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || 'Could not ' + action + ' this acceptance.');

      delete _reviewDrafts[id];
      // Approval changed a finding's status, so the whole tracker is stale.
      await Promise.all([load(), loadAcceptances()]);
      renderAcceptances();
      renderStats();
      renderActiveView();
    } catch (err) {
      errEl.textContent = err.message;
      errEl.hidden = false;
      item.querySelectorAll('button').forEach(b => { b.disabled = false; });
    }
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
    await Promise.all([load(), loadAcceptances()]);
    renderAcceptances();
    renderStats();
    renderFilters();
    renderActiveView();
  }

  return { loadAndRender };
})();

window.RemediationTrackerTab = RemediationTrackerTab;
