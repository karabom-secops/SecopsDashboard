/* tab-risk-register.js — Per-tenant Risk Register kanban board */

const RiskRegisterTab = (() => {
  'use strict';

  let _risks = [];
  let _dragId = null;

  const STAGES = ['identified', 'assessing', 'mitigating', 'monitoring', 'closed'];

  function esc(s) {
    return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function fmt(dateStr) {
    if (!dateStr) return '—';
    return String(dateStr).slice(0, 10);
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

  function scoreBadge(score) {
    if (score >= 15) return 'badge-red';
    if (score >= 8)  return 'badge-amber';
    return 'badge-green';
  }

  // ── Stats ──────────────────────────────────────────────────────────────────

  async function renderStats() {
    const el = document.getElementById('rr-stats');
    if (!el) return;
    try {
      const res  = await fetch('api/risks/stats' + tenantParam('?'), { credentials: 'same-origin' });
      const data = await res.json();
      el.innerHTML = `
        <div class="stat-card accent-blue">
          <div class="stat-label">Open Risks</div>
          <div class="stat-value">${data.open}</div>
        </div>
        <div class="stat-card accent-red">
          <div class="stat-label">High Risk (Score ≥ 15)</div>
          <div class="stat-value">${data.highRisk}</div>
        </div>
        <div class="stat-card accent-red">
          <div class="stat-label">Overdue</div>
          <div class="stat-value">${data.overdue}</div>
        </div>
        <div class="stat-card accent-green">
          <div class="stat-label">Closed This Month</div>
          <div class="stat-value">${data.closedThisMonth}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Avg. Resolution Time</div>
          <div class="stat-value">${data.avgResolutionDays !== null ? data.avgResolutionDays + 'd' : '—'}</div>
        </div>`;
    } catch (_) {
      el.innerHTML = '<p class="empty-state">Failed to load stats.</p>';
    }
  }

  // ── Board rendering ────────────────────────────────────────────────────────

  function render() {
    const byStage = Object.fromEntries(STAGES.map(s => [s, []]));
    _risks.forEach(r => { if (byStage[r.stage]) byStage[r.stage].push(r); });

    STAGES.forEach(stage => {
      const body = document.getElementById(`rr-body-${stage}`);
      const count = document.getElementById(`rr-count-${stage}`);
      if (!body) return;
      const items = byStage[stage];
      if (count) count.textContent = items.length;

      if (items.length === 0) {
        body.innerHTML = '<p class="empty-state">No risks.</p>';
        return;
      }

      body.innerHTML = items.map(r => `
        <div class="rr-card" data-id="${r.id}" ${canWrite() ? 'draggable="true"' : ''}>
          <div class="rr-card-header">
            <span class="rr-card-title">${esc(r.title)}</span>
            <span class="badge ${scoreBadge(r.risk_score)}">${r.risk_score}</span>
          </div>
          <div class="rr-card-meta">
            <span>${esc(r.category)}</span>
            ${r.owner ? `<span>${esc(r.owner)}</span>` : ''}
          </div>
          <div class="rr-card-due">Due: ${fmt(r.due_date)}</div>
        </div>
      `).join('');

      body.querySelectorAll('.rr-card').forEach(card => {
        card.addEventListener('click', () => openModal(parseInt(card.dataset.id, 10)));
        if (canWrite()) {
          card.addEventListener('dragstart', (e) => {
            _dragId = parseInt(card.dataset.id, 10);
            card.classList.add('dragging');
            e.dataTransfer.effectAllowed = 'move';
            // Some browsers (notably Firefox) require data to be set for a drag
            // to be recognized as valid, otherwise dragover/drop never fire.
            e.dataTransfer.setData('text/plain', String(_dragId));
          });
          card.addEventListener('dragend', () => card.classList.remove('dragging'));
        }
      });
    });
  }

  function wireColumns() {
    document.querySelectorAll('.rr-column').forEach(col => {
      col.addEventListener('dragover', (e) => {
        if (!canWrite()) return;
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
        col.classList.add('drag-over');
      });
      col.addEventListener('dragleave', () => col.classList.remove('drag-over'));
      col.addEventListener('drop', async (e) => {
        e.preventDefault();
        col.classList.remove('drag-over');
        if (!canWrite() || _dragId === null) return;
        const stage = col.dataset.stage;
        const risk = _risks.find(r => r.id === _dragId);
        if (!risk || risk.stage === stage) { _dragId = null; return; }

        const prevStage = risk.stage;
        risk.stage = stage;
        render();

        try {
          const body = { stage };
          const isSA = window.currentUser && window.currentUser.role === 'superadmin';
          if (isSA && window.globalTenantId) body.tenantId = window.globalTenantId;
          const res = await fetch(`api/risks/${_dragId}/stage`, {
            method: 'PATCH', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
            body: JSON.stringify(body),
          });
          if (!res.ok) throw new Error('stage update failed');
          renderStats();
        } catch (_) {
          risk.stage = prevStage;
          render();
        }
        _dragId = null;
      });
    });
  }

  // ── Data loading ───────────────────────────────────────────────────────────

  async function load() {
    const res = await fetch('api/risks' + tenantParam('?'), { credentials: 'same-origin' });
    const data = await res.json();
    _risks = data.risks || [];
  }

  // ── Modal ──────────────────────────────────────────────────────────────────

  function updateScoreDisplay() {
    const lk = parseInt(document.getElementById('rr-likelihood').value, 10) || 0;
    const im = parseInt(document.getElementById('rr-impact').value, 10) || 0;
    document.getElementById('rr-score-display').textContent = lk * im;
  }

  function openModal(id) {
    const risk = id ? _risks.find(r => r.id === id) : null;
    const readOnly = !canWrite();

    // Move the modal to be a direct child of <body> so its fixed positioning
    // and stacking order can never be affected by an ancestor (e.g. .tab-panel).
    const modalEl = document.getElementById('risk-modal');
    if (modalEl.parentElement !== document.body) document.body.appendChild(modalEl);

    document.getElementById('rr-modal-title').textContent = risk ? 'Edit Risk' : 'New Risk';
    document.getElementById('rr-id').value = risk ? risk.id : '';
    document.getElementById('rr-title').value = risk ? risk.title : '';
    document.getElementById('rr-description').value = risk ? risk.description : '';
    document.getElementById('rr-category').value = risk ? risk.category : 'operational';
    document.getElementById('rr-likelihood').value = risk ? risk.likelihood : 3;
    document.getElementById('rr-impact').value = risk ? risk.impact : 3;
    document.getElementById('rr-owner').value = risk ? risk.owner : '';
    document.getElementById('rr-mitigation').value = risk ? risk.mitigation_plan : '';
    document.getElementById('rr-start').value = risk ? fmt(risk.start_date) : fmt(new Date().toISOString());
    document.getElementById('rr-due').value = risk ? fmt(risk.due_date) : '';
    document.getElementById('rr-stage').value = risk ? risk.stage : 'identified';
    updateScoreDisplay();

    document.getElementById('rr-modal-delete').hidden = !(risk && canWrite());

    document.getElementById('rr-form').querySelectorAll('input, select, textarea').forEach(el => {
      el.disabled = readOnly;
    });
    document.getElementById('rr-modal-save').hidden = readOnly;

    document.getElementById('risk-modal').hidden = false;
    document.body.classList.add('modal-open');
  }

  function closeModal() {
    document.getElementById('risk-modal').hidden = true;
    document.body.classList.remove('modal-open');
  }

  async function saveRisk() {
    const id = document.getElementById('rr-id').value;
    const body = {
      title: document.getElementById('rr-title').value.trim(),
      description: document.getElementById('rr-description').value.trim(),
      category: document.getElementById('rr-category').value,
      likelihood: document.getElementById('rr-likelihood').value,
      impact: document.getElementById('rr-impact').value,
      owner: document.getElementById('rr-owner').value.trim(),
      mitigation_plan: document.getElementById('rr-mitigation').value.trim(),
      start_date: document.getElementById('rr-start').value,
      due_date: document.getElementById('rr-due').value || null,
      stage: document.getElementById('rr-stage').value,
    };
    if (!body.title) { alert('Title is required.'); return; }
    if (!body.start_date) { alert('Start date is required.'); return; }

    const isSA = window.currentUser && window.currentUser.role === 'superadmin';
    if (isSA && window.globalTenantId) body.tenantId = window.globalTenantId;

    const url = id ? `api/risks/${id}` : 'api/risks';
    const method = id ? 'PUT' : 'POST';
    await fetch(url, {
      method, headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
      body: JSON.stringify(body),
    });

    closeModal();
    await load();
    render();
    renderStats();
  }

  async function deleteRisk() {
    const id = document.getElementById('rr-id').value;
    if (!id) return;
    if (!confirm('Delete this risk?')) return;
    await fetch(`api/risks/${id}` + tenantParam('?'), { method: 'DELETE', credentials: 'same-origin' });
    closeModal();
    await load();
    render();
    renderStats();
  }

  // ── Wiring ─────────────────────────────────────────────────────────────────

  function wireOnce() {
    if (RiskRegisterTab._wired) return;
    RiskRegisterTab._wired = true;

    document.getElementById('rr-new-btn').addEventListener('click', () => openModal(null));
    document.getElementById('rr-new-btn').hidden = !canWrite();
    document.getElementById('rr-modal-close').addEventListener('click', closeModal);
    document.getElementById('rr-modal-close-2').addEventListener('click', closeModal);
    document.getElementById('rr-modal-save').addEventListener('click', saveRisk);
    document.getElementById('rr-modal-delete').addEventListener('click', deleteRisk);
    document.getElementById('rr-likelihood').addEventListener('change', updateScoreDisplay);
    document.getElementById('rr-impact').addEventListener('change', updateScoreDisplay);

    wireColumns();
  }

  // ── Main entry ─────────────────────────────────────────────────────────────

  async function loadAndRender() {
    wireOnce();
    await renderStats();
    await load();
    render();
  }

  return { loadAndRender };
})();

window.RiskRegisterTab = RiskRegisterTab;
