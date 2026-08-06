/* tab-vulns.js — Vulnerability Management tab renderer */

(function () {
  'use strict';

  // ── State ──────────────────────────────────────────────────────────────────
  let _currentScan   = null;   // full scan object for selected month
  let _trendsData    = [];     // array from /api/vulns/trends
  let _sortKey       = 'total';
  let _sortAsc       = false;
  let _activeFilter  = 'All';  // severity filter
  let _statusFilter  = 'All';  // status filter
  let _vulnChart     = null;
  let _searchText    = '';
  let _pendingVulnNotice = '';

  const STATUS_LABELS = {
    open:          'Open',
    'in-progress': 'In Progress',
    fixed:         'Fixed',
    accepted:      'Accepted Risk',
  };

  // ── XSS helper ─────────────────────────────────────────────────────────────
  function escHtml(str) {
    return String(str ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // ── Risk badge helper ──────────────────────────────────────────────────────
  function riskBadge(risk) {
    const cls = 'risk-badge risk-' + String(risk || 'info').toLowerCase().replace(/[^a-z]/g, '');
    return `<span class="${escHtml(cls)}">${escHtml(risk || 'Info')}</span>`;
  }


  // ── Tenant query helper ────────────────────────────────────────────────────
  function tenantParam(sep) {
    const isSA = window.currentUser && window.currentUser.role === 'superadmin';
    if (!isSA || !window.globalTenantId) return '';
    return sep + 'tenantId=' + encodeURIComponent(window.globalTenantId);
  }

  // ── Public render entry point ──────────────────────────────────────────────
  window.renderVulns = async function renderVulns(monthKey) {
    const loadingEl = document.getElementById('vulns-loading');
    const emptyEl   = document.getElementById('vulns-empty-state');
    const contentEl = document.getElementById('vulns-content');
    if (loadingEl) { loadingEl.hidden = false; }
    if (emptyEl)   { emptyEl.hidden   = true; }
    if (contentEl) { contentEl.hidden = true; }

    // Fetch scan list + trends together
    try {
      const [listRes, trendsRes] = await Promise.all([
        fetch('api/vulns' + tenantParam('?')),
        fetch('api/vulns/trends' + tenantParam('?')),
      ]);

      const scanList  = listRes.ok  ? await listRes.json()   : [];
      _trendsData     = trendsRes.ok ? await trendsRes.json() : [];

      // Populate the scan selector
      _populateScanSelector(scanList, monthKey);

      // Determine which month to display
      const selectedKey = monthKey
        || (scanList.length > 0 ? scanList[0].monthKey : null);

      if (selectedKey) {
        const scanRes = await fetch(`api/vulns/${selectedKey}` + tenantParam('?'));
        if (scanRes.ok) {
          _currentScan = await scanRes.json();
        } else {
          _currentScan = null;
        }
      } else {
        _currentScan = null;
      }
    } catch {
      _currentScan = null;
      _trendsData  = [];
    }

    // Reset search on new scan load
    _searchText = '';
    const searchInput = document.getElementById('vuln-search');
    if (searchInput) searchInput.value = '';

    if (loadingEl) loadingEl.hidden = true;
    _renderAll();
  };

  // ── Populate scan month selector ────────────────────────────────────────────
  function _populateScanSelector(scanList, selectedKey) {
    const sel    = document.getElementById('vulnScanSelect');
    const delBtn = document.getElementById('vulnDeleteScanBtn');
    if (!sel) return;

    const current = selectedKey || (scanList.length > 0 ? scanList[0].monthKey : '');
    sel.innerHTML = scanList.length === 0
      ? '<option value="">— No scans uploaded —</option>'
      : scanList.map(s => `<option value="${escHtml(s.monthKey)}"${s.monthKey === current ? ' selected' : ''}>${escHtml(s.monthKey)}</option>`).join('');

    // Show uploaded-at timestamp for the current scan
    const currentItem = scanList.find(s => s.monthKey === current);
    _renderUploadedAt(currentItem ? currentItem.uploadedAt : null);

    // Show delete button only when a scan is selected AND user is admin/superadmin
    const isAdmin = window.canWrite('vulns');
    if (delBtn) delBtn.hidden = !current || !isAdmin;

    // Wire change handler once
    if (!sel.dataset.handlerSet) {
      sel.dataset.handlerSet = '1';
      sel.addEventListener('change', () => {
        if (delBtn) {
          const _isAdmin = window.canWrite('vulns');
          delBtn.hidden = !sel.value || !_isAdmin;
        }
        if (sel.value) renderVulns(sel.value);
      });
    }
  }

  // ── Upload timestamp ───────────────────────────────────────────────────────
  function _renderUploadedAt(dateStr) {
    const el = document.getElementById('vulnUploadedAt');
    if (!el) return;
    if (!dateStr) { el.textContent = ''; return; }
    const d = new Date(dateStr);
    el.textContent = 'Uploaded ' + d.toLocaleDateString('en-ZA', { day: 'numeric', month: 'short', year: 'numeric' });
  }

  // ── Full render ────────────────────────────────────────────────────────────
  function _renderAll() {
    _renderStatCards();
    _renderVulnNotice();
    _renderEmptyOrContent();
    // Show/hide export buttons
    const exportBtn = document.getElementById('vulnExportCsvBtn');
    if (exportBtn) exportBtn.hidden = !_currentScan;
    const itReportBtn = document.getElementById('vulnItReportBtn');
    if (itReportBtn) itReportBtn.hidden = !_currentScan;    // Dynamic page title
    document.title = _currentScan
      ? `SecOps — Vulns ${_currentScan.monthKey}`
      : 'SecOps Dashboard';  }

  // ── Stat cards ─────────────────────────────────────────────────────────────
  function _renderStatCards() {
    const el = document.getElementById('vulns-stat-cards');
    if (!el) return;

    const s = _currentScan ? _currentScan.summary : null;

    // Compute MoM deltas from trends
    let prevSummary = null;
    if (_currentScan && _trendsData.length >= 2) {
      const idx = _trendsData.findIndex(t => t.monthKey === _currentScan.monthKey);
      if (idx > 0) prevSummary = _trendsData[idx - 1];
    }

    function delta(cur, prev) {
      if (prev === null || prev === undefined) return '';
      const d = cur - prev;
      if (d === 0) return '';
      const cls = d > 0 ? 'delta-up-bad' : 'delta-down-good';
      return `<span class="stat-delta ${cls}">${d > 0 ? '+' : ''}${d}</span>`;
    }

    const cards = [
      {
        label:  'Critical',
        value:  s ? s.critical : '–',
        accent: 'accent-red',
        d:      s && prevSummary ? delta(s.critical, prevSummary.critical) : '',
      },
      {
        label:  'High',
        value:  s ? s.high : '–',
        accent: 'accent-amber',
        d:      s && prevSummary ? delta(s.high, prevSummary.high) : '',
      },
      {
        label:  'Medium',
        value:  s ? s.medium : '–',
        accent: 'accent-blue',
        d:      s && prevSummary ? delta(s.medium, prevSummary.medium) : '',
      },
      {
        label:  'Low',
        value:  s ? s.low : '–',
        accent: 'accent-green',
        d:      s && prevSummary ? delta(s.low, prevSummary.low) : '',
      },
    ];

    el.innerHTML = cards.map(c => `
      <div class="stat-card ${c.accent}">
        <div class="stat-label">${c.label}</div>
        <div class="stat-value">${c.value}</div>
        ${c.d}
      </div>
    `).join('');
  }

  // ── Empty state vs content ─────────────────────────────────────────────────
  function _renderEmptyOrContent() {
    const emptyEl   = document.getElementById('vulns-empty-state');
    const contentEl = document.getElementById('vulns-content');
    if (!emptyEl || !contentEl) return;

    if (!_currentScan) {
      // Build dynamic upload href for superadmin
      const isSA = window.currentUser && window.currentUser.role === 'superadmin';
      const tenantId = window.globalTenantId;
      const uploadHref = 'upload.html' + (isSA && tenantId ? '?tenantId=' + encodeURIComponent(tenantId) : '');
      emptyEl.innerHTML = `
        <div class="vuln-empty-card">
          <p>No vulnerability scan uploaded yet.</p>
          <a href="${uploadHref}" class="btn btn-primary">Upload Vulnerability Scan</a>
        </div>`;
      emptyEl.hidden   = false;
      contentEl.hidden = true;
      return;
    }

    emptyEl.hidden   = true;
    contentEl.hidden = false;

    _renderTrendChart();
    _renderTopVulns();
    _renderHostTable();
    _renderStatusSummary();
    _renderFilterChips();
    _renderFindingsTable();
  }

  // ── Trend chart (Chart.js) ────────────────────────────────────────────────
  function _renderTrendChart() {
    const canvas = document.getElementById('chartVulnTrend');
    if (!canvas) return;
    if (_vulnChart) { _vulnChart.destroy(); _vulnChart = null; }
    if (_trendsData.length === 0) return;

    // Oldest → newest for left-to-right reading
    const sorted = [..._trendsData].reverse();

    _vulnChart = new Chart(canvas, {
      type: 'line',
      data: {
        labels: sorted.map(d => {
          const [y, m] = d.monthKey.split('-');
          return new Date(parseInt(y), parseInt(m) - 1).toLocaleDateString('en-US', { month: 'short', year: '2-digit' });
        }),
        datasets: [
          { label: 'Critical', data: sorted.map(d => d.critical || 0), borderColor: '#e8394a', backgroundColor: 'rgba(232,57,74,0.06)',  tension: 0.3, pointRadius: 4, fill: false },
          { label: 'High',     data: sorted.map(d => d.high     || 0), borderColor: '#f59e0b', backgroundColor: 'rgba(245,158,11,0.06)', tension: 0.3, pointRadius: 4, fill: false },
          { label: 'Medium',   data: sorted.map(d => d.medium   || 0), borderColor: '#0066cc', backgroundColor: 'rgba(0,102,204,0.06)',  tension: 0.3, pointRadius: 4, fill: false },
          { label: 'Low',      data: sorted.map(d => d.low      || 0), borderColor: '#22c55e', backgroundColor: 'rgba(34,197,94,0.06)',  tension: 0.3, pointRadius: 4, fill: false },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: { beginAtZero: true, ticks: { color: '#7a9bb0', precision: 0 }, grid: { color: 'rgba(0,0,0,0.06)' } },
          x: { ticks: { color: '#7a9bb0' }, grid: { display: false } },
        },
        plugins: {
          legend: { position: 'bottom', labels: { color: '#7a9bb0', boxWidth: 12, padding: 16 } },
          tooltip: { mode: 'index', intersect: false },
        },
      },
    });
  }

  function _renderVulnNotice() {
    const notice = document.getElementById('vulnUploadNotice');
    if (!notice) return;
    if (!_pendingVulnNotice) {
      notice.hidden = true;
      notice.textContent = '';
      return;
    }
    notice.textContent = _pendingVulnNotice;
    notice.hidden = false;
    _pendingVulnNotice = '';
  }

  window.showVulnAutoClosedNotice = function (message) {
    _pendingVulnNotice = String(message || '');
    _renderVulnNotice();
  };

  // ── Top vulnerabilities table ──────────────────────────────────────────────
  function _renderTopVulns() {
    const tbody = document.getElementById('vuln-top-tbody');
    if (!tbody || !_currentScan) return;

    const top = _currentScan.summary.topVulns || [];
    tbody.innerHTML = top.map(v => `
      <tr>
        <td>${escHtml(v.name)}</td>
        <td>${riskBadge(v.risk)}</td>
        <td>${escHtml(String(v.hostCount))}</td>
        <td>${escHtml(v.cve || '—')}</td>
        <td class="solution-cell" title="${escHtml(v.solution)}">${escHtml(v.solution ? v.solution.slice(0, 80) + (v.solution.length > 80 ? '…' : '') : '—')}</td>
      </tr>
    `).join('') || '<tr><td colspan="5">No findings.</td></tr>';
  }

  // ── Per-host table (sortable) ──────────────────────────────────────────────
  function _renderHostTable() {
    const table = document.getElementById('vuln-host-table');
    const tbody = document.getElementById('vuln-host-tbody');
    if (!table || !tbody || !_currentScan) return;

    // Attach sort listeners once
    if (!table.dataset.sortInit) {
      table.dataset.sortInit = '1';
      table.querySelectorAll('th[data-sort]').forEach(th => {
        th.style.cursor = 'pointer';
        th.addEventListener('click', () => {
          const key = th.dataset.sort;
          if (_sortKey === key) {
            _sortAsc = !_sortAsc;
          } else {
            _sortKey = key;
            _sortAsc = key === 'host';
          }
          _renderHostTable();
        });
      });
    }

    let rows = [...(_currentScan.summary.hostSummary || [])];
    rows.sort((a, b) => {
      const av = a[_sortKey] ?? '';
      const bv = b[_sortKey] ?? '';
      if (typeof av === 'number') return _sortAsc ? av - bv : bv - av;
      return _sortAsc ? String(av).localeCompare(String(bv)) : String(bv).localeCompare(String(av));
    });

    // Update sort arrows
    table.querySelectorAll('th[data-sort]').forEach(th => {
      const arrow = th.querySelector('.sort-arrow');
      if (!arrow) return;
      if (th.dataset.sort === _sortKey) {
        arrow.textContent = _sortAsc ? ' ▲' : ' ▼';
      } else {
        arrow.textContent = '';
      }
    });

    tbody.innerHTML = rows.map(h => `
      <tr>
        <td>${escHtml(h.host)}</td>
        <td class="${h.critical > 0 ? 'esc-bad' : ''}">${h.critical}</td>
        <td class="${h.high > 0 ? 'esc-warn' : ''}">${h.high}</td>
        <td>${h.medium}</td>
        <td>${h.low}</td>
        <td>${h.total}</td>
      </tr>
    `).join('') || '<tr><td colspan="6">No host data.</td></tr>';
  }

  // ── Filter chips for findings ──────────────────────────────────────────────
  function _renderFilterChips() {
    // ── Severity filter ──
    const severityEl = document.getElementById('vuln-finding-filters');
    if (severityEl) {
      const levels = ['All', 'Critical', 'High', 'Medium', 'Low'];
      severityEl.innerHTML = levels.map(l => `
        <button class="chip${_activeFilter === l ? ' active' : ''}" data-level="${escHtml(l)}">${escHtml(l)}</button>
      `).join('');
      severityEl.querySelectorAll('.chip').forEach(btn => {
        btn.addEventListener('click', () => {
          _activeFilter = btn.dataset.level;
          _renderFilterChips();
          _renderFindingsTable();
        });
      });
    }

    // ── Search input (wire once) ──
    const searchInput = document.getElementById('vuln-search');
    if (searchInput && !searchInput.dataset.handlerSet) {
      searchInput.dataset.handlerSet = '1';
      searchInput.addEventListener('input', e => {
        _searchText = e.target.value.trim().toLowerCase();
        _renderFindingsTable();
      });
    }

    // ── Status filter ──
    const statusEl = document.getElementById('vuln-status-filters');
    if (statusEl) {
      const statuses = [
        { key: 'All',         label: 'All Statuses' },
        { key: 'open',        label: 'Open' },
        { key: 'in-progress', label: 'In Progress' },
        { key: 'fixed',       label: 'Fixed' },
        { key: 'accepted',    label: 'Accepted Risk' },
      ];
      statusEl.innerHTML = statuses.map(s => `
        <button class="chip${_statusFilter === s.key ? ' active' : ''}${s.key !== 'All' ? ' chip-st-' + escHtml(s.key) : ''}" data-status="${escHtml(s.key)}">${escHtml(s.label)}</button>
      `).join('');
      statusEl.querySelectorAll('.chip').forEach(btn => {
        btn.addEventListener('click', () => {
          _statusFilter = btn.dataset.status;
          _renderFilterChips();
          _renderFindingsTable();
        });
      });
    }
  }

  // ── Findings table ─────────────────────────────────────────────────────────
  function _renderFindingsTable() {
    const tbody = document.getElementById('vuln-findings-tbody');
    if (!tbody || !_currentScan) return;

    const SEVERITY_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3 };
    const allFindings = _currentScan.findings || [];
    const findings = allFindings.map((f, i) => ({ f, i })).sort((a, b) =>
      (SEVERITY_ORDER[a.f.risk] ?? 4) - (SEVERITY_ORDER[b.f.risk] ?? 4)
    );
    let filtered = findings;
    if (_activeFilter !== 'All') {
      filtered = filtered.filter(({ f }) => f.risk === _activeFilter);
    }
    if (_statusFilter !== 'All') {
      filtered = filtered.filter(({ f }) => (f.status || 'open') === _statusFilter);
    }
    if (_searchText) {
      filtered = filtered.filter(({ f }) =>
        (f.host || '').toLowerCase().includes(_searchText) ||
        (f.name || '').toLowerCase().includes(_searchText) ||
        (f.cve  || '').toLowerCase().includes(_searchText)
      );
    }

    tbody.innerHTML = filtered.map(({ f, i: origIdx }) => {
      const s           = f.status || 'open';
      const statusLabel = STATUS_LABELS[s] || s;
      const notesHtml   = f.notes
        ? `<span class="notes-preview" title="${escHtml(f.notes)}">${escHtml(f.notes.slice(0, 50))}${f.notes.length > 50 ? '…' : ''}</span>`
        : `<span class="notes-add">+ Add note</span>`;
      return `
        <tr>
          <td class="col-check"><input type="checkbox" class="finding-cb" data-idx="${origIdx}"></td>
          <td>${escHtml(f.host)}</td>
          <td>${escHtml(f.port || '—')}</td>
          <td>${riskBadge(f.risk)}</td>
          <td class="vuln-name-cell" title="${escHtml(f.name)}">${escHtml(f.name)}</td>
          <td>${escHtml(f.cve || '—')}</td>
          <td class="age-cell">${_ageHtml(f)}</td>
          <td class="due-cell">${_dueHtml(f)}</td>
          <td><button class="status-pill ${escHtml(s)} status-edit-btn" data-idx="${origIdx}" title="Click to manage status">${escHtml(statusLabel)}</button></td>
          <td class="notes-cell" data-idx="${origIdx}">${notesHtml}</td>
        </tr>
      `;
    }).join('') || `<tr><td colspan="10">No findings match the current filter.</td></tr>`;

    tbody.querySelectorAll('.status-edit-btn, .notes-cell').forEach(el => {
      el.addEventListener('click', () => {
        const idx = parseInt(el.dataset.idx, 10);
        _openFindingModal(idx);
      });
    });

    // ── Checkbox / bulk selection ──
    const selectAll = document.getElementById('vulnSelectAll');
    const bulkBar   = document.getElementById('vulnBulkBar');
    const bulkCount = document.getElementById('vulnBulkCount');

    function _syncBulkBar() {
      if (!bulkBar) return;
      const checked = tbody.querySelectorAll('.finding-cb:checked');
      bulkBar.hidden = checked.length === 0;
      if (bulkCount) bulkCount.textContent = `${checked.length} selected`;
    }

    if (selectAll) {
      selectAll.checked = false;
      selectAll.addEventListener('change', () => {
        tbody.querySelectorAll('.finding-cb').forEach(cb => { cb.checked = selectAll.checked; });
        _syncBulkBar();
      });
    }
    tbody.querySelectorAll('.finding-cb').forEach(cb => {
      cb.addEventListener('change', () => {
        if (!cb.checked && selectAll) selectAll.checked = false;
        _syncBulkBar();
      });
    });

    const applyBtn = document.getElementById('vulnBulkApplyBtn');
    const clearBtn = document.getElementById('vulnBulkClearBtn');

    if (clearBtn) {
      clearBtn.onclick = () => {
        tbody.querySelectorAll('.finding-cb').forEach(cb => { cb.checked = false; });
        if (selectAll) selectAll.checked = false;
        _syncBulkBar();
      };
    }

    if (applyBtn) {
      applyBtn.onclick = async () => {
        const statusSel = document.getElementById('vulnBulkStatus');
        const status    = statusSel ? statusSel.value : '';
        if (!status) { alert('Please choose a status to apply.'); return; }

        const checked = [...tbody.querySelectorAll('.finding-cb:checked')];
        const indices = checked.map(cb => parseInt(cb.dataset.idx, 10));
        if (indices.length === 0) return;

        const monthKey = _currentScan.monthKey;
        const body     = { status, indices, tenantId: window.globalTenantId };

        applyBtn.disabled = true;
        applyBtn.textContent = 'Saving…';
        try {
          const res = await fetch(`api/vulns/${encodeURIComponent(monthKey)}/findings/bulk-status`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
          });
          if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            alert('Bulk update failed: ' + (err.error || res.status));
            return;
          }
          // Update local state then re-render
          indices.forEach(idx => {
            if (_currentScan.findings[idx]) _currentScan.findings[idx].status = status;
          });
          if (selectAll) selectAll.checked = false;
          if (statusSel) statusSel.value = '';
          _renderFindingsTable();
          _renderStatusSummary();
        } finally {
          applyBtn.disabled = false;
          applyBtn.textContent = 'Apply';
        }
      };
    }
  }

  // ── Age/SLA helpers ────────────────────────────────────────────────────────

  // Remediation SLA, in days. Mirrors SLA_DAYS in lib/vuln-parser.js — used only
  // as a fallback for scans uploaded before due dates were stored.
  const SLA_DAYS = { critical: 7, high: 14, medium: 30, low: 60 };

  /** Remediation deadline for a finding, or null when it has no SLA. */
  function _dueDate(f) {
    if (f.dueDate) return new Date(f.dueDate);
    const days = SLA_DAYS[(f.risk || '').toLowerCase()];
    if (!days || !f.firstSeenAt) return null;
    return new Date(new Date(f.firstSeenAt).getTime() + days * 86400000);
  }

  /** Whole days until the deadline; negative once overdue. */
  function _daysToDue(f) {
    const due = _dueDate(f);
    if (!due) return null;
    return Math.ceil((due - Date.now()) / 86400000);
  }

  /** Findings already closed have stopped the clock. */
  function _slaActive(f) {
    const s = f.status || 'open';
    return s === 'open' || s === 'in-progress';
  }

  function _ageHtml(f) {
    if (!f.firstSeenAt) return '<span class="age-unknown">—</span>';
    const days = Math.floor((Date.now() - new Date(f.firstSeenAt)) / 86400000);
    const left = _daysToDue(f);
    const isOverdue = _slaActive(f) && left !== null && left < 0;
    const cls = isOverdue ? 'age-overdue' : (days < 7 ? 'age-new' : '');
    return `<span class="${cls}">${days}d</span>`;
  }

  /** Due-date cell: date plus how far past/short of the deadline it is. */
  function _dueHtml(f) {
    const due = _dueDate(f);
    if (!due) return '<span class="age-unknown">—</span>';

    const dateStr = due.toLocaleDateString('en-ZA', { day: '2-digit', month: 'short', year: 'numeric' });
    if (!_slaActive(f)) return `<span class="due-closed" title="Closed — SLA no longer running">${dateStr}</span>`;

    const left = _daysToDue(f);
    if (left < 0)  return `<span class="due-overdue" title="Overdue by ${-left} day(s)">${dateStr} <em>(${-left}d over)</em></span>`;
    if (left <= 3) return `<span class="due-soon" title="Due in ${left} day(s)">${dateStr} <em>(${left}d left)</em></span>`;
    return `<span class="due-ok">${dateStr}</span>`;
  }

  // ── Status summary bar ─────────────────────────────────────────────────────
  function _renderStatusSummary() {
    const el = document.getElementById('vuln-status-summary');
    if (!el) return;
    if (!_currentScan) { el.hidden = true; return; }

    const findings = _currentScan.findings || [];
    const counts = { open: 0, 'in-progress': 0, fixed: 0, accepted: 0 };
    findings.forEach(f => {
      const s = f.status || 'open';
      if (counts[s] !== undefined) counts[s]++;
    });

    const remediatedPct = findings.length
      ? Math.round(((counts.fixed + counts.accepted) / findings.length) * 100)
      : 0;

    el.hidden = false;
    el.innerHTML = `
      <span class="status-count status-count-open" title="Click to filter" data-status="open">
        <span class="sc-dot"></span>Open <strong>${counts.open}</strong>
      </span>
      <span class="status-count status-count-inprogress" title="Click to filter" data-status="in-progress">
        <span class="sc-dot"></span>In Progress <strong>${counts['in-progress']}</strong>
      </span>
      <span class="status-count status-count-fixed" title="Click to filter" data-status="fixed">
        <span class="sc-dot"></span>Fixed <strong>${counts.fixed}</strong>
      </span>
      <span class="status-count status-count-accepted" title="Click to filter" data-status="accepted">
        <span class="sc-dot"></span>Accepted Risk <strong>${counts.accepted}</strong>
      </span>
      <span class="status-count status-count-total">
        Total <strong>${findings.length}</strong>
      </span>
      <span class="status-remediated-pct">
        ${remediatedPct}% addressed
        <div class="remediation-bar"><div class="remediation-fill" style="width:0%"></div></div>
      </span>
    `;

    // Animate bar width after paint
    setTimeout(() => {
      const fill = el.querySelector('.remediation-fill');
      if (fill) fill.style.width = remediatedPct + '%';
    }, 60);

    el.querySelectorAll('.status-count[data-status]').forEach(span => {
      span.addEventListener('click', () => {
        _statusFilter = span.dataset.status;
        _renderFilterChips();
        _renderFindingsTable();
      });
    });
  }

  // ── Finding management modal ───────────────────────────────────────────────
  function _openFindingModal(origIdx) {
    const f     = _currentScan.findings[origIdx];
    const modal = document.getElementById('vuln-finding-modal');
    if (!modal || !f) return;

    const riskKey = String(f.risk || 'info').toLowerCase().replace(/[^a-z]/g, '');
    const RISK_COLOURS = { critical: '#e8394a', high: '#f59e0b', medium: '#3b82f6', low: '#22c55e', info: '#94a3b8' };

    // Colour accent strip at top of modal
    const strip = document.getElementById('modal-risk-strip');
    if (strip) strip.style.background = RISK_COLOURS[riskKey] || '#94a3b8';

    const riskEl = document.getElementById('modal-vuln-risk');
    riskEl.className   = 'risk-badge risk-' + riskKey;
    riskEl.textContent = f.risk || 'Info';

    document.getElementById('modal-vuln-cve').textContent  = f.cve ? f.cve : '';
    document.getElementById('modal-vuln-name').textContent = f.name;

    const hostSpan = document.getElementById('modal-host-text');
    if (hostSpan) hostSpan.textContent = `${f.host}  ·  Port: ${f.port || '—'}`;

    document.getElementById('modal-status-select').value = f.status || 'open';

    const notesEl = document.getElementById('modal-notes');
    notesEl.value = f.notes || '';
    document.getElementById('modal-notes-count').textContent = notesEl.value.length;

    const updatedEl = document.getElementById('modal-updated-at');
    updatedEl.textContent = f.statusUpdatedAt
      ? 'Last updated: ' + new Date(f.statusUpdatedAt).toLocaleString()
      : '';

    document.getElementById('modal-error').hidden = true;
    modal.dataset.idx = origIdx;
    modal.hidden = false;
    document.body.classList.add('modal-open');

    // Role gating — readonly users can view but not edit
    const isAdmin = window.canWrite('vulns');
    const statusSel   = document.getElementById('modal-status-select');
    const notesField  = document.getElementById('modal-notes');
    const saveButton  = document.getElementById('modal-save-btn');
    if (statusSel)  statusSel.disabled  = !isAdmin;
    if (notesField) notesField.disabled = !isAdmin;
    if (saveButton) saveButton.hidden   = !isAdmin;

    if (isAdmin) {
      statusSel.focus();
    }
  }

  function _closeModal() {
    const modal = document.getElementById('vuln-finding-modal');
    if (modal) modal.hidden = true;
    document.body.classList.remove('modal-open');
  }

  async function _saveFindingModal() {
    const modal   = document.getElementById('vuln-finding-modal');
    const origIdx = parseInt(modal.dataset.idx, 10);
    const status  = document.getElementById('modal-status-select').value;
    const notes   = document.getElementById('modal-notes').value.trim();
    const saveBtn = document.getElementById('modal-save-btn');
    const errEl   = document.getElementById('modal-error');

    saveBtn.disabled    = true;
    saveBtn.textContent = 'Saving…';
    errEl.hidden        = true;

    try {
      const res = await fetch(`api/vulns/${_currentScan.monthKey}/finding/${origIdx}`, {
        method:  'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ status, notes, tenantId: window.globalTenantId }),
      });

      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        errEl.textContent = d.error || `Server error (${res.status})`;
        errEl.hidden      = false;
        return;
      }

      const data = await res.json();
      _currentScan.findings[origIdx].status          = status;
      _currentScan.findings[origIdx].notes           = notes;
      _currentScan.findings[origIdx].statusUpdatedAt = data.statusUpdatedAt || new Date().toISOString();

      _closeModal();
      _renderStatusSummary();
      _renderFilterChips();
      _renderFindingsTable();
    } catch (err) {
      errEl.textContent = 'Network error: ' + err.message;
      errEl.hidden      = false;
    } finally {
      saveBtn.disabled    = false;
      saveBtn.textContent = 'Save Changes';
    }
  }

  // ── Export CSV ─────────────────────────────────────────────────────────────
  function _exportCsv() {
    if (!_currentScan) return;
    let rows = _currentScan.findings || [];
    if (_activeFilter !== 'All') rows = rows.filter(f => f.risk === _activeFilter);
    if (_statusFilter !== 'All') rows = rows.filter(f => (f.status || 'open') === _statusFilter);
    const esc = v => '"' + String(v ?? '').replace(/"/g, '""') + '"';
    const csv = [
      ['Host', 'Port', 'Risk', 'Vulnerability', 'CVE', 'Days Open', 'Due Date', 'SLA', 'Status', 'Notes'].join(','),
      ...rows.map(f => {
        const days = f.firstSeenAt
          ? Math.floor((Date.now() - new Date(f.firstSeenAt)) / 86400000) + 'd'
          : '';
        const due  = _dueDate(f);
        const left = _daysToDue(f);
        const sla  = !due || !_slaActive(f) ? ''
                   : (left < 0 ? `Overdue by ${-left}d` : `${left}d left`);
        return [
          f.host, f.port || '', f.risk, f.name,
          f.cve || '', days,
          due ? due.toISOString().slice(0, 10) : '',
          sla,
          f.status || 'open', f.notes || ''
        ].map(esc).join(',');
      })
    ].join('\r\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = 'vulns-' + _currentScan.monthKey + '.csv';
    a.click();
    URL.revokeObjectURL(url);
  }

  // ── IT Escalation Report ──────────────────────────────────────────────────
  function _generateItReport() {
    if (!_currentScan) return;
    const SEVERITY_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3 };
    let rows = (_currentScan.findings || []).slice().sort((a, b) =>
      (SEVERITY_ORDER[a.risk] ?? 4) - (SEVERITY_ORDER[b.risk] ?? 4)
    );
    if (_activeFilter !== 'All') rows = rows.filter(f => f.risk === _activeFilter);
    if (_statusFilter !== 'All') rows = rows.filter(f => (f.status || 'open') === _statusFilter);

    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    rows.forEach(f => { if (counts[f.risk] !== undefined) counts[f.risk]++; });

    const severityColor = { Critical: '#b91c1c', High: '#c2410c', Medium: '#1d4ed8', Low: '#15803d' };
    const esc = s => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    const now = new Date().toLocaleDateString('en-ZA', { day: 'numeric', month: 'long', year: 'numeric' });

    const filterLabel = [
      _activeFilter !== 'All' ? `Severity: ${_activeFilter}` : '',
      _statusFilter !== 'All' ? `Status: ${_statusFilter}` : '',
    ].filter(Boolean).join(' | ') || 'All findings';

    const tableRows = rows.map(f => {
      const days = f.firstSeenAt
        ? Math.floor((Date.now() - new Date(f.firstSeenAt)) / 86400000) + 'd'
        : '—';
      const color = severityColor[f.risk] || '#374151';
      const solution = (f.solution || '—').replace(/\n/g, ' ');
      const due  = _dueDate(f);
      const left = _daysToDue(f);
      const overdue = _slaActive(f) && left !== null && left < 0;
      const dueLabel = due
        ? due.toLocaleDateString('en-ZA', { day: '2-digit', month: 'short', year: 'numeric' }) +
          (overdue ? ` (${-left}d over)` : '')
        : '—';
      return `<tr>
        <td style="color:${color};font-weight:700;white-space:nowrap">${esc(f.risk)}</td>
        <td>${esc(f.host)}</td>
        <td>${esc(f.port || '—')}</td>
        <td>${esc(f.cve || '—')}</td>
        <td>${esc(f.name)}</td>
        <td style="text-align:center">${esc(days)}</td>
        <td style="text-align:center;white-space:nowrap${overdue ? ';color:#b91c1c;font-weight:700' : ''}">${esc(dueLabel)}</td>
        <td style="font-size:12px">${esc(solution)}</td>
      </tr>`;
    }).join('');

    const html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>IT Remediation Report — ${esc(_currentScan.monthKey)}</title>
<style>
  body{font-family:Arial,sans-serif;font-size:13px;color:#1e293b;margin:32px;line-height:1.5}
  h1{font-size:20px;margin-bottom:4px}
  .meta{color:#64748b;font-size:12px;margin-bottom:24px}
  .summary{display:flex;gap:16px;margin-bottom:24px}
  .scard{border:1px solid #e2e8f0;border-radius:6px;padding:10px 20px;min-width:90px;text-align:center}
  .scard .num{font-size:24px;font-weight:700}
  .scard .lbl{font-size:11px;color:#64748b;text-transform:uppercase}
  table{width:100%;border-collapse:collapse;font-size:12px}
  th{background:#1e3a5f;color:#fff;padding:8px;text-align:left;font-size:11px;text-transform:uppercase}
  td{padding:7px 8px;border-bottom:1px solid #e2e8f0;vertical-align:top}
  tr:nth-child(even) td{background:#f8fafc}
  .footer{margin-top:24px;font-size:11px;color:#94a3b8;border-top:1px solid #e2e8f0;padding-top:12px}
  @media print{body{margin:16px}}
</style></head><body>
<h1>Vulnerability Remediation Report</h1>
<div class="meta">Scan period: <strong>${esc(_currentScan.monthKey)}</strong> &nbsp;|&nbsp; Filter: <strong>${esc(filterLabel)}</strong> &nbsp;|&nbsp; Generated: <strong>${now}</strong></div>
<div class="summary">
  <div class="scard"><div class="num" style="color:#b91c1c">${counts.Critical}</div><div class="lbl">Critical</div></div>
  <div class="scard"><div class="num" style="color:#c2410c">${counts.High}</div><div class="lbl">High</div></div>
  <div class="scard"><div class="num" style="color:#1d4ed8">${counts.Medium}</div><div class="lbl">Medium</div></div>
  <div class="scard"><div class="num" style="color:#15803d">${counts.Low}</div><div class="lbl">Low</div></div>
  <div class="scard"><div class="num">${rows.length}</div><div class="lbl">Total</div></div>
</div>
<table>
  <thead><tr><th>Priority</th><th>Host</th><th>Port</th><th>CVE</th><th>Vulnerability</th><th>Age</th><th>Remediate By</th><th>Recommended Action</th></tr></thead>
  <tbody>${tableRows || '<tr><td colspan="8">No findings match the selected filter.</td></tr>'}</tbody>
</table>
<div class="footer">Generated by SecOps Dashboard &mdash; For IT remediation use only.<br>
Remediation SLA, measured from the date a finding was first detected: Critical 1 week &middot; High 2 weeks &middot; Medium 1 month &middot; Low 2 months.</div>
</body></html>`;

    const win = window.open('', '_blank');
    if (win) {
      win.document.write(html);
      win.document.close();
    }
  }

  // ── Modal wiring (once at load) ────────────────────────────────────────────
  (function _initModal() {
    const modal   = document.getElementById('vuln-finding-modal');
    const notesEl = document.getElementById('modal-notes');
    const countEl = document.getElementById('modal-notes-count');
    if (!modal) return;

    document.getElementById('modal-close-btn').addEventListener('click',  _closeModal);
    document.getElementById('modal-cancel-btn').addEventListener('click', _closeModal);
    document.getElementById('modal-save-btn').addEventListener('click',   _saveFindingModal);

    modal.addEventListener('click', e => { if (e.target === modal) _closeModal(); });
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape' && !modal.hidden) _closeModal();
    });

    if (notesEl && countEl) {
      notesEl.addEventListener('input', () => {
        countEl.textContent = notesEl.value.length;
      });
    }

    // ── Export CSV button ──
    const exportBtn = document.getElementById('vulnExportCsvBtn');
    if (exportBtn) exportBtn.addEventListener('click', _exportCsv);

    // ── IT Report button ──
    const itReportBtn = document.getElementById('vulnItReportBtn');
    if (itReportBtn) itReportBtn.addEventListener('click', _generateItReport);

    // ── Delete scan button (two-step inline confirm) ──
    const delBtn = document.getElementById('vulnDeleteScanBtn');
    if (delBtn) {
      delBtn.addEventListener('click', async () => {
        const sel      = document.getElementById('vulnScanSelect');
        const monthKey = sel ? sel.value : '';
        if (!monthKey) return;

        // First click: arm the button
        if (!delBtn.dataset.armed) {
          delBtn.dataset.armed = '1';
          delBtn.textContent   = '\u26a0\ufe0f Confirm delete?';
          delBtn.classList.add('btn-delete-armed');
          setTimeout(() => {
            if (delBtn.dataset.armed) {
              delete delBtn.dataset.armed;
              delBtn.classList.remove('btn-delete-armed');
              delBtn.textContent = '\uD83D\uDDD1\uFE0F Delete Scan';
            }
          }, 4000);
          return;
        }

        // Second click: proceed
        delete delBtn.dataset.armed;
        delBtn.classList.remove('btn-delete-armed');
        delBtn.disabled    = true;
        delBtn.textContent = 'Deleting…';

        try {
          const res = await fetch(`api/vulns/${encodeURIComponent(monthKey)}` + tenantParam('?'), { method: 'DELETE' });
          if (!res.ok) {
            const d = await res.json().catch(() => ({}));
            alert(d.error || `Delete failed (${res.status})`);
            return;
          }
          await renderVulns();
        } catch (err) {
          alert('Network error: ' + err.message);
        } finally {
          delBtn.disabled    = false;
          delBtn.textContent = '\uD83D\uDDD1\uFE0F Delete Scan';
        }
      });
    }
  })();

})();
