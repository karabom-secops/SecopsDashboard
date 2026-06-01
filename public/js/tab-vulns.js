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
  let _trendCanvas   = null;
  let _trendTooltip  = null;
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
    const isAdmin = window.currentUser && (window.currentUser.role === 'admin' || window.currentUser.role === 'superadmin');
    if (delBtn) delBtn.hidden = !current || !isAdmin;

    // Wire change handler once
    if (!sel.dataset.handlerSet) {
      sel.dataset.handlerSet = '1';
      sel.addEventListener('change', () => {
        if (delBtn) {
          const _isAdmin = window.currentUser && (window.currentUser.role === 'admin' || window.currentUser.role === 'superadmin');
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
    // Show/hide export button
    const exportBtn = document.getElementById('vulnExportCsvBtn');
    if (exportBtn) exportBtn.hidden = !_currentScan;    // Dynamic page title
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
          <p>No Nessus scan uploaded yet.</p>
          <a href="${uploadHref}" class="btn btn-primary">Upload Nessus Scan</a>
        </div>`;
      emptyEl.hidden   = false;
      contentEl.hidden = true;
      return;
    }

    emptyEl.hidden   = true;
    contentEl.hidden = false;

    _renderTrendChart(_currentScan.monthKey);
    _renderTopVulns();
    _renderHostTable();
    _renderStatusSummary();
    _renderFilterChips();
    _renderFindingsTable();
  }

  // ── Trend chart ────────────────────────────────────────────────────────────
  function _renderTrendChart(selectedMonthKey) {
    const canvas  = document.getElementById('chartVulnTrend');
    const tooltip = document.getElementById('tooltipVulnTrend');
    if (!canvas || !tooltip) return;

    _trendCanvas  = canvas;
    _trendTooltip = tooltip;

    if (_trendsData.length === 0) return;

    const DPR = window.devicePixelRatio || 1;
    const wrap = canvas.parentElement;
    const W    = wrap.clientWidth  || 700;
    const H    = wrap.clientHeight || 260;

    canvas.width  = W * DPR;
    canvas.height = H * DPR;
    canvas.style.width  = W + 'px';
    canvas.style.height = H + 'px';

    const ctx = canvas.getContext('2d');
    ctx.scale(DPR, DPR);

    const PAD = { top: 20, right: 20, bottom: 50, left: 50 };
    const cW  = W - PAD.left - PAD.right;
    const cH  = H - PAD.top  - PAD.bottom;

    const series = [
      { key: 'critical', colour: '#e8394a', label: 'Critical' },
      { key: 'high',     colour: '#f59e0b', label: 'High'     },
      { key: 'medium',   colour: '#0066cc', label: 'Medium'   },
      { key: 'low',      colour: '#22c55e', label: 'Low'      },
    ];

    const maxVal = Math.max(1, ...series.map(s => Math.max(..._trendsData.map(t => t[s.key] || 0))));
    const n      = _trendsData.length;

    function xPos(i) { return PAD.left + (i / Math.max(n - 1, 1)) * cW; }
    function yPos(v) { return PAD.top  + cH - (v / maxVal) * cH; }

    // Background
    ctx.clearRect(0, 0, W, H);

    // Grid lines
    ctx.strokeStyle = '#e5e7eb';
    ctx.lineWidth   = 1;
    for (let i = 0; i <= 5; i++) {
      const y = PAD.top + (cH / 5) * i;
      ctx.beginPath(); ctx.moveTo(PAD.left, y); ctx.lineTo(W - PAD.right, y); ctx.stroke();
    }

    // Y axis labels
    ctx.fillStyle  = '#6b7280';
    ctx.font       = '11px sans-serif';
    ctx.textAlign  = 'right';
    for (let i = 0; i <= 5; i++) {
      const v = Math.round(maxVal * (1 - i / 5));
      const y = PAD.top + (cH / 5) * i;
      ctx.fillText(String(v), PAD.left - 6, y + 4);
    }

    // X axis labels
    ctx.textAlign = 'center';
    _trendsData.forEach((t, i) => {
      const x = xPos(i);
      ctx.fillText(t.monthKey ? t.monthKey.slice(5) : '', x, H - 10);
    });

    // Selected-month vertical marker
    const selIdx = _trendsData.findIndex(t => t.monthKey === selectedMonthKey);
    if (selIdx >= 0) {
      ctx.save();
      ctx.setLineDash([4, 4]);
      ctx.strokeStyle = '#94a3b8';
      ctx.lineWidth   = 1.5;
      const xm = xPos(selIdx);
      ctx.beginPath(); ctx.moveTo(xm, PAD.top); ctx.lineTo(xm, H - PAD.bottom); ctx.stroke();
      ctx.restore();
    }

    // Series lines
    series.forEach(s => {
      ctx.beginPath();
      ctx.strokeStyle = s.colour;
      ctx.lineWidth   = 2;
      _trendsData.forEach((t, i) => {
        const x = xPos(i);
        const y = yPos(t[s.key] || 0);
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      });
      ctx.stroke();

      // Dots
      _trendsData.forEach((t, i) => {
        ctx.beginPath();
        ctx.fillStyle = s.colour;
        ctx.arc(xPos(i), yPos(t[s.key] || 0), 3, 0, Math.PI * 2);
        ctx.fill();
      });
    });

    // Legend
    const legendY = H - PAD.bottom + 22;
    let legendX   = PAD.left;
    series.forEach(s => {
      ctx.fillStyle = s.colour;
      ctx.fillRect(legendX, legendY, 12, 4);
      ctx.fillStyle  = '#374151';
      ctx.textAlign  = 'left';
      ctx.fillText(s.label, legendX + 16, legendY + 6);
      legendX += 80;
    });

    // Tooltip on hover
    canvas.onmousemove = null;
    canvas.onmouseleave = null;

    canvas.onmousemove = (e) => {
      const rect = canvas.getBoundingClientRect();
      const mx   = e.clientX - rect.left;
      const my   = e.clientY - rect.top;

      let closest = null, minDist = Infinity;
      _trendsData.forEach((t, i) => {
        series.forEach(s => {
          const dx = mx - xPos(i);
          const dy = my - yPos(t[s.key] || 0);
          const d  = Math.sqrt(dx * dx + dy * dy);
          if (d < minDist) { minDist = d; closest = { t, s, i }; }
        });
      });

      if (closest && minDist < 30) {
        tooltip.hidden = false;
        tooltip.style.left = (xPos(closest.i) + 10) + 'px';
        tooltip.style.top  = (yPos(closest.t[closest.s.key] || 0) - 10) + 'px';
        tooltip.textContent = `${closest.t.monthKey} — ${closest.s.label}: ${closest.t[closest.s.key] || 0}`;
      } else {
        tooltip.hidden = true;
      }
    };

    canvas.onmouseleave = () => { tooltip.hidden = true; };
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

    const findings = _currentScan.findings || [];
    let filtered = findings;
    if (_activeFilter !== 'All') {
      filtered = filtered.filter(f => f.risk === _activeFilter);
    }
    if (_statusFilter !== 'All') {
      filtered = filtered.filter(f => (f.status || 'open') === _statusFilter);
    }

    tbody.innerHTML = filtered.map(f => {
      const origIdx     = findings.indexOf(f);
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
          <td><button class="status-pill ${escHtml(s)} status-edit-btn" data-idx="${origIdx}" title="Click to manage status">${escHtml(statusLabel)}</button></td>
          <td class="notes-cell" data-idx="${origIdx}">${notesHtml}</td>
        </tr>
      `;
    }).join('') || `<tr><td colspan="9">No findings match the current filter.</td></tr>`;

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

  // ── Age/SLA helper ─────────────────────────────────────────────────────────
  function _ageHtml(f) {
    if (!f.firstSeenAt) return '<span class="age-unknown">—</span>';
    const days = Math.floor((Date.now() - new Date(f.firstSeenAt)) / 86400000);
    const risk = (f.risk || '').toLowerCase();
    const isOverdue = (risk === 'critical' && days > 30) || (risk === 'high' && days > 60) || (risk === 'medium' && days > 90);
    const cls = isOverdue ? 'age-overdue' : (days < 7 ? 'age-new' : '');
    return `<span class="${cls}">${days}d</span>`;
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
        <div class="remediation-bar"><div class="remediation-fill" style="width:${remediatedPct}%"></div></div>
      </span>
    `;

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
    const isAdmin = window.currentUser && window.currentUser.role !== 'readonly';
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
      ['Host', 'Port', 'Risk', 'Vulnerability', 'CVE', 'Days Open', 'Status', 'Notes'].join(','),
      ...rows.map(f => {
        const days = f.firstSeenAt
          ? Math.floor((Date.now() - new Date(f.firstSeenAt)) / 86400000) + 'd'
          : '';
        return [
          f.host, f.port || '', f.risk, f.name,
          f.cve || '', days, f.status || 'open', f.notes || ''
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
