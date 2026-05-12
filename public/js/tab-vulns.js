/* tab-vulns.js — Vulnerability Management tab renderer */

(function () {
  'use strict';

  // ── State ──────────────────────────────────────────────────────────────────
  let _currentScan   = null;   // full scan object for selected week
  let _trendsData    = [];     // array from /api/vulns/trends
  let _sortKey       = 'total';
  let _sortAsc       = false;
  let _activeFilter  = 'All';
  let _trendCanvas   = null;
  let _trendTooltip  = null;

  // Status cycle for remediation tracking
  const STATUS_CYCLE = ['open', 'in-progress', 'fixed', 'accepted'];

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

  // ── Status pill helper ─────────────────────────────────────────────────────
  function statusPill(status, index) {
    const s = status || 'open';
    return `<span class="status-pill ${escHtml(s)}" data-idx="${index}" role="button" tabindex="0">${escHtml(s)}</span>`;
  }

  // ── Public render entry point ──────────────────────────────────────────────
  window.renderVulns = async function renderVulns(monthKey) {
    // Fetch scan list + trends together
    try {
      const [listRes, trendsRes] = await Promise.all([
        fetch('api/vulns'),
        fetch('api/vulns/trends'),
      ]);

      const scanList  = listRes.ok  ? await listRes.json()   : [];
      _trendsData     = trendsRes.ok ? await trendsRes.json() : [];

      // Populate the scan selector
      _populateScanSelector(scanList, monthKey);

      // Determine which month to display
      const selectedKey = monthKey
        || (scanList.length > 0 ? scanList[0].monthKey : null);

      if (selectedKey) {
        const scanRes = await fetch(`api/vulns/${selectedKey}`);
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
    const sel = document.getElementById('vulnScanSelect');
    if (!sel) return;

    const current = selectedKey || (scanList.length > 0 ? scanList[0].monthKey : '');
    sel.innerHTML = scanList.length === 0
      ? '<option value="">— No scans uploaded —</option>'
      : scanList.map(s => `<option value="${escHtml(s.monthKey)}"${s.monthKey === current ? ' selected' : ''}>${escHtml(s.monthKey)}</option>`).join('');

    // Wire change handler once
    if (!sel.dataset.handlerSet) {
      sel.dataset.handlerSet = '1';
      sel.addEventListener('change', () => {
        if (sel.value) renderVulns(sel.value);
      });
    }
  }

  // ── Full render ────────────────────────────────────────────────────────────
  function _renderAll() {
    _renderStatCards();
    _renderEmptyOrContent();
  }

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
      emptyEl.hidden   = false;
      contentEl.hidden = true;
      return;
    }

    emptyEl.hidden   = true;
    contentEl.hidden = false;

    _renderTrendChart(_currentScan.monthKey);
    _renderTopVulns();
    _renderHostTable();
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
    const el = document.getElementById('vuln-finding-filters');
    if (!el) return;

    const levels = ['All', 'Critical', 'High', 'Medium', 'Low'];
    el.innerHTML = levels.map(l => `
      <button class="chip${_activeFilter === l ? ' active' : ''}" data-level="${escHtml(l)}">${escHtml(l)}</button>
    `).join('');

    el.querySelectorAll('.chip').forEach(btn => {
      btn.addEventListener('click', () => {
        _activeFilter = btn.dataset.level;
        _renderFilterChips();
        _renderFindingsTable();
      });
    });
  }

  // ── Findings table ─────────────────────────────────────────────────────────
  function _renderFindingsTable() {
    const tbody = document.getElementById('vuln-findings-tbody');
    if (!tbody || !_currentScan) return;

    const findings = _currentScan.findings || [];
    const filtered = _activeFilter === 'All'
      ? findings
      : findings.filter(f => f.risk === _activeFilter);

    tbody.innerHTML = filtered.map((f, displayIdx) => {
      // Map display index back to original index for PATCH calls
      const origIdx = findings.indexOf(f);
      return `
        <tr>
          <td>${escHtml(f.host)}</td>
          <td>${escHtml(f.port || '—')}</td>
          <td>${riskBadge(f.risk)}</td>
          <td class="vuln-name-cell" title="${escHtml(f.name)}">${escHtml(f.name)}</td>
          <td>${escHtml(f.cve || '—')}</td>
          <td>${statusPill(f.status, origIdx)}</td>
        </tr>
      `;
    }).join('') || '<tr><td colspan="6">No findings match the current filter.</td></tr>';

    // Attach status pill click handlers
    tbody.querySelectorAll('.status-pill').forEach(pill => {
      pill.addEventListener('click', () => _cycleStatus(pill));
      pill.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); _cycleStatus(pill); }
      });
    });
  }

  // ── Status cycling ─────────────────────────────────────────────────────────
  async function _cycleStatus(pill) {
    if (!_currentScan) return;
    const idx    = parseInt(pill.dataset.idx, 10);
    const cur    = _currentScan.findings[idx].status || 'open';
    const curPos = STATUS_CYCLE.indexOf(cur);
    const next   = STATUS_CYCLE[(curPos + 1) % STATUS_CYCLE.length];

    try {
      const res = await fetch(`api/vulns/${_currentScan.monthKey}/finding/${idx}`, {
        method:  'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ status: next }),
      });

      if (!res.ok) return;
      _currentScan.findings[idx].status = next;

      // Update pill in place
      pill.textContent = next;
      pill.className   = `status-pill ${next}`;
    } catch {
      // Network error — silently skip
    }
  }

})();
