/* tab-metrics.js — renders the Metrics & Trends tab (native Canvas 2D only) */

(function () {
  'use strict';

  // ── Public render ──────────────────────────────────────────────────────────
  window.renderMetrics = function renderMetrics(weekData, summaryData) {
    const weekKey = window.currentWeekKey;

    // Find the metrics entry for the current week
    const currentMetrics = summaryData.find(m => m.weekKey === weekKey) || null;

    renderStatCards(currentMetrics);

    // Draw all four line charts
    const labels = summaryData.map(m => fmtLabel(m.weekCommencing));

    drawChart(
      document.getElementById('chartAlerts'),
      document.getElementById('tooltipAlerts'),
      labels,
      [
        { label: 'Total Alerts',   values: summaryData.map(m => m.orgs.totalAlerts),   color: '#f85149' },
        { label: 'Escalated',      values: summaryData.map(m => m.orgs.totalEscalated), color: '#d29922' },
      ],
      weekKey,
      summaryData
    );

    drawChart(
      document.getElementById('chartResolution'),
      document.getElementById('tooltipResolution'),
      labels,
      [
        { label: 'Resolution Rate %', values: summaryData.map(m => m.priorities.resolutionRate), color: '#3fb950' },
      ],
      weekKey,
      summaryData
    );

    drawChart(
      document.getElementById('chartCoverage'),
      document.getElementById('tooltipCoverage'),
      labels,
      [
        { label: 'Avg Coverage Score', values: summaryData.map(m => m.orgs.avgCoverageScore), color: '#58a6ff' },
      ],
      weekKey,
      summaryData
    );

    drawChart(
      document.getElementById('chartCritical'),
      document.getElementById('tooltipCritical'),
      labels,
      [
        { label: 'Critical Open', values: summaryData.map(m => m.priorities.criticalOpen), color: '#a371f7' },
      ],
      weekKey,
      summaryData
    );

    // Org health table
    renderOrgHealthTable(summaryData, weekKey);
  };

  // ── Stat cards ─────────────────────────────────────────────────────────────
  function renderStatCards(m) {
    const container = document.getElementById('metrics-stat-cards');
    if (!m) {
      container.innerHTML = '<p style="color:var(--muted);font-size:.87rem">No metrics available for this week.</p>';
      return;
    }

    const d = m.deltas || {};

    container.innerHTML = [
      metricCard('Total Alerts',      m.orgs.totalAlerts,          deltaHtml(d.totalAlerts,      'worse-up'),   'accent-red'),
      metricCard('Escalated',         m.orgs.totalEscalated,       deltaHtml(d.totalEscalated,   'worse-up'),   'accent-amber'),
      metricCard('Resolution Rate',   m.priorities.resolutionRate + '%', deltaHtml(d.resolutionRate, 'better-up'), 'accent-green'),
      metricCard('Avg Coverage',      m.orgs.avgCoverageScore !== null ? m.orgs.avgCoverageScore + '%' : '—',
                                                                   deltaHtml(d.avgCoverageScore, 'better-up'),  'accent-blue'),
      metricCard('Critical Open',     m.priorities.criticalOpen,   deltaHtml(d.criticalOpen,     'worse-up'),   m.priorities.criticalOpen > 0 ? 'accent-red' : 'accent-green'),
      metricCard('Sysmon Deploy',     m.agents.sysmonDeploymentRate !== null ? m.agents.sysmonDeploymentRate + '%' : '—',
                                                                   deltaHtml(d.sysmonDeploymentRate, 'better-up'), 'accent-blue'),
    ].join('');
  }

  /**
   * direction: 'worse-up' (increase = bad) | 'better-up' (increase = good)
   */
  function deltaHtml(delta, direction) {
    if (delta === null || delta === undefined) return '';
    const isUp = delta > 0;
    const arrow = isUp ? '▲' : delta < 0 ? '▼' : '—';
    const abs   = Math.abs(delta);

    let cls = 'delta-neutral';
    if (delta !== 0) {
      if (direction === 'worse-up')  cls = isUp ? 'delta-up-bad'  : 'delta-down-bad';
      if (direction === 'better-up') cls = isUp ? 'delta-up-good' : 'delta-down-good';
    }
    return `<span class="${cls}">${arrow} ${abs}</span>`;
  }

  function metricCard(label, value, deltaHtml, accent) {
    return `<div class="stat-card ${accent}">
      <span class="stat-label">${label}</span>
      <span class="stat-value">${value !== null && value !== undefined ? value : '—'}</span>
      <span class="stat-delta">${deltaHtml || ''}</span>
    </div>`;
  }

  // ── Line chart (native Canvas 2D) ─────────────────────────────────────────
  /**
   * @param {HTMLCanvasElement} canvas
   * @param {HTMLElement}       tooltip
   * @param {string[]}          labels
   * @param {{ label, values, color }[]} datasets
   * @param {string}            selectedWeekKey
   * @param {object[]}          summaryData
   */
  function drawChart(canvas, tooltip, labels, datasets, selectedWeekKey, summaryData) {
    if (!canvas) return;

    const DPR  = window.devicePixelRatio || 1;
    const W    = canvas.parentElement.clientWidth || 400;
    const H    = 180;

    canvas.width  = W * DPR;
    canvas.height = H * DPR;
    canvas.style.height = H + 'px';

    const ctx = canvas.getContext('2d');
    ctx.scale(DPR, DPR);

    const PAD  = { top: 20, right: 20, bottom: 36, left: 44 };
    const pw   = W - PAD.left - PAD.right;
    const ph   = H - PAD.top  - PAD.bottom;

    // Compute Y range across all datasets (ignore nulls)
    const allValues = datasets.flatMap(d => d.values).filter(v => v !== null && v !== undefined);
    let yMin = allValues.length ? Math.min(...allValues) : 0;
    let yMax = allValues.length ? Math.max(...allValues) : 100;
    if (yMin === yMax) { yMin = Math.max(0, yMin - 5); yMax = yMax + 5; }
    const yPad = (yMax - yMin) * 0.12;
    yMin = Math.max(0, yMin - yPad);
    yMax = yMax + yPad;

    const n = labels.length;
    const xPos = (i) => PAD.left + (n <= 1 ? pw / 2 : (i / (n - 1)) * pw);
    const yPos = (v) => PAD.top  + ph - ((v - yMin) / (yMax - yMin)) * ph;

    const COLORS = {
      bg:     '#0d1117',
      grid:   '#30363d',
      text:   '#8b949e',
      textBr: '#e6edf3',
    };

    // Background
    ctx.fillStyle = COLORS.bg;
    ctx.fillRect(0, 0, W, H);

    // Y grid lines + labels (5 steps)
    const ySteps = 4;
    ctx.textAlign    = 'right';
    ctx.textBaseline = 'middle';
    ctx.font         = '10px sans-serif';
    ctx.fillStyle    = COLORS.text;
    for (let i = 0; i <= ySteps; i++) {
      const val = yMin + ((yMax - yMin) * i / ySteps);
      const y   = yPos(val);
      ctx.strokeStyle = COLORS.grid;
      ctx.lineWidth   = 0.5;
      ctx.beginPath();
      ctx.moveTo(PAD.left, y);
      ctx.lineTo(PAD.left + pw, y);
      ctx.stroke();
      ctx.fillText(Math.round(val), PAD.left - 6, y);
    }

    // X labels + vertical tick for selected week
    const selectedIdx = summaryData.findIndex(m => m.weekKey === selectedWeekKey);
    ctx.textAlign    = 'center';
    ctx.textBaseline = 'top';

    labels.forEach((lbl, i) => {
      const x = xPos(i);
      ctx.fillStyle = COLORS.text;
      ctx.font      = '10px sans-serif';
      // Only show a subset of labels to avoid crowding
      if (n <= 6 || i % Math.ceil(n / 6) === 0 || i === n - 1) {
        ctx.fillText(lbl, x, PAD.top + ph + 6);
      }
    });

    // Selected week dashed vertical line
    if (selectedIdx >= 0) {
      const sx = xPos(selectedIdx);
      ctx.save();
      ctx.strokeStyle = '#58a6ff';
      ctx.lineWidth   = 1.2;
      ctx.setLineDash([4, 3]);
      ctx.beginPath();
      ctx.moveTo(sx, PAD.top);
      ctx.lineTo(sx, PAD.top + ph);
      ctx.stroke();
      ctx.restore();
    }

    // Dataset lines
    datasets.forEach(ds => {
      ctx.strokeStyle = ds.color;
      ctx.lineWidth   = 2;
      ctx.lineJoin    = 'round';
      ctx.lineCap     = 'round';
      ctx.setLineDash([]);

      let started = false;
      ctx.beginPath();
      ds.values.forEach((val, i) => {
        if (val === null || val === undefined) { started = false; return; }
        const x = xPos(i);
        const y = yPos(val);
        if (!started) { ctx.moveTo(x, y); started = true; }
        else          { ctx.lineTo(x, y); }
      });
      ctx.stroke();

      // Dots
      ds.values.forEach((val, i) => {
        if (val === null || val === undefined) return;
        const x = xPos(i);
        const y = yPos(val);
        ctx.fillStyle = ds.color;
        ctx.beginPath();
        ctx.arc(x, y, 3, 0, Math.PI * 2);
        ctx.fill();
      });
    });

    // ── Hover tooltip ──────────────────────────────────────────────────────
    // Remove old listener by replacing canvas with clone
    const newCanvas = canvas.cloneNode(true);
    canvas.parentNode.replaceChild(newCanvas, canvas);

    // Re-draw on new canvas (DOM is replaced so we need to recurse draw calls on it)
    // Instead, track mouse directly on the in-place canvas before replacement
    // Better: keep original canvas and just update the tooltip element

    // Reattach listener to the new canvas
    newCanvas.addEventListener('mousemove', (e) => {
      const rect = newCanvas.getBoundingClientRect();
      const mx   = e.clientX - rect.left;

      // Find nearest data point index
      let nearestIdx = 0;
      let minDist    = Infinity;
      for (let i = 0; i < n; i++) {
        const dist = Math.abs(xPos(i) - mx);
        if (dist < minDist) { minDist = dist; nearestIdx = i; }
      }

      const lines = datasets.map(ds => {
        const v = ds.values[nearestIdx];
        return `<span style="color:${ds.color}">${ds.label}: <strong>${v !== null && v !== undefined ? v : '—'}</strong></span>`;
      });

      tooltip.innerHTML = `<div style="margin-bottom:2px;color:var(--muted)">${labels[nearestIdx]}</div>${lines.join('<br>')}`;
      tooltip.hidden = false;

      const tx = xPos(nearestIdx);
      tooltip.style.left = tx + 'px';
      tooltip.style.top  = (PAD.top - 4) + 'px';
    });

    newCanvas.addEventListener('mouseleave', () => {
      tooltip.hidden = true;
    });
  }

  // ── Org health table ───────────────────────────────────────────────────────
  async function renderOrgHealthTable(summaryData, selectedWeekKey) {
    const tbody = document.getElementById('org-health-tbody');
    tbody.innerHTML = '';

    let orgHistory;
    try {
      orgHistory = await fetch('api/metrics/orgs').then(r => r.json());
    } catch (_) {
      return;
    }

    const orgNames = Object.keys(orgHistory).sort();
    if (orgNames.length === 0) {
      const tr = document.createElement('tr');
      tr.innerHTML = '<td colspan="4" style="text-align:center;color:var(--muted);padding:1.5rem">No org history available.</td>';
      tbody.appendChild(tr);
      return;
    }

    orgNames.forEach(name => {
      const history = orgHistory[name];
      // Last 8 weeks
      const recent = history.slice(-8);

      // Latest entry
      const latest = recent[recent.length - 1] || {};

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${escHtml(name)}</td>
        <td class="sparkline-cell"><canvas width="80" height="30"></canvas></td>
        <td>${latest.alerts !== undefined ? latest.alerts : '—'}</td>
        <td>${coverageCellInline(latest.coverageScore)}</td>
      `;

      const sparkCanvas = tr.querySelector('canvas');
      drawSparkline(sparkCanvas, recent.map(h => h.alerts));

      tbody.appendChild(tr);
    });
  }

  function coverageCellInline(score) {
    if (score === null || score === undefined) return '<span style="color:var(--muted)">—</span>';
    const cls = score < 75 ? 'cov-bad' : score < 90 ? 'cov-warn' : 'cov-good';
    return `<span class="${cls}">${score}%</span>`;
  }

  // ── Sparkline (minimal 80×30 canvas, no axes) ────────────────────────────
  function drawSparkline(canvas, values) {
    const vals = values.filter(v => v !== null && v !== undefined);
    if (!canvas || vals.length === 0) return;

    const W  = 80, H = 30;
    canvas.width  = W * (window.devicePixelRatio || 1);
    canvas.height = H * (window.devicePixelRatio || 1);
    canvas.style.width  = W + 'px';
    canvas.style.height = H + 'px';

    const ctx = canvas.getContext('2d');
    ctx.scale(window.devicePixelRatio || 1, window.devicePixelRatio || 1);

    let mn = Math.min(...vals), mx = Math.max(...vals);
    if (mn === mx) { mn = Math.max(0, mn - 1); mx = mx + 1; }

    const xStep = W / Math.max(vals.length - 1, 1);
    const yOf   = (v) => H - 2 - ((v - mn) / (mx - mn)) * (H - 4);

    ctx.clearRect(0, 0, W, H);
    ctx.strokeStyle = '#58a6ff';
    ctx.lineWidth   = 1.5;
    ctx.lineJoin    = 'round';
    ctx.beginPath();
    vals.forEach((v, i) => {
      const x = i * xStep;
      const y = yOf(v);
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.stroke();
  }

  // ── Helpers ────────────────────────────────────────────────────────────────
  function fmtLabel(dateStr) {
    if (!dateStr) return '';
    // Try to format as short date
    try {
      const d = new Date(dateStr);
      if (!isNaN(d)) {
        return (d.getMonth() + 1) + '/' + d.getDate();
      }
    } catch (_) {}
    // Fallback: take last 5 chars of ISO date (MM-DD)
    return String(dateStr).slice(5);
  }

  function escHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

})();
