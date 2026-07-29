/* tab-edr.js — Managed EDR (SentinelOne) threats, fleet health & activity */
const EdrTab = (() => {
  'use strict';

  const charts = {};
  let bound   = false;
  let summary = null;

  // Palette pulled from the dashboard's semantic CSS variables so the charts
  // read the same as the rest of the app.
  const COLORS = {
    blue:   '#0066CC',
    cyan:   '#00BADF',
    red:    '#E8394A',
    amber:  '#F59E0B',
    green:  '#22C55E',
    purple: '#7C3AED',
    muted:  '#4A7A96',
  };
  const SERIES = [COLORS.blue, COLORS.cyan, COLORS.amber, COLORS.purple, COLORS.green, COLORS.red, COLORS.muted];

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function tenantQS(extra) {
    const params = new URLSearchParams(extra || {});
    const isSA = window.currentUser && window.currentUser.role === 'superadmin';
    if (isSA && window.globalTenantId) params.set('tenantId', window.globalTenantId);
    const s = params.toString();
    return s ? '?' + s : '';
  }

  function tenantBody() {
    const isSA = window.currentUser && window.currentUser.role === 'superadmin';
    if (!isSA || !window.globalTenantId) return {};
    return { tenantId: window.globalTenantId };
  }

  /** snake_case / lower-case API values → readable labels. */
  function humanise(v) {
    if (!v) return '—';
    return String(v).replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
  }

  function fmtDate(v) {
    if (!v) return '—';
    const d = new Date(v);
    if (isNaN(d.getTime())) return '—';
    return d.toLocaleString('en-ZA', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
  }

  function fmtHours(h) {
    if (h === null || h === undefined) return '—';
    if (h < 1)  return Math.round(h * 60) + 'm';
    if (h < 48) return h.toFixed(1) + 'h';
    return (h / 24).toFixed(1) + 'd';
  }

  function selectedDays() {
    const sel = document.getElementById('edr-range');
    return sel ? sel.value : '30';
  }

  // ── Rendering ────────────────────────────────────────────────────────────

  function renderStats(s) {
    const t = s.threats;
    const f = s.fleet;
    const cards = [
      { label: `Threats Detected (${s.windowDays}d)`, value: t.total,      accent: 'blue'  },
      { label: 'Malicious',                           value: t.malicious,  accent: t.malicious > 0 ? 'red' : 'green' },
      { label: 'Suspicious',                          value: t.suspicious, accent: 'amber' },
      { label: 'Unresolved',                          value: t.unresolved, accent: t.unresolved > 0 ? 'red' : 'green' },
      { label: 'Mitigation Rate', value: t.mitigationRate === null ? '—' : t.mitigationRate + '%', accent: 'green' },
      { label: 'Mean Time to Mitigate', value: fmtHours(t.mttmHours), accent: 'blue' },
      { label: 'Affected Endpoints',    value: t.affectedEndpoints,   accent: 'amber' },
      { label: 'Protected Endpoints',   value: f.total,               accent: 'blue'  },
    ];

    document.getElementById('edr-stats').innerHTML = cards.map(c => `
      <div class="stat-card accent-${c.accent}">
        <div class="stat-label">${esc(c.label)}</div>
        <div class="stat-value">${esc(c.value)}</div>
      </div>`).join('');
  }

  function renderFleet(f) {
    const rows = [
      { label: 'Total agents',            value: f.total,         tone: '' },
      { label: 'Online',                  value: f.online,        tone: 'green' },
      { label: 'Infected',                value: f.infected,      tone: f.infected > 0 ? 'red' : 'green' },
      { label: 'Active threats on agents', value: f.activeThreats, tone: f.activeThreats > 0 ? 'red' : 'green' },
      { label: 'Agent up to date',        value: f.upToDate,      tone: 'green' },
      { label: 'Agent out of date',       value: f.outOfDate,     tone: f.outOfDate > 0 ? 'amber' : 'green' },
      { label: 'Not seen in 7+ days',     value: f.stale,         tone: f.stale > 0 ? 'amber' : 'green' },
    ];

    const coverage = f.coverage === null ? '—' : f.coverage + '%';
    document.getElementById('edr-fleet').innerHTML = `
      <div class="edr-fleet-coverage">
        <span class="edr-fleet-coverage-value">${esc(coverage)}</span>
        <span class="edr-fleet-coverage-label">agents on the current version</span>
      </div>
      <table class="data-table edr-fleet-table"><tbody>
        ${rows.map(r => `<tr><td>${esc(r.label)}</td><td class="edr-fleet-num${r.tone ? ' edr-tone-' + r.tone : ''}">${esc(r.value)}</td></tr>`).join('')}
      </tbody></table>`;
  }

  function renderTallyTable(id, rows, cols) {
    const tbody = document.querySelector(`#${id} tbody`);
    if (!tbody) return;
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="${cols}" class="edr-muted">No data for this period.</td></tr>`;
      return;
    }
    tbody.innerHTML = rows;
  }

  function renderTopTables(s) {
    renderTallyTable('edr-top-endpoints', s.topEndpoints.map(r => `
      <tr><td>${esc(r.label)}</td><td>${r.count}</td>
          <td class="${r.unresolved > 0 ? 'edr-tone-red' : ''}">${r.unresolved}</td></tr>`).join(''), 3);

    renderTallyTable('edr-top-threats', s.topThreats.map(r => `
      <tr><td class="edr-mono">${esc(r.label)}</td>
          <td>${esc(r.classification || '—')}</td><td>${r.count}</td></tr>`).join(''), 3);
  }

  function destroyChart(key) {
    if (charts[key]) { charts[key].destroy(); charts[key] = null; }
  }

  function renderCharts(s) {
    if (typeof Chart === 'undefined') return;

    // ── Detections over time ──
    destroyChart('trend');
    const trendEl = document.getElementById('edr-trend-chart');
    if (trendEl) {
      charts.trend = new Chart(trendEl, {
        type: 'line',
        data: {
          labels: s.daily.map(d => d.date.slice(5)),
          datasets: [
            { label: 'Detections', data: s.daily.map(d => d.count),
              borderColor: COLORS.blue, backgroundColor: 'rgba(0,102,204,.12)',
              fill: true, tension: .3, pointRadius: 0, borderWidth: 2 },
            { label: 'Mitigated', data: s.daily.map(d => d.mitigated),
              borderColor: COLORS.green, backgroundColor: 'transparent',
              tension: .3, pointRadius: 0, borderWidth: 2, borderDash: [4, 3] },
          ],
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { position: 'bottom' } },
          scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
        },
      });
    }

    // ── Classification breakdown ──
    destroyChart('classification');
    const classEl = document.getElementById('edr-class-chart');
    if (classEl) {
      charts.classification = new Chart(classEl, {
        type: 'doughnut',
        data: {
          labels: s.byClassification.map(r => r.label),
          datasets: [{ data: s.byClassification.map(r => r.count), backgroundColor: SERIES, borderWidth: 0 }],
        },
        options: {
          responsive: true, maintainAspectRatio: false, cutout: '58%',
          plugins: { legend: { position: 'right', labels: { boxWidth: 12 } } },
        },
      });
    }

    // ── Incident status ──
    destroyChart('status');
    const statusEl = document.getElementById('edr-status-chart');
    if (statusEl) {
      const statusColor = { resolved: COLORS.green, in_progress: COLORS.amber, unresolved: COLORS.red };
      charts.status = new Chart(statusEl, {
        type: 'bar',
        data: {
          labels: s.byStatus.map(r => humanise(r.label)),
          datasets: [{
            label: 'Threats',
            data: s.byStatus.map(r => r.count),
            backgroundColor: s.byStatus.map(r => statusColor[r.label] || COLORS.muted),
            borderRadius: 6,
          }],
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
        },
      });
    }
  }

  function renderThreatsTable(rows) {
    const tbody = document.querySelector('#edr-threats-table tbody');
    if (!tbody) return;
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="edr-muted">No threats match these filters.</td></tr>';
      return;
    }

    const confBadge = { malicious: 'badge-red', suspicious: 'badge-amber' };
    const statBadge = { resolved: 'badge-green', in_progress: 'badge-amber', unresolved: 'badge-red' };

    tbody.innerHTML = rows.map(t => `
      <tr>
        <td>${esc(fmtDate(t.detectedAt))}</td>
        <td class="edr-mono" title="${esc(t.filePath || '')}">${esc(t.threatName)}</td>
        <td>${esc(t.classification || '—')}</td>
        <td>${esc(t.endpointName || '—')}</td>
        <td><span class="badge ${confBadge[t.confidenceLevel] || 'badge-muted'}">${esc(humanise(t.confidenceLevel))}</span></td>
        <td><span class="badge ${t.mitigationStatus === 'mitigated' ? 'badge-green' : 'badge-amber'}">${esc(humanise(t.mitigationStatus))}</span></td>
        <td><span class="badge ${statBadge[t.incidentStatus] || 'badge-muted'}">${esc(humanise(t.incidentStatus))}</span></td>
      </tr>`).join('');
  }

  function renderActivityTable(rows) {
    const tbody = document.querySelector('#edr-activity-table tbody');
    if (!tbody) return;
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="edr-muted">No activity for this period.</td></tr>';
      return;
    }
    tbody.innerHTML = rows.map(a => `
      <tr>
        <td>${esc(fmtDate(a.createdAt))}</td>
        <td>${esc(a.primaryDescription || a.activityTypeName || '—')}</td>
        <td>${esc(a.endpointName || '—')}</td>
        <td>${esc(a.userName || '—')}</td>
      </tr>`).join('');
  }

  function renderSyncMeta(sync) {
    const el = document.getElementById('edr-sync-meta');
    if (!el) return;
    if (!sync || !sync.last_synced_at) { el.textContent = ''; return; }
    const when = fmtDate(sync.last_synced_at);
    const ok   = sync.last_sync_status === 'ok';
    el.innerHTML = `<span class="${ok ? 'edr-tone-green' : 'edr-tone-red'}">${ok ? '✓' : '✗'}</span> Last synced ${esc(when)}`;
    el.title = sync.last_sync_message || '';
  }

  // ── Data loading ─────────────────────────────────────────────────────────

  async function loadThreats() {
    const status     = document.getElementById('edr-filter-status');
    const confidence = document.getElementById('edr-filter-confidence');
    const qs = tenantQS({
      days: selectedDays(),
      ...(status && status.value     ? { status: status.value }         : {}),
      ...(confidence && confidence.value ? { confidence: confidence.value } : {}),
    });
    try {
      const res = await fetch('api/edr/threats' + qs, { credentials: 'same-origin' });
      renderThreatsTable(res.ok ? await res.json() : []);
    } catch (_) { renderThreatsTable([]); }
  }

  async function loadAndRender() {
    const days = selectedDays();
    let s, activities;

    try {
      const [sRes, aRes] = await Promise.all([
        fetch('api/edr/summary' + tenantQS({ days }),                  { credentials: 'same-origin' }),
        fetch('api/edr/activities' + tenantQS({ days, limit: 100 }),   { credentials: 'same-origin' }),
      ]);
      s          = sRes.ok ? await sRes.json() : null;
      activities = aRes.ok ? await aRes.json() : [];
    } catch (err) {
      console.error('EDR load failed:', err);
      s = null; activities = [];
    }

    const empty   = document.getElementById('edr-empty');
    const content = document.getElementById('edr-content');

    // No integration configured, or configured but never synced.
    if (!s || (s.threats.total === 0 && s.fleet.total === 0 && !(s.sync && s.sync.last_synced_at))) {
      if (empty)   empty.hidden = false;
      if (content) content.hidden = true;
      renderSyncMeta(s && s.sync);
      return;
    }

    if (empty)   empty.hidden = true;
    if (content) content.hidden = false;

    summary = s;
    renderStats(s);
    renderFleet(s.fleet);
    renderTopTables(s);
    renderCharts(s);
    renderActivityTable(activities);
    renderSyncMeta(s.sync);
    await loadThreats();
  }

  async function syncNow() {
    const btn = document.getElementById('edr-sync-btn');
    const meta = document.getElementById('edr-sync-meta');
    if (btn) { btn.disabled = true; btn.textContent = 'Syncing…'; }
    if (meta) meta.textContent = 'Pulling from SentinelOne…';

    try {
      const res = await fetch('api/integrations/sentinelone/sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(tenantBody()),
      });
      const data = await res.json();
      if (!data.ok && meta) {
        meta.innerHTML = `<span class="edr-tone-red">✗</span> ${esc(data.error || 'Sync failed.')}`;
        return;
      }
      await loadAndRender();
    } catch (err) {
      if (meta) meta.innerHTML = `<span class="edr-tone-red">✗</span> ${esc(err.message)}`;
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Sync Now'; }
    }
  }

  function bind() {
    if (bound) return;
    bound = true;

    const range = document.getElementById('edr-range');
    if (range) range.addEventListener('change', () => loadAndRender());

    const refresh = document.getElementById('edr-refresh-btn');
    if (refresh) refresh.addEventListener('click', () => loadAndRender());

    const sync = document.getElementById('edr-sync-btn');
    if (sync) sync.addEventListener('click', syncNow);

    ['edr-filter-status', 'edr-filter-confidence'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.addEventListener('change', loadThreats);
    });

    const gotoAdmin = document.getElementById('edr-goto-admin');
    if (gotoAdmin) {
      gotoAdmin.addEventListener('click', e => {
        e.preventDefault();
        if (typeof window.switchTab === 'function') window.switchTab('admin');
      });
    }
  }

  return {
    loadAndRender: async () => { bind(); await loadAndRender(); },
    getSummary:    () => summary,
  };
})();

window.EdrTab = EdrTab;
