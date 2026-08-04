/* wazuh-ui.js — shared rendering helpers for the Wazuh-backed tabs
   (Managed NDR and Managed Office 365).

   The two screens draw different panels but share the same contract with the
   API: every panel arrives as an envelope { available, data, reason,
   lastEventAt } rather than a bare array, and a panel that isn't available must
   explain itself rather than render an empty chart. That distinction is the
   whole point — "the office365 module isn't configured on the Wazuh manager"
   and "no failed logins in the last 24 hours" are completely different
   conversations with a customer, and a chart showing 0 conflates them into a
   dangerous lie. */
const WazuhUI = (() => {
  'use strict';

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

  // A source is considered stale when its newest event is older than this.
  // Silent ingestion stoppage is the failure customers actually experience, and
  // neither an error nor an empty chart surfaces it.
  const STALE_HOURS = 6;

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

  function fmtDate(v) {
    if (!v) return '—';
    const d = new Date(v);
    if (isNaN(d.getTime())) return '—';
    return d.toLocaleString('en-ZA', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
  }

  function fmtNum(v) {
    if (v === null || v === undefined) return '—';
    const n = Number(v);
    if (isNaN(n)) return '—';
    return n.toLocaleString('en-ZA');
  }

  function humanise(v) {
    if (!v) return '—';
    return String(v).replace(/[_-]/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
  }

  /** Percentage of `part` out of `whole`, or null when there's nothing to divide. */
  function pct(part, whole) {
    if (!whole) return null;
    return Math.round((part / whole) * 100);
  }

  // ── Panel availability ───────────────────────────────────────────────────

  const REASON_TEXT = {
    not_ingesting:     'This log source is not reaching Wazuh yet.',
    no_data_in_range:  'No matching events in this period.',
    query_error:       'Wazuh could not answer this query.',
    not_permitted:     'This query was refused — check the integration scope and indexer permissions.',
  };

  const REASON_HINT = {
    not_ingesting:    'Configure ingestion on the Wazuh manager, then re-test the integration under Admin → Integrations.',
    query_error:      'Check the indexer logs, then re-test the integration under Admin → Integrations.',
    not_permitted:    'The indexer user may lack read access to wazuh-alerts-4.x-*.',
  };

  function isReady(envelope) {
    return !!(envelope && envelope.available && envelope.data);
  }

  // A panel's original markup (canvas or table), stashed the first time we
  // replace it so a source coming back online can be rendered again.
  const originalHtml = new Map();

  /**
   * Replace a panel's body with a reasoned placeholder. Deliberately keeps the
   * card in the grid at roughly its normal height so the layout doesn't reflow
   * as sources come and go.
   */
  function placeholder(containerId, envelope) {
    const el = document.getElementById(containerId);
    if (!el) return;
    if (!originalHtml.has(containerId)) originalHtml.set(containerId, el.innerHTML);

    const reason = (envelope && envelope.reason) || 'not_ingesting';
    const text   = REASON_TEXT[reason] || REASON_TEXT.not_ingesting;
    const hint   = REASON_HINT[reason];
    el.innerHTML = `
      <div class="wz-placeholder">
        <p class="wz-placeholder-text">${esc(text)}</p>
        ${hint ? `<p class="wz-placeholder-hint">${esc(hint)}</p>` : ''}
      </div>`;
  }

  /** Put a panel's canvas/table back after it was replaced by a placeholder. */
  function restore(containerId) {
    const el = document.getElementById(containerId);
    if (!el || !originalHtml.has(containerId)) return;
    if (el.querySelector('.wz-placeholder')) el.innerHTML = originalHtml.get(containerId);
  }

  /**
   * Render a panel if its data is there, otherwise swap in the placeholder.
   * Returns true when `render` ran, so callers can skip chart setup.
   */
  function panel(containerId, envelope, render) {
    if (!isReady(envelope)) { placeholder(containerId, envelope); return false; }
    restore(containerId);
    render(envelope.data);
    return true;
  }

  // ── Tables ───────────────────────────────────────────────────────────────

  /** Fill a table body from rows, or show a single muted "no data" line. */
  function fillTable(tableId, rows, cols, rowHtml) {
    const tbody = document.querySelector(`#${tableId} tbody`);
    if (!tbody) return;
    if (!rows || !rows.length) {
      tbody.innerHTML = `<tr><td colspan="${cols}" class="edr-muted">No data for this period.</td></tr>`;
      return;
    }
    tbody.innerHTML = rows.map(rowHtml).join('');
  }

  // ── Charts ───────────────────────────────────────────────────────────────

  function destroyChart(charts, key) {
    if (charts[key]) { charts[key].destroy(); charts[key] = null; }
  }

  /** Multi-series line chart over a [{date, …}] series. */
  function lineChart(charts, key, canvasId, data, datasets) {
    destroyChart(charts, key);
    const el = document.getElementById(canvasId);
    if (!el || typeof Chart === 'undefined') return;
    charts[key] = new Chart(el, {
      type: 'line',
      data: {
        labels: (data || []).map(d => String(d.date || '').slice(5)),
        datasets: datasets.map((ds, i) => ({
          label: ds.label,
          data: (data || []).map(d => d[ds.field] || 0),
          borderColor: ds.color || SERIES[i % SERIES.length],
          backgroundColor: ds.fill ? ds.fillColor || 'rgba(0,102,204,.12)' : 'transparent',
          fill: !!ds.fill,
          tension: .3, pointRadius: 0, borderWidth: 2,
          borderDash: ds.dashed ? [4, 3] : undefined,
        })),
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom' } },
        scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
      },
    });
  }

  /** Doughnut over a [{label, count}] tally. */
  function doughnutChart(charts, key, canvasId, rows, colorFor) {
    destroyChart(charts, key);
    const el = document.getElementById(canvasId);
    if (!el || typeof Chart === 'undefined') return;
    charts[key] = new Chart(el, {
      type: 'doughnut',
      data: {
        labels: (rows || []).map(r => humanise(r.label)),
        datasets: [{
          data: (rows || []).map(r => r.count),
          backgroundColor: (rows || []).map((r, i) => (colorFor && colorFor(r.label)) || SERIES[i % SERIES.length]),
          borderWidth: 0,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false, cutout: '58%',
        plugins: { legend: { position: 'right', labels: { boxWidth: 12 } } },
      },
    });
  }

  /** Horizontal bar over a [{label, count}] tally — good for long labels. */
  function barChart(charts, key, canvasId, rows, label, color) {
    destroyChart(charts, key);
    const el = document.getElementById(canvasId);
    if (!el || typeof Chart === 'undefined') return;
    charts[key] = new Chart(el, {
      type: 'bar',
      data: {
        labels: (rows || []).map(r => r.label),
        datasets: [{
          label: label || 'Events',
          data: (rows || []).map(r => r.count),
          backgroundColor: color || COLORS.blue,
          borderRadius: 6,
        }],
      },
      options: {
        indexAxis: 'y',
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { x: { beginAtZero: true, ticks: { precision: 0 } } },
      },
    });
  }

  // ── Stat cards ───────────────────────────────────────────────────────────

  function renderStats(containerId, cards) {
    const el = document.getElementById(containerId);
    if (!el) return;
    el.innerHTML = cards.map(c => `
      <div class="stat-card accent-${c.accent || 'blue'}">
        <div class="stat-label">${esc(c.label)}</div>
        <div class="stat-value">${esc(c.value)}</div>
      </div>`).join('');
  }

  // ── Chrome: sync meta, staleness banner, source note ─────────────────────

  function renderSyncMeta(elId, sync) {
    const el = document.getElementById(elId);
    if (!el) return;
    if (!sync || !sync.last_synced_at) { el.textContent = ''; return; }
    const ok = sync.last_sync_status === 'ok';
    el.innerHTML = `<span class="${ok ? 'edr-tone-green' : 'edr-tone-red'}">${ok ? '✓' : '✗'}</span> Rollups updated ${esc(fmtDate(sync.last_synced_at))}`;
    el.title = sync.last_sync_message || '';
  }

  function hoursSince(iso) {
    if (!iso) return null;
    const t = new Date(iso).getTime();
    if (isNaN(t)) return null;
    return (Date.now() - t) / 3600000;
  }

  /**
   * Warn when a source that IS configured has gone quiet. Only fires for
   * sources the last probe found ingesting — a source that was never set up
   * isn't stale, it's absent, and the panel placeholders already say so.
   */
  function renderStaleBanner(elId, envelopes) {
    const el = document.getElementById(elId);
    if (!el) return;

    const stale = [];
    Object.keys(envelopes).forEach(name => {
      const e = envelopes[name];
      if (!e || !e.available || !e.lastEventAt) return;
      const age = hoursSince(e.lastEventAt);
      if (age !== null && age > STALE_HOURS) {
        stale.push(`${name} (last event ${fmtDate(e.lastEventAt)})`);
      }
    });

    if (!stale.length) { el.hidden = true; el.textContent = ''; return; }
    el.hidden = false;
    el.innerHTML = `<strong>Ingestion may have stopped.</strong> No new events for over ${STALE_HOURS} hours: ${esc(stale.join('; '))}.`;
  }

  /**
   * Label which store answered. Live indexer results and Postgres rollups differ
   * slightly — approximate cardinality, top-N truncation — so the reader needs
   * to know which one they're looking at rather than filing a bug.
   */
  function renderSourceNote(elId, summary) {
    const el = document.getElementById(elId);
    if (!el) return;
    if (!summary || !summary.source) { el.textContent = ''; return; }
    el.textContent = summary.source === 'live'
      ? `Queried live from the Wazuh Indexer over the last ${summary.windowDays} days (${summary.timeZone || 'UTC'}).`
      : `Built from stored daily rollups over the last ${summary.windowDays} days — ranges beyond 30 days exceed the indexer's retention.`;
  }

  /** Wire an "Admin → Integrations" link inside an empty state. */
  function bindAdminLink(id) {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener('click', e => {
      e.preventDefault();
      if (typeof window.switchTab === 'function') window.switchTab('admin');
    });
  }

  /** Shared "Sync Now" handler — both tabs sync the same Wazuh integration. */
  async function syncNow(btnId, metaId, reload) {
    const btn  = document.getElementById(btnId);
    const meta = document.getElementById(metaId);
    if (btn) { btn.disabled = true; btn.textContent = 'Syncing…'; }
    if (meta) meta.textContent = 'Snapshotting daily rollups from Wazuh…';

    try {
      const res = await fetch('api/integrations/wazuh/sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(tenantBody()),
      });
      const data = await res.json();
      if (!data.ok) {
        if (meta) meta.innerHTML = `<span class="edr-tone-red">✗</span> ${esc(data.error || data.message || 'Sync failed.')}`;
        return;
      }
      await reload();
    } catch (err) {
      if (meta) meta.innerHTML = `<span class="edr-tone-red">✗</span> ${esc(err.message)}`;
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Sync Now'; }
    }
  }

  return {
    COLORS, SERIES, STALE_HOURS,
    esc, tenantQS, tenantBody, fmtDate, fmtNum, humanise, pct,
    isReady, placeholder, restore, panel, fillTable,
    destroyChart, lineChart, doughnutChart, barChart,
    renderStats, renderSyncMeta, renderStaleBanner, renderSourceNote,
    bindAdminLink, syncNow,
  };
})();

window.WazuhUI = WazuhUI;
