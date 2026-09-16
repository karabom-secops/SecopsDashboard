/* wazuh-ui.js — shared rendering helpers for the Wazuh-backed tabs
   (Managed NDR and Managed Identity).

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

  // Worded for any log source: Managed NDR reads FortiAnalyzer and Managed
  // Identity reads Microsoft directly, with Wazuh kept for clients not yet moved.
  const REASON_TEXT = {
    not_ingesting:     'This log source is not reaching the dashboard yet.',
    no_data_in_range:  'No matching events in this period.',
    query_error:       'The log source could not answer this query.',
    not_permitted:     'This query was refused — check the integration\'s permissions.',
    not_synced:        'Nothing has been collected yet.',
    not_licensed:      'Not available — this needs a Microsoft Entra ID P1 or P2 licence on the client\'s tenant.',
    beyond_retention:  'Not available for this period — Microsoft keeps this data for a limited time only.',
    category_unknown:  'Not available — DNSFilter\'s Generative AI category has not been identified yet.',
    unrecognised_response: 'The log source answered in a form this dashboard does not recognise yet.',
    not_available:     'This report is not available from the log source.',
    rate_limited:      'The log source was busy and refused this query — it will be collected again on the next run.',
    source_error:      'The log source failed on this query — it will be collected again on the next run.',
    unreachable:       'The log source could not be reached for this query.',
    category_filter_unsupported: 'Not available — this DNSFilter will not limit the report to the AI category, and the results carry nothing to limit them by here.',
  };

  const REASON_HINT = {
    not_ingesting:    'Check the log source is sending this data, then re-test the integration under Admin → Integrations.',
    query_error:      'Re-test the integration under Admin → Integrations; the last sync message says what failed.',
    not_permitted:    'The API user may lack read access to these logs.',
    not_synced:       'Press Sync Now, or wait for the hourly collection.',
    not_licensed:     'Sign-ins need Entra ID P1; risky users and risk detections need P2.',
    beyond_retention: 'Office 365 audit content is kept for 7 days; shorter ranges will show it.',
    category_unknown: 'Run Test Connection on the DNSFilter (MSP) card, which looks the category up by name.',
    unrecognised_response: 'Re-test the integration: the Test result records the fields the source returned.',
    rate_limited:     'Nothing to fix — press Sync Now, or wait for the hourly collection to pick the day up.',
    source_error:     'Nothing to fix here yet — press Sync Now. If it keeps happening, the sync message names the error.',
    unreachable:      'Check that this dashboard can reach the log source.',
    category_filter_unsupported: 'Run Test Connection: it records which filters this DNSFilter accepts.',
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

  /**
   * Fill a table body from rows, or show a single muted line. `emptyText`
   * overrides "No data" for a table the source cannot produce at all — "not
   * available" and "nothing happened" are different findings.
   */
  function fillTable(tableId, rows, cols, rowHtml, emptyText) {
    const tbody = document.querySelector(`#${tableId} tbody`);
    if (!tbody) return;
    if (emptyText || !rows || !rows.length) {
      tbody.innerHTML = `<tr><td colspan="${cols}" class="edr-muted">${esc(emptyText || 'No data for this period.')}</td></tr>`;
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
    if (summary.provider === 'fortianalyzer') {
      el.textContent = `Collected from FortiAnalyzer${summary.adom ? ` (ADOM ${summary.adom})` : ''} into daily ` +
        `rollups, refreshed hourly — the last ${summary.windowDays} days, with today still in progress ` +
        `(${summary.timeZone || 'UTC'}).`;
      return;
    }
    if (summary.provider === 'dnsfilter') {
      const org = summary.organisation || {};
      el.textContent = `Collected from DNSFilter${org.name ? ` (${org.name})` : ''} into daily rollups, ` +
        `refreshed hourly — the last ${summary.windowDays} days (${summary.timeZone || 'UTC'}), with today and ` +
        `yesterday still settling. Counts are DNS lookups, not visits or prompts.`;
      return;
    }
    if (summary.provider === 'ms_graph') {
      el.textContent = `Collected from Microsoft Graph and the Office 365 Management Activity API into daily ` +
        `rollups, refreshed hourly — the last ${summary.windowDays} days (${summary.timeZone || 'UTC'}). ` +
        `Today and yesterday are still filling in: Office 365 audit events can arrive hours late.`;
      return;
    }
    el.textContent = summary.source === 'live'
      ? `Queried live from the Wazuh Indexer over the last ${summary.windowDays} days (${summary.timeZone || 'UTC'}).`
      : `Built from stored daily rollups over the last ${summary.windowDays} days — ranges beyond 30 days exceed the indexer's retention.`;
  }

  /**
   * Word a screen's empty state from why the integration is unavailable.
   *
   * "Never set up" and "set up, then switched off" look identical from the data
   * side — both yield nothing — but they need opposite things from the operator.
   * Telling someone to go configure an integration they already configured is
   * how an afternoon disappears.
   *
   * @param {string} elId      the screen's empty-state container
   * @param {object} summary   the /api/{ndr,o365}/summary response (may be null)
   * @param {string} sourceHint what ingestion this screen needs, e.g.
   *                            "your FortiGate is forwarding syslog to Wazuh"
   */
  function renderEmptyState(elId, summary, sourceHint) {
    const el = document.getElementById(elId);
    if (!el) return;
    const linkId = elId + '-admin-link';
    const link = `<a href="#" id="${linkId}">Admin → Integrations</a>`;

    const reason = summary && summary.reason;
    let body;

    if (!summary) {
      // The request itself failed. Say that, rather than inventing a cause —
      // guessing here is what previously told an admin to use a dropdown only
      // superadmins can see.
      body = `<p><strong>Could not load this screen.</strong></p>
        <p>The request to the server failed. Try Refresh; if it keeps happening, check the
        server log for the error behind it.</p>`;
    } else if (reason === 'no_tenant') {
      // No organisation is attached to this request. For a superadmin that means
      // the header filter is unset; for everyone else it means their account has
      // no active organisation, which they cannot fix from the filter.
      const isSA = window.currentUser && window.currentUser.role === 'superadmin';
      body = isSA
        ? `<p><strong>No organisation selected.</strong></p>
           <p>Pick one from the Organisation dropdown in the header to see its data.</p>`
        : `<p><strong>Your account has no active organisation.</strong></p>
           <p>If there is an organisation dropdown in the header, choose one there. Otherwise ask an
           administrator to assign your account to an organisation — every screen on this dashboard
           is scoped to one.</p>`;
    } else if (reason === 'msp_not_configured') {
      body = `<p><strong>The DNSFilter MSP key is not set.</strong></p>
        <p>This client's organisation is configured, but the shared DNSFilter key is not. A superadmin
        sets it once under ${link} → DNSFilter (MSP).</p>`;
    } else if (reason === 'disabled') {
      const name = { fortianalyzer: 'FortiAnalyzer', ms_graph: 'Microsoft Graph', dnsfilter: 'DNSFilter' }[summary.provider] || 'Wazuh';
      body = `<p><strong>The ${name} integration is switched off.</strong></p>
        <p>Its connection may be working fine — but while it is disabled nothing syncs and
        this screen stays empty. Enable it under ${link}, then press Save.</p>`;
    } else {
      body = `<p><strong>No data yet.</strong></p>
        <p>Configure the integration under ${link}, and make sure ${esc(sourceHint)}.</p>`;
    }

    el.innerHTML = body;
    bindAdminLink(linkId);
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

  /**
   * Read a response that SHOULD be JSON, and say what arrived when it isn't.
   *
   * A reverse proxy returning 502, a server still starting, an expired session
   * bouncing to the login page, or a route missing from the running build all
   * answer with HTML. res.json() then throws "Unexpected token '<'", which
   * sends the reader looking for a bug in the request instead of at the
   * deployment. The body is read ONCE, as text, so nothing here can throw.
   *
   * @returns {{ok: boolean, data: object|null, error: string|null}}
   */
  async function readJson(res) {
    let body = '';
    try { body = await res.text(); } catch (_) { /* connection died mid-read */ }

    const type = (res.headers && res.headers.get && res.headers.get('content-type')) || '';
    if (type.indexOf('json') >= 0 || /^\s*[{[]/.test(body)) {
      try {
        return { ok: res.ok, data: JSON.parse(body), error: null };
      } catch (_) { /* truncated or mislabelled — fall through to the report */ }
    }

    const hint = res.status === 401 || res.status === 403
      ? 'you may have been signed out — reload the page and sign in again'
      : res.status === 404
        ? 'that endpoint is not in the running build — the server may need redeploying'
        : res.status >= 500
          ? 'the server, or a proxy in front of it, returned an error page'
          : 'the server did not return JSON';
    return { ok: false, data: null, error: `HTTP ${res.status} — ${hint}.` };
  }

  /**
   * Shared "Sync Now" handler. `provider` is whichever integration served the
   * screen — FortiAnalyzer for NDR once configured, Wazuh otherwise.
   */
  async function syncNow(btnId, metaId, reload, provider) {
    const btn  = document.getElementById(btnId);
    const meta = document.getElementById(metaId);
    // Only known targets: the value becomes part of the request path.
    const SYNC_LABEL = {
      fortianalyzer: 'Collecting from FortiAnalyzer — this can take a minute…',
      ms_identity:   'Collecting from Microsoft Graph and Office 365 — this can take a minute…',
      dnsfilter:     'Collecting from DNSFilter — this can take a minute…',
      wazuh:         'Snapshotting daily rollups from Wazuh…',
    };
    const p    = Object.prototype.hasOwnProperty.call(SYNC_LABEL, provider) ? provider : 'wazuh';
    if (btn) { btn.disabled = true; btn.textContent = 'Syncing…'; }
    if (meta) meta.textContent = SYNC_LABEL[p];

    try {
      const res = await fetch(`api/integrations/${p}/sync`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(tenantBody()),
      });
      const r = await readJson(res);
      const data = r.data || {};
      if (!r.ok || !data.ok) {
        if (meta) meta.innerHTML = `<span class="edr-tone-red">✗</span> ${esc(r.error || data.error || data.message || 'Sync failed.')}`;
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
    renderEmptyState, bindAdminLink, syncNow, readJson,
    reasonText: reason => REASON_TEXT[reason] || REASON_TEXT.not_ingesting,
  };
})();

window.WazuhUI = WazuhUI;
