/* tab-o365.js — Managed Identity: sign-ins, admin changes, alerts, identity
   risk, mailbox rules, sharing and DLP.

   Read directly from Microsoft Graph and the Office 365 Management Activity API
   (or from Wazuh, for clients not yet migrated). Both return the same shape.

   The direct APIs report per part what they could not read — a tenant without
   Entra ID P2 has no risky-user feed, one without the DLP permission no DLP —
   and each panel says so rather than showing zero. */
const O365Tab = (() => {
  'use strict';

  const U = window.WazuhUI;
  const charts = {};
  let bound   = false;
  let summary = null;
  let lastProvider = 'wazuh';

  const RISK_BADGE = { high: 'badge-red', medium: 'badge-amber', low: 'badge-muted', hidden: 'badge-muted' };

  function selectedDays() {
    const sel = document.getElementById('o365-range');
    return sel ? sel.value : '30';
  }

  /**
   * One part of a half as its own envelope: unavailable, with the reason, when
   * the source could not read it. Wazuh responses carry no `unavailable`, so
   * they pass through unchanged.
   */
  function part(envelope, key) {
    if (!U.isReady(envelope)) return envelope;
    const list = Array.isArray(envelope.data.unavailable) ? envelope.data.unavailable : [];
    const miss = list.find(u => (u && (u.key || u)) === key);
    return miss ? { available: false, data: null, reason: miss.reason || 'query_error' } : envelope;
  }

  const ready = (env, key) => (U.isReady(part(env, key)) ? env.data : null);

  // ── Stats ────────────────────────────────────────────────────────────────

  function renderStats(s) {
    const si = ready(s.o365, 'signins');
    const ad = ready(s.o365, 'admin');
    const sh = ready(s.o365, 'sharing');
    const dl = ready(s.o365, 'dlp');
    const ru = ready(s.graph, 'riskyUsers');
    const dash = '—';

    const totalSignins = si ? si.signins.success + si.signins.failed : null;
    const failRate = si ? U.pct(si.signins.failed, totalSignins) : null;

    U.renderStats('o365-stats', [
      { label: `Sign-ins (${s.windowDays}d)`, value: totalSignins === null ? dash : U.fmtNum(totalSignins), accent: 'blue' },
      { label: 'Failed Sign-ins', value: si ? U.fmtNum(si.signins.failed) : dash, accent: si && si.signins.failed > 0 ? 'amber' : 'green' },
      { label: 'Failure Rate',    value: failRate === null ? dash : failRate + '%', accent: failRate !== null && failRate > 20 ? 'red' : 'green' },
      { label: 'Active Accounts', value: si ? U.fmtNum(si.signins.uniqueUsers) : dash, accent: 'blue' },
      { label: 'Admin Changes',   value: ad ? U.fmtNum(ad.admin.total) : dash, accent: 'amber' },
      { label: 'External Shares', value: sh ? U.fmtNum(sh.sharing.total) : dash, accent: sh && sh.sharing.total > 0 ? 'amber' : 'green' },
      { label: 'DLP Matches',     value: dl ? U.fmtNum(dl.dlp.total) : dash, accent: dl && dl.dlp.total > 0 ? 'red' : 'green' },
      { label: 'Risky Users',     value: ru ? U.fmtNum(ru.riskyUsers.distinct) : dash, accent: ru && ru.riskyUsers.distinct > 0 ? 'red' : 'green' },
    ]);
  }

  // ── Office 365 panels ────────────────────────────────────────────────────

  function renderO365(s) {
    U.panel('o365-signin-panel', part(s.o365, 'signins'), d => {
      U.lineChart(charts, 'signin', 'o365-signin-chart', d.signins.trend, [
        { label: 'Successful', field: 'success', color: U.COLORS.green, fill: true, fillColor: 'rgba(34,197,94,.12)' },
        { label: 'Failed',     field: 'failed',  color: U.COLORS.red },
      ]);
    });

    U.panel('o365-reason-panel', part(s.o365, 'failedLogins'), d => {
      U.barChart(charts, 'reason', 'o365-reason-chart', (d.failedLogins.byReason || []).slice(0, 8), 'Failures', U.COLORS.red);
    });

    U.panel('o365-workload-panel', part(s.o365, 'byWorkload'), d => {
      U.doughnutChart(charts, 'workload', 'o365-workload-chart', d.byWorkload);
    });

    U.panel('o365-faileduser-panel', part(s.o365, 'failedLogins'), d => {
      U.fillTable('o365-faileduser-table', d.failedLogins.byUser, 3, r => `
        <tr><td>${U.esc(r.label)}</td><td>${U.fmtNum(r.count)}</td><td>${U.fmtNum(r.distinctIps)}</td></tr>`);
    });

    U.panel('o365-failedip-panel', part(s.o365, 'failedLogins'), d => {
      U.fillTable('o365-failedip-table', d.failedLogins.byIp, 3, r => `
        <tr>
          <td class="edr-mono">${U.esc(r.label)}</td>
          <td>${U.fmtNum(r.count)}</td>
          <td>${U.fmtNum(r.targetedUsers)}${r.spray ? ' <span class="badge badge-red">Spray</span>' : ''}</td>
        </tr>`);
    });

    U.panel('o365-admin-panel', part(s.o365, 'admin'), d => {
      // Rollup mode keeps counts, not individual events, so fall back to the
      // per-operation tally rather than showing an empty table.
      if (d.admin.recent && d.admin.recent.length) {
        U.fillTable('o365-admin-table', d.admin.recent, 5, r => `
          <tr>
            <td>${U.esc(U.fmtDate(r.when))}</td>
            <td>${U.esc(r.operation)}</td>
            <td>${U.esc(r.actor || '—')}</td>
            <td>${U.esc(r.target || '—')}</td>
            <td class="edr-mono">${U.esc(r.clientIp || '—')}</td>
          </tr>`);
      } else {
        U.fillTable('o365-admin-table', d.admin.byOperation, 5, r => `
          <tr><td>—</td><td>${U.esc(r.label)}</td><td colspan="3">${U.fmtNum(r.count)} in period</td></tr>`);
      }
    });

    U.panel('o365-mailbox-panel', part(s.o365, 'mailboxRules'), d => {
      if (d.mailboxRules.recent && d.mailboxRules.recent.length) {
        U.fillTable('o365-mailbox-table', d.mailboxRules.recent, 4, r => `
          <tr>
            <td>${U.esc(U.fmtDate(r.when))}</td>
            <td>${U.esc(r.operation)}</td>
            <td>${U.esc(r.mailbox || '—')}</td>
            <td>${U.esc(r.actor || '—')}</td>
          </tr>`);
      } else {
        U.fillTable('o365-mailbox-table', d.mailboxRules.byOperation, 4, r => `
          <tr><td>—</td><td>${U.esc(r.label)}</td><td colspan="2">${U.fmtNum(r.count)} in period</td></tr>`);
      }
    });

    U.panel('o365-sharing-panel', part(s.o365, 'sharing'), d => {
      U.fillTable('o365-sharing-table', d.sharing.byOperation, 2, r => `
        <tr><td>${U.esc(r.label)}</td><td>${U.fmtNum(r.count)}</td></tr>`);
    });

    U.panel('o365-dlp-panel', part(s.o365, 'dlp'), d => {
      U.fillTable('o365-dlp-table', d.dlp.byPolicy, 2, r => `
        <tr><td>${U.esc(r.label)}</td><td>${U.fmtNum(r.count)}</td></tr>`);
    });
  }

  // ── Microsoft Graph panels ───────────────────────────────────────────────

  function renderGraph(s) {
    U.panel('o365-geo-panel', part(s.graph, 'signins'), d => {
      // The Management Activity API ships no geo at all, so sign-in locations
      // can only come from the Graph auditLogs/signIns feed.
      U.barChart(charts, 'geo', 'o365-geo-chart', (d.signins.byCountry || []).slice(0, 10), 'Sign-ins', U.COLORS.purple);
    });

    U.panel('o365-legacy-panel', part(s.graph, 'signins'), d => {
      U.fillTable('o365-legacy-table', d.signins.legacyAuth.byUser, 2, r => `
        <tr><td>${U.esc(r.label)}</td><td>${U.fmtNum(r.count)}</td></tr>`);
    });

    U.panel('o365-mitre-panel', part(s.graph, 'alerts'), d => {
      U.fillTable('o365-mitre-table', d.alerts.byTechnique, 2, r => `
        <tr><td class="edr-mono">${U.esc(r.label)}</td><td>${U.fmtNum(r.count)}</td></tr>`);
    });

    U.panel('o365-risky-panel', part(s.graph, 'riskyUsers'), d => {
      U.fillTable('o365-risky-table', d.riskyUsers.users, 3, r => {
        const badge = RISK_BADGE[String(r.level || '').toLowerCase()] || 'badge-muted';
        return `
          <tr>
            <td>${U.esc(r.label)}</td>
            <td><span class="badge ${badge}">${U.esc(U.humanise(r.level))}</span></td>
            <td>${U.esc(U.humanise(r.state))}</td>
          </tr>`;
      });
    });
  }

  // ── Load ─────────────────────────────────────────────────────────────────

  async function loadAndRender() {
    const days = selectedDays();
    let s = null;

    try {
      const res = await fetch('api/o365/summary' + U.tenantQS({ days }), { credentials: 'same-origin' });
      s = res.ok ? await res.json() : null;
    } catch (err) {
      console.error('O365 load failed:', err);
      s = null;
    }

    if (s && s.provider) lastProvider = s.provider;

    const empty   = document.getElementById('o365-empty');
    const content = document.getElementById('o365-content');

    if (!s || !s.configured) {
      U.renderEmptyState('o365-empty', s,
        'Managed Identity collection is switched on for the client\'s Microsoft Graph integration');
      if (empty)   empty.hidden = false;
      if (content) content.hidden = true;
      U.renderSyncMeta('o365-sync-meta', s && s.sync);
      return;
    }

    if (empty)   empty.hidden = true;
    if (content) content.hidden = false;

    summary = s;
    renderStats(s);
    renderO365(s);
    renderGraph(s);
    U.renderSyncMeta('o365-sync-meta', s.sync);
    U.renderStaleBanner('o365-banner', {
      'Office 365': s.o365,
      'Microsoft Graph': s.graph,
    });
    U.renderSourceNote('o365-source-note', s);

    const note = document.getElementById('o365-source-note');
    if (note && U.isReady(s.o365) && s.o365.data.sampled) {
      note.textContent += ' On some days only part of the sign-in or audit volume could be read, so those figures are a sample.';
    }
  }

  function bind() {
    if (bound) return;
    bound = true;

    const range = document.getElementById('o365-range');
    if (range) range.addEventListener('change', () => loadAndRender());

    const refresh = document.getElementById('o365-refresh-btn');
    if (refresh) refresh.addEventListener('click', () => loadAndRender());

    // The Graph integration's own sync is Secure Score; Identity has its own target.
    const sync = document.getElementById('o365-sync-btn');
    if (sync) sync.addEventListener('click', () => U.syncNow('o365-sync-btn', 'o365-sync-meta', loadAndRender,
      lastProvider === 'ms_graph' ? 'ms_identity' : 'wazuh'));
  }

  return {
    loadAndRender: async () => { bind(); await loadAndRender(); },
    getSummary:    () => summary,
  };
})();

window.O365Tab = O365Tab;
