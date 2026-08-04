/* tab-o365.js — Managed Office 365: O365 and Microsoft Graph activity via Wazuh.

   Two independent halves. The `office365` wodle only needs an Azure app with
   Management Activity API access; `ms-graph` needs a separate registration with
   SecurityAlert.Read.All / IdentityRiskyUser.Read.All / AuditLog.Read.All and
   admin consent, so it is absent more often than present. The O365 half must
   render fully on its own — the Graph panels simply explain themselves. */
const O365Tab = (() => {
  'use strict';

  const U = window.WazuhUI;
  const charts = {};
  let bound   = false;
  let summary = null;

  const RISK_BADGE = { high: 'badge-red', medium: 'badge-amber', low: 'badge-muted', hidden: 'badge-muted' };

  function selectedDays() {
    const sel = document.getElementById('o365-range');
    return sel ? sel.value : '30';
  }

  // ── Stats ────────────────────────────────────────────────────────────────

  function renderStats(s) {
    const o = U.isReady(s.o365)  ? s.o365.data  : null;
    const g = U.isReady(s.graph) ? s.graph.data : null;
    const dash = '—';

    const totalSignins = o ? o.signins.success + o.signins.failed : null;
    const failRate = o ? U.pct(o.signins.failed, totalSignins) : null;

    U.renderStats('o365-stats', [
      { label: `Sign-ins (${s.windowDays}d)`, value: totalSignins === null ? dash : U.fmtNum(totalSignins), accent: 'blue' },
      { label: 'Failed Sign-ins', value: o ? U.fmtNum(o.signins.failed) : dash, accent: o && o.signins.failed > 0 ? 'amber' : 'green' },
      { label: 'Failure Rate',    value: failRate === null ? dash : failRate + '%', accent: failRate !== null && failRate > 20 ? 'red' : 'green' },
      { label: 'Active Accounts', value: o ? U.fmtNum(o.signins.uniqueUsers) : dash, accent: 'blue' },
      { label: 'Admin Changes',   value: o ? U.fmtNum(o.admin.total) : dash, accent: 'amber' },
      { label: 'External Shares', value: o ? U.fmtNum(o.sharing.total) : dash, accent: o && o.sharing.total > 0 ? 'amber' : 'green' },
      { label: 'DLP Matches',     value: o ? U.fmtNum(o.dlp.total) : dash, accent: o && o.dlp.total > 0 ? 'red' : 'green' },
      { label: 'Risky Users',     value: g ? U.fmtNum(g.riskyUsers.distinct) : dash, accent: g && g.riskyUsers.distinct > 0 ? 'red' : 'green' },
    ]);
  }

  // ── Office 365 panels ────────────────────────────────────────────────────

  function renderO365(s) {
    U.panel('o365-signin-panel', s.o365, d => {
      U.lineChart(charts, 'signin', 'o365-signin-chart', d.signins.trend, [
        { label: 'Successful', field: 'success', color: U.COLORS.green, fill: true, fillColor: 'rgba(34,197,94,.12)' },
        { label: 'Failed',     field: 'failed',  color: U.COLORS.red },
      ]);
    });

    U.panel('o365-reason-panel', s.o365, d => {
      U.barChart(charts, 'reason', 'o365-reason-chart', (d.failedLogins.byReason || []).slice(0, 8), 'Failures', U.COLORS.red);
    });

    U.panel('o365-workload-panel', s.o365, d => {
      U.doughnutChart(charts, 'workload', 'o365-workload-chart', d.byWorkload);
    });

    U.panel('o365-faileduser-panel', s.o365, d => {
      U.fillTable('o365-faileduser-table', d.failedLogins.byUser, 3, r => `
        <tr><td>${U.esc(r.label)}</td><td>${U.fmtNum(r.count)}</td><td>${U.fmtNum(r.distinctIps)}</td></tr>`);
    });

    U.panel('o365-failedip-panel', s.o365, d => {
      U.fillTable('o365-failedip-table', d.failedLogins.byIp, 3, r => `
        <tr>
          <td class="edr-mono">${U.esc(r.label)}</td>
          <td>${U.fmtNum(r.count)}</td>
          <td>${U.fmtNum(r.targetedUsers)}${r.spray ? ' <span class="badge badge-red">Spray</span>' : ''}</td>
        </tr>`);
    });

    U.panel('o365-admin-panel', s.o365, d => {
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

    U.panel('o365-mailbox-panel', s.o365, d => {
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

    U.panel('o365-sharing-panel', s.o365, d => {
      U.fillTable('o365-sharing-table', d.sharing.byOperation, 2, r => `
        <tr><td>${U.esc(r.label)}</td><td>${U.fmtNum(r.count)}</td></tr>`);
    });

    U.panel('o365-dlp-panel', s.o365, d => {
      U.fillTable('o365-dlp-table', d.dlp.byPolicy, 2, r => `
        <tr><td>${U.esc(r.label)}</td><td>${U.fmtNum(r.count)}</td></tr>`);
    });
  }

  // ── Microsoft Graph panels ───────────────────────────────────────────────

  function renderGraph(s) {
    U.panel('o365-geo-panel', s.graph, d => {
      // The Management Activity API ships no geo at all, so sign-in locations
      // can only come from the Graph auditLogs/signIns feed.
      U.barChart(charts, 'geo', 'o365-geo-chart', (d.signins.byCountry || []).slice(0, 10), 'Sign-ins', U.COLORS.purple);
    });

    U.panel('o365-legacy-panel', s.graph, d => {
      U.fillTable('o365-legacy-table', d.signins.legacyAuth.byUser, 2, r => `
        <tr><td>${U.esc(r.label)}</td><td>${U.fmtNum(r.count)}</td></tr>`);
    });

    U.panel('o365-mitre-panel', s.graph, d => {
      U.fillTable('o365-mitre-table', d.alerts.byTechnique, 2, r => `
        <tr><td class="edr-mono">${U.esc(r.label)}</td><td>${U.fmtNum(r.count)}</td></tr>`);
    });

    U.panel('o365-risky-panel', s.graph, d => {
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

    const empty   = document.getElementById('o365-empty');
    const content = document.getElementById('o365-content');

    if (!s || !s.configured) {
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
  }

  function bind() {
    if (bound) return;
    bound = true;

    const range = document.getElementById('o365-range');
    if (range) range.addEventListener('change', () => loadAndRender());

    const refresh = document.getElementById('o365-refresh-btn');
    if (refresh) refresh.addEventListener('click', () => loadAndRender());

    const sync = document.getElementById('o365-sync-btn');
    if (sync) sync.addEventListener('click', () => U.syncNow('o365-sync-btn', 'o365-sync-meta', loadAndRender));

    U.bindAdminLink('o365-goto-admin');
  }

  return {
    loadAndRender: async () => { bind(); await loadAndRender(); },
    getSummary:    () => summary,
  };
})();

window.O365Tab = O365Tab;
