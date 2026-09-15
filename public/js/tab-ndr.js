/* tab-ndr.js — Managed NDR: FortiGate firewall monitoring, from FortiAnalyzer
   (or Wazuh, for clients not yet migrated). Both sources return the same shape.

   Four independent panel groups (traffic, IPS threats, geo, VPN/admin). Each
   renders or explains itself on its own, so the screen is fully useful when
   only some of them have data — which is the normal case while a deployment is
   still being onboarded. */
const NdrTab = (() => {
  'use strict';

  const U = window.WazuhUI;
  const charts = {};
  let bound   = false;
  let summary = null;
  // Which integration answered last, so Sync Now reaches the right one even
  // when the screen is showing its empty state.
  let lastProvider = 'wazuh';

  /** "Not available" text for a table the source cannot produce, else undefined. */
  function notAvailable(d, key) {
    return (d && Array.isArray(d.unavailable) && d.unavailable.indexOf(key) >= 0)
      ? 'Not available from this log source.' : undefined;
  }

  const SEVERITY_COLOR = {
    critical: U.COLORS.red,
    high:     U.COLORS.red,
    medium:   U.COLORS.amber,
    low:      U.COLORS.cyan,
    info:     U.COLORS.muted,
  };

  function selectedDays() {
    const sel = document.getElementById('ndr-range');
    return sel ? sel.value : '30';
  }

  // ── Stats ────────────────────────────────────────────────────────────────

  function renderStats(s) {
    const t  = U.isReady(s.traffic)  ? s.traffic.data  : null;
    const th = U.isReady(s.threats)  ? s.threats.data  : null;
    const va = U.isReady(s.vpnAdmin) ? s.vpnAdmin.data : null;

    const dash = '—';
    const blockRate = th ? U.pct(th.blocked, th.blocked + th.allowed) : null;

    U.renderStats('ndr-stats', [
      { label: `Threats Detected (${s.windowDays}d)`, value: th ? U.fmtNum(th.total) : dash, accent: 'blue' },
      { label: 'Blocked',           value: th ? U.fmtNum(th.blocked) : dash, accent: 'green' },
      // An IPS "detected"/"pass" verdict means the attack was seen and let
      // through — the number that actually needs an analyst's attention.
      { label: 'Allowed Through',   value: th ? U.fmtNum(th.allowed) : dash, accent: th && th.allowed > 0 ? 'red' : 'green' },
      { label: 'Block Rate',        value: blockRate === null ? dash : blockRate + '%', accent: 'green' },
      { label: 'Attacking Sources', value: th ? U.fmtNum(th.uniqueSources) : dash, accent: 'amber' },
      { label: 'Policy Denies',     value: t ? U.fmtNum(t.denied) : dash, accent: 'amber' },
      { label: 'VPN Login Failures', value: va ? U.fmtNum(va.vpn.failed) : dash, accent: va && va.vpn.failed > 0 ? 'red' : 'green' },
      { label: 'Config Changes',    value: va ? U.fmtNum(va.admin.configChanges) : dash, accent: 'blue' },
    ]);
  }

  // ── Panels ───────────────────────────────────────────────────────────────

  function renderTraffic(s) {
    U.panel('ndr-traffic-panel', s.traffic, d => {
      U.lineChart(charts, 'traffic', 'ndr-traffic-chart', d.trend, [
        { label: 'Allowed', field: 'allowed', color: U.COLORS.green, fill: true, fillColor: 'rgba(34,197,94,.12)' },
        { label: 'Denied',  field: 'denied',  color: U.COLORS.red },
      ]);
    });

    U.panel('ndr-talkers-panel', s.traffic, d => {
      U.fillTable('ndr-talkers-table', d.topSources, 3, r => `
        <tr><td class="edr-mono">${U.esc(r.label)}</td><td>${U.esc(r.country || '—')}</td><td>${U.fmtNum(r.count)}</td></tr>`,
        notAvailable(d, 'topSources'));
    });

    U.panel('ndr-ports-panel', s.traffic, d => {
      U.fillTable('ndr-ports-table', d.topPorts, 3, r => `
        <tr><td class="edr-mono">${U.esc(r.label)}</td><td>${U.esc(r.service || '—')}</td><td>${U.fmtNum(r.count)}</td></tr>`,
        notAvailable(d, 'topPorts'));
    });

    U.panel('ndr-policies-panel', s.traffic, d => {
      U.fillTable('ndr-policies-table', d.topPolicies, 3, r => `
        <tr><td class="edr-mono">${U.esc(r.label)}</td><td>${U.esc(r.name || '—')}</td><td>${U.fmtNum(r.count)}</td></tr>`,
        notAvailable(d, 'topPolicies'));
    });
  }

  function renderThreats(s) {
    U.panel('ndr-threat-panel', s.threats, d => {
      U.lineChart(charts, 'threat', 'ndr-threat-chart', d.trend, [
        { label: 'Detections', field: 'count',   color: U.COLORS.blue, fill: true },
        { label: 'Blocked',    field: 'blocked', color: U.COLORS.green, dashed: true },
      ]);
    });

    U.panel('ndr-severity-panel', s.threats, d => {
      U.doughnutChart(charts, 'severity', 'ndr-severity-chart', d.bySeverity,
        label => SEVERITY_COLOR[String(label).toLowerCase()]);
    });

    U.panel('ndr-attacks-panel', s.threats, d => {
      U.fillTable('ndr-attacks-table', d.topAttacks, 6, r => {
        const sev = String(r.severity || '').toLowerCase();
        const badge = sev === 'critical' || sev === 'high' ? 'badge-red'
          : sev === 'medium' ? 'badge-amber' : 'badge-muted';
        return `
          <tr>
            <td class="edr-mono">${U.esc(r.label)}</td>
            <td><span class="badge ${badge}">${U.esc(U.humanise(r.severity))}</span></td>
            <td>${U.fmtNum(r.count)}</td>
            <td class="edr-tone-green">${U.fmtNum(r.blocked)}</td>
            <td class="${r.allowed > 0 ? 'edr-tone-red' : ''}">${U.fmtNum(r.allowed)}</td>
            <td>${U.fmtNum(r.targets)}</td>
          </tr>`;
      });
    });
  }

  function renderGeo(s) {
    U.panel('ndr-geo-panel', s.geo, d => {
      U.barChart(charts, 'geo', 'ndr-geo-chart', (d.countries || []).slice(0, 10), 'Events', U.COLORS.purple);
    });
  }

  function renderVpnAdmin(s) {
    U.panel('ndr-vpn-panel', s.vpnAdmin, d => {
      U.fillTable('ndr-vpn-table', d.vpn.failedUsers, 4, r => `
        <tr>
          <td>${U.esc(r.label)}</td>
          <td class="${r.count > 0 ? 'edr-tone-red' : ''}">${U.fmtNum(r.count)}</td>
          <td>${U.fmtNum(r.sources)}</td>
          <td>${U.esc(U.humanise(r.reason))}</td>
        </tr>`);
    });

    U.panel('ndr-admin-panel', s.vpnAdmin, d => {
      U.fillTable('ndr-admin-table', d.admin.topAdmins, 3, r => `
        <tr><td>${U.esc(r.label)}</td><td>${U.fmtNum(r.count)}</td><td class="edr-mono">${U.esc(r.via || '—')}</td></tr>`);
    });

    U.panel('ndr-config-panel', s.vpnAdmin, d => {
      U.fillTable('ndr-config-table', d.admin.changesByPath, 2, r => `
        <tr><td class="edr-mono">${U.esc(r.label)}</td><td>${U.fmtNum(r.count)}</td></tr>`);
    });
  }

  // ── Load ─────────────────────────────────────────────────────────────────

  async function loadAndRender() {
    const days = selectedDays();
    let s = null;

    try {
      const res = await fetch('api/ndr/summary' + U.tenantQS({ days }), { credentials: 'same-origin' });
      s = res.ok ? await res.json() : null;
    } catch (err) {
      console.error('NDR load failed:', err);
      s = null;
    }

    if (s && s.provider) lastProvider = s.provider;

    const empty   = document.getElementById('ndr-empty');
    const content = document.getElementById('ndr-content');

    // Only a missing or disabled integration counts as "empty", and
    // renderEmptyState words itself from which. Once Wazuh is connected the
    // screen always renders and individual panels explain their own gaps —
    // showing the onboarding card because one source is quiet would hide the
    // sources that are working.
    if (!s || !s.configured) {
      U.renderEmptyState('ndr-empty', s, 'your FortiGates are logging to FortiAnalyzer');
      if (empty)   empty.hidden = false;
      if (content) content.hidden = true;
      U.renderSyncMeta('ndr-sync-meta', s && s.sync);
      return;
    }

    if (empty)   empty.hidden = true;
    if (content) content.hidden = false;

    summary = s;
    renderStats(s);
    renderTraffic(s);
    renderThreats(s);
    renderGeo(s);
    renderVpnAdmin(s);
    U.renderSyncMeta('ndr-sync-meta', s.sync);
    U.renderStaleBanner('ndr-banner', {
      'firewall traffic': s.traffic,
      'firewall threats': s.threats,
    });
    U.renderSourceNote('ndr-source-note', s);

    // Scaled IPS counts must be labelled as such, wherever they appear.
    const note = document.getElementById('ndr-source-note');
    if (note && U.isReady(s.threats) && s.threats.data.estimated) {
      note.textContent += ' On some days the IPS blocked/allowed figures are estimated from a sample of the logs.';
    }
  }

  function bind() {
    if (bound) return;
    bound = true;

    const range = document.getElementById('ndr-range');
    if (range) range.addEventListener('change', () => loadAndRender());

    const refresh = document.getElementById('ndr-refresh-btn');
    if (refresh) refresh.addEventListener('click', () => loadAndRender());

    const sync = document.getElementById('ndr-sync-btn');
    if (sync) sync.addEventListener('click', () => U.syncNow('ndr-sync-btn', 'ndr-sync-meta', loadAndRender, lastProvider));

  }

  return {
    loadAndRender: async () => { bind(); await loadAndRender(); },
    getSummary:    () => summary,
  };
})();

window.NdrTab = NdrTab;
